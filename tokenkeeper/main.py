import logging
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import get_current_username, verifier
from .data import TokensDataAccess, UsersDataAccess
from .db import engine, get_session
from .models import (
    HealthResponse,
    ReadyResponse,
    RevokeResponse,
    TokenCreate,
    TokenRead,
    TokenResponse,
    TokenRevoke,
    VerifyResponse,
)
from .tables import Token, User
from .utils import generate_token, hash_token, parse_token, verify_token

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(User.metadata.create_all)
    await verifier.init_keys()
    try:
        yield
    finally:
        await verifier.close()
        await engine.dispose()


app = FastAPI(lifespan=lifespan)


@app.get("/healthz", response_model=HealthResponse)
async def get_health():
    """
    Health check endpoint to verify the service is running.
    """
    logger.debug("Health check successful")
    return HealthResponse(status="ok")


@app.get("/readyz", response_model=ReadyResponse)
async def get_ready(session: AsyncSession = Depends(get_session)):
    """
    Readiness check endpoint to verify the service is ready to accept requests.
    """
    try:
        async with session as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        logger.info("Readiness check unsuccessful")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service is not ready",
        ) from exc

    logger.debug("Readiness check successful")
    return ReadyResponse(status="ready")


@app.get("/token", response_model=list[TokenRead])
async def list_tokens(
    username: str = Depends(get_current_username),
    tokens_data_access: TokensDataAccess = Depends(),
):
    tokens = await tokens_data_access.list_active_tokens(username)
    logger.info("Listed tokens for user '%s'", username)
    return [
        TokenRead(
            name=token.name,
            created_at=token.created_at,
            last_used=token.last_used,
            expires_at=token.expires_at,
        )
        for token in tokens
    ]


@app.post("/token", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def create_token(
    data: TokenCreate,
    username: str = Depends(get_current_username),
    tokens_data_access: TokensDataAccess = Depends(),
    users_data_access: UsersDataAccess = Depends(),
):
    logger.info("Creating token '%s' for user '%s'", data.name, username)

    await users_data_access.ensure_user_exists(username)

    if (
        await tokens_data_access.get_active_token_by_name(username, data.name)
        is not None
    ):
        logger.warning(
            "Conflict: Active token '%s' already exists for user '%s'",
            data.name,
            username,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Active token name already exists for user",
        )

    prefix, secret, full_token = generate_token()
    hashed = hash_token(secret)
    token = Token(
        prefix=prefix,
        name=data.name,
        user=username,
        hashed_token=hashed,
        expires_at=data.expires_at,
    )

    inserted = await tokens_data_access.create_token(token)
    if not inserted:
        logger.error(
            "Token creation failed due to prefix collision for user '%s'", username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate a unique token prefix",
        )

    logger.info("Token created with prefix '%s' for user '%s'", prefix, username)
    return TokenResponse(token=full_token)


@app.post("/token/verify", response_model=VerifyResponse)
async def verify(
    authorization: Annotated[str, Header()],
    tokens_data_access: TokensDataAccess = Depends(),
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Missing bearer token",
            headers={
                "WWW-Authenticate": 'Bearer realm="tokenkeeper", error="invalid_request"'
            },
        )
    token_value = authorization.removeprefix("Bearer ").strip()

    try:
        prefix, secret = parse_token(token_value)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Token invalid",
            headers={
                "WWW-Authenticate": 'Bearer realm="tokenkeeper", error="invalid_token"'
            },
        ) from exc

    logger.info("Verifying token with prefix '%s'", prefix)
    async with tokens_data_access.lock_active_token(prefix) as token:
        if not (token and verify_token(secret, token.hashed_token)):
            # exception → auto-rollback, row lock released
            logger.warning("Token verification failed for prefix '%s'", prefix)
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "Token invalid",
                headers={
                    "WWW-Authenticate": 'Bearer realm="tokenkeeper", error="invalid_token"'
                },
            )

        tokens_data_access.touch_token(token)

    logger.info(
        "Token verified successfully for user '%s' (prefix: '%s')",
        token.user,
        prefix,
    )
    return VerifyResponse(valid=True, user=token.user)


@app.post("/token/revoke", response_model=RevokeResponse)
async def revoke(
    data: TokenRevoke,
    username: str = Depends(get_current_username),
    tokens_data_access: TokensDataAccess = Depends(),
):
    logger.info("Revoking token '%s' for user '%s'", data.name, username)
    revoked = await tokens_data_access.revoke_token_by_name(username, data.name)

    if not revoked:
        logger.warning(
            "Revocation failed: no active token '%s' found for user '%s'",
            data.name,
            username,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No active token found with name '{data.name}'",
        )

    logger.info("Token '%s' successfully revoked for user '%s'", data.name, username)
    return RevokeResponse(revoked=True)
