import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException

from .auth import get_current_user, verifier
from .data import TokensDataAccess, UsersDataAccess
from .db import engine
from .models import TokenCreate, TokenRead, TokenResponse, TokenRevoke
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
        await engine.dispose()
        await verifier.close()


app = FastAPI(lifespan=lifespan)


@app.get("/token", response_model=list[TokenRead])
async def list_tokens(
    claims: dict = Depends(get_current_user),
    tokens_data_access: TokensDataAccess = Depends(),
):
    username = claims.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Missing username in token")

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


@app.post("/token", response_model=TokenResponse)
async def create_token(
    data: TokenCreate,
    claims: dict = Depends(get_current_user),
    tokens_data_access: TokensDataAccess = Depends(),
    users_data_access: UsersDataAccess = Depends(),
):
    username = claims.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Missing username in token")

    logger.info("Creating token '%s' for user '%s'", data.name, username)

    # Create user if it doesn't exist
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
            status_code=409, detail="Active token name already exists for user"
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

    success = await tokens_data_access.create_token(token)
    if not success:
        logger.error(
            "Token creation failed due to prefix collision for user '%s'", username
        )
        raise HTTPException(
            status_code=500, detail="Failed to generate a unique token prefix"
        )

    logger.info("Token created with prefix '%s' for user '%s'", prefix, username)
    return TokenResponse(token=full_token)


@app.post("/token/verify")
async def verify(
    authorization: str = Header(...),
    tokens_data_access: TokensDataAccess = Depends(),
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Missing or invalid Bearer token")

    token_value = authorization.removeprefix("Bearer ").strip()
    try:
        prefix, secret = parse_token(token_value)
    except ValueError:
        raise HTTPException(status_code=403, detail="Invalid or unauthorized token")

    logger.info("Verifying token with prefix '%s'", prefix)
    token = await tokens_data_access.get_active_token_by_prefix(prefix)

    if token and verify_token(secret, token.hashed_token):
        await tokens_data_access.touch_token(token)
        logger.info(
            "Token verified successfully for user '%s' (prefix: '%s')",
            token.user,
            prefix,
        )
        return {"valid": True, "user": token.user}

    logger.warning("Token verification failed for prefix '%s'", prefix)
    raise HTTPException(status_code=403, detail="Invalid or unauthorized token")


@app.post("/token/revoke")
async def revoke(
    data: TokenRevoke,
    claims: dict = Depends(get_current_user),
    tokens_data_access: TokensDataAccess = Depends(),
):
    username = claims.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Missing username in token")

    logger.info("Revoking token '%s' for user '%s'", data.name, username)
    success = await tokens_data_access.revoke_token_by_name(username, data.name)

    if not success:
        logger.warning(
            "Revocation failed: no active token '%s' found for user '%s'",
            data.name,
            username,
        )
        raise HTTPException(status_code=403, detail="No active token found to revoke")

    logger.info("Token '%s' successfully revoked for user '%s'", data.name, username)
    return {"revoked": True}
