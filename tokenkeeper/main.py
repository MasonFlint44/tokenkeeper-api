import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import get_current_user, verifier
from .db import engine, get_session
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
        await verifier.close()


app = FastAPI(lifespan=lifespan)


@app.get("/token", response_model=list[TokenRead])
async def list_tokens(
    claims: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    username = claims.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Missing username in token")

    now = datetime.now(timezone.utc)

    result = await session.execute(
        select(Token.name, Token.created_at, Token.last_used, Token.expires_at).where(
            Token.user == username,
            Token.revoked == False,
            (Token.expires_at.is_(None) | (Token.expires_at > now)),
        )
    )
    tokens = result.all()
    return [
        TokenRead(
            name=name, created_at=created_at, last_used=last_used, expires_at=expires_at
        )
        for name, created_at, last_used, expires_at in tokens
    ]


@app.post("/token", response_model=TokenResponse)
async def create_token(
    data: TokenCreate,
    claims: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    username = claims.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Missing username in token")

    user_exists = await session.scalar(
        select(User.username).where(User.username == username).limit(1)
    )
    if not user_exists:
        session.add(User(username=username))
        await session.commit()

    now = datetime.now(timezone.utc)

    # Only reject if there's an *active* token with the same name
    existing_token = await session.execute(
        select(Token)
        .where(
            Token.user == username,
            Token.name == data.name,
            Token.revoked == False,
            (Token.expires_at.is_(None) | (Token.expires_at > now)),
        )
        .limit(1)
    )
    if existing_token.scalar_one_or_none():
        logger.warning(
            "Active token with name '%s' already exists for user '%s'",
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
    session.add(token)
    try:
        await session.commit()
        logger.info("Token created for user '%s' with prefix '%s'", username, prefix)
        return TokenResponse(token=full_token)
    except IntegrityError:
        await session.rollback()
        logger.error("Token prefix collision for user '%s'", username)
        raise HTTPException(
            status_code=500, detail="Failed to generate a unique token prefix"
        )


@app.post("/token/verify")
async def verify(
    authorization: str = Header(...),
    session: AsyncSession = Depends(get_session),
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Missing or invalid Bearer token")

    token_value = authorization.removeprefix("Bearer ").strip()

    try:
        prefix, secret = parse_token(token_value)
    except ValueError:
        raise HTTPException(status_code=403, detail="Invalid or unauthorized token")

    now = datetime.now(timezone.utc)

    result = await session.execute(
        select(Token).where(
            Token.prefix == prefix,
            Token.revoked == False,
            (Token.expires_at.is_(None) | (Token.expires_at > now)),
        )
    )
    token = result.scalar_one_or_none()

    if token and verify_token(secret, token.hashed_token):
        token.last_used = now
        await session.commit()
        logger.info("Token verified for user '%s'", token.user)
        return {"valid": True, "user": token.user}

    logger.warning("Failed token verification")
    raise HTTPException(status_code=403, detail="Invalid or unauthorized token")


@app.post("/token/revoke")
async def revoke(
    data: TokenRevoke,
    claims: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    username = claims.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Missing username in token")

    now = datetime.now(timezone.utc)

    # Only consider active tokens with matching user and name
    result = await session.execute(
        select(Token).where(
            Token.user == username,
            Token.name == data.name,
            Token.revoked == False,
            (Token.expires_at.is_(None) | (Token.expires_at > now)),
        )
    )
    token = result.scalar_one_or_none()

    if not token:
        logger.warning(
            "No active token to revoke for user '%s' and name '%s'", username, data.name
        )
        raise HTTPException(status_code=403, detail="No active token found to revoke")

    token.revoked = True
    await session.commit()

    logger.info("Token revoked for user '%s' with name '%s'", username, data.name)
    return {"revoked": True}
