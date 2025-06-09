import secrets

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_token(secret: str) -> str:
    return pwd_context.hash(secret)


def verify_token(plain_secret: str, hashed: str) -> bool:
    return pwd_context.verify(plain_secret, hashed)


def generate_token() -> tuple[str, str, str]:
    prefix = secrets.token_hex(16)
    secret = secrets.token_urlsafe(64)
    full_token = f"tk_{prefix}_{secret}"
    return prefix, secret, full_token


def parse_token(full_token: str) -> tuple[str, str]:
    if len(full_token) != 122:
        raise ValueError("Invalid token length")
    if not full_token.startswith("tk_"):
        raise ValueError("Missing prefix")
    parts = full_token.split("_", 2)
    if len(parts) != 3:
        raise ValueError("Malformed token")
    _, prefix, secret = parts
    if len(prefix) != 32:
        raise ValueError("Invalid prefix length")
    if len(secret) != 86:
        raise ValueError("Invalid secret length")
    return prefix, secret
