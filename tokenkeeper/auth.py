from cognito_jwt_verifier import AsyncCognitoJwtVerifier
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer

ISSUER = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_AE7uogN5r"
CLIENT_IDS = ["m95vusubvir6psn1mfac61ond"]

verifier = AsyncCognitoJwtVerifier(ISSUER, client_ids=CLIENT_IDS)
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{ISSUER}/oauth2/authorize",
    tokenUrl=f"{ISSUER}/oauth2/token",
)


async def get_current_username(token: str = Depends(oauth2_scheme)) -> str:
    try:
        claims = await verifier.verify_access_token(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    username = claims.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Missing username in token")
    return username
