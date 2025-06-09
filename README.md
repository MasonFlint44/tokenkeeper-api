# TokenKeeper API

**TokenKeeper** is a secure, FastAPI-based service for managing and verifying personal access tokens. It integrates with AWS Cognito for user authentication and uses PostgreSQL for persistent storage. Tokens are hashed with Argon2 and optionally support expiration, revocation, and last-used tracking.

## Features

- 🔐 Secure token generation using Argon2 hashing
- 📅 Optional token expiration and usage tracking
- ✅ Verification and revocation of tokens
- 🧾 List non-revoked, non-expired tokens
- 🪪 Cognito-based user authentication
- 🗃️ PostgreSQL + SQLAlchemy (async) backend

## API Endpoints

- `POST /token` — Create a new token
- `POST /token/verify` — Verify token validity
- `POST /token/revoke` — Revoke a token by name
- `GET /token` — List current user’s active tokens

## Requirements

- Python 3.12+
- PostgreSQL
- AWS Cognito User Pool
- `asyncpg`, `sqlalchemy`, `fastapi`, `passlib[argon2]`, `cognito-jwt-verifier`

## Getting Started

1. Update your database URL in db.py:

```python
DATABASE_URL = "postgresql+asyncpg://user:password@localhost/tokenkeeper"
```

2. Set up your Cognito issuer and client ID in auth.py:

```python
ISSUER = "https://cognito-idp.<region>.amazonaws.com/<user_pool_id>"
CLIENT_IDS = ["<app_client_id>"]
```

3. Run the FastAPI app:

```bash
uvicorn tokenkeeper.main:app --reload
```

## License

MIT
