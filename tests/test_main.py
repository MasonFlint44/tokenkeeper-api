import secrets
from datetime import datetime, timedelta, timezone

from httpx import AsyncClient


async def test_create_token(async_client: AsyncClient):
    try:
        response = await async_client.post(
            "/token",
            json={
                "name": "create-token",
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(days=1)
                ).isoformat(),
            },
        )

        assert response.status_code == 200
        response_json = response.json()
        tk_prefix, prefix, token = response_json["token"].split("_", 2)
        assert tk_prefix == "tk"
        assert len(prefix) == 32
        assert len(token) == 86
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": "create-token"})


async def test_create_token_conflict(async_client):
    try:
        token_name = "duplicate-token"
        data = {
            "name": token_name,
            "expires_at": (datetime.utcnow() + timedelta(days=1)).isoformat(),
        }
        await async_client.post("/token", json=data)
        response = await async_client.post("/token", json=data)
        assert response.status_code == 409
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": token_name})


async def test_create_token_reuse_name_after_revocation(async_client):
    try:
        token_name = "reusable-token"
        expires_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

        # Create and revoke
        await async_client.post(
            "/token", json={"name": token_name, "expires_at": expires_at}
        )
        await async_client.post("/token/revoke", json={"name": token_name})

        # Should be able to reuse
        response = await async_client.post(
            "/token", json={"name": token_name, "expires_at": expires_at}
        )
        assert response.status_code == 200
    finally:
        await async_client.post("/token/revoke", json={"name": token_name})


async def test_create_token_reuse_name_after_expiry(async_client):
    try:
        token_name = "expired-reuse"
        expired_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        fresh_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

        # Expired token
        await async_client.post(
            "/token", json={"name": token_name, "expires_at": expired_at}
        )

        # Should be able to reuse
        response = await async_client.post(
            "/token", json={"name": token_name, "expires_at": fresh_at}
        )
        assert response.status_code == 200
    finally:
        await async_client.post("/token/revoke", json={"name": token_name})


async def test_create_token_invalid_datetime_format(async_client):
    response = await async_client.post(
        "/token",
        json={"name": "bad-dt", "expires_at": "not-a-datetime"},
    )
    assert response.status_code == 422


async def test_create_token_missing_name(async_client):
    response = await async_client.post(
        "/token",
        json={
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        },
    )
    assert response.status_code == 422


async def test_create_token_missing_expires_at(async_client):
    try:
        response = await async_client.post(
            "/token",
            json={"name": "no-expiry"},
        )
        assert response.status_code == 200
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": "no-expiry"})


async def test_list_tokens(async_client: AsyncClient):
    try:
        # Ensure there's at least one token
        expires_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        await async_client.post(
            "/token",
            json={
                "name": "list-token",
                "expires_at": expires_at,
            },
        )

        response = await async_client.get("/token")

        assert response.status_code == 200
        tokens = response.json()
        assert isinstance(tokens, list)
        token = next((t for t in tokens if t["name"] == "list-token"), None)
        assert token is not None
        assert datetime.now(timezone.utc) - datetime.fromisoformat(
            token["created_at"]
        ) < timedelta(seconds=1)
        assert token["expires_at"] == expires_at.replace("+00:00", "Z")
        assert token["last_used"] is None
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": "list-token"})


async def test_token_verify_success(async_client):
    try:
        create_response = await async_client.post(
            "/token",
            json={
                "name": "verify-token",
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(days=1)
                ).isoformat(),
            },
        )
        token_value = create_response.json()["token"]

        verify_response = await async_client.post(
            "/token/verify",
            headers={"Authorization": f"Bearer {token_value}"},
        )
        assert verify_response.status_code == 200
        assert verify_response.json()["valid"] is True
        assert verify_response.json()["user"] == "testuser"
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": "verify-token"})


async def test_token_verify_invalid_token_format(async_client):
    headers = {"Authorization": "Bearer invalidtokenformat"}
    response = await async_client.post("/token/verify", headers=headers)
    assert response.status_code == 403


async def test_token_verify_invalid_token(async_client):
    headers = {
        "Authorization": f"Bearer tk_{secrets.token_hex(16)}_{secrets.token_urlsafe(64)}"
    }
    response = await async_client.post("/token/verify", headers=headers)
    assert response.status_code == 403


async def test_token_verify_expired_token(async_client):
    try:
        expired_time = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        response = await async_client.post(
            "/token",
            json={"name": "expired-token", "expires_at": expired_time},
        )
        token_value = response.json()["token"]

        verify_response = await async_client.post(
            "/token/verify", headers={"Authorization": f"Bearer {token_value}"}
        )
        assert verify_response.status_code == 403
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": "expired-token"})


async def test_token_verify_empty_bearer_token(async_client):
    headers = {"Authorization": "Bearer "}
    response = await async_client.post("/token/verify", headers=headers)
    assert response.status_code == 403


async def test_token_verify_missing_bearer_prefix(async_client):
    headers = {"Authorization": "tokenwithoutbearerprefix"}
    response = await async_client.post("/token/verify", headers=headers)
    assert response.status_code == 403


async def test_revoke_token(async_client):
    try:
        token_name = "revoke-token"
        await async_client.post(
            "/token",
            json={
                "name": token_name,
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(days=1)
                ).isoformat(),
            },
        )

        response = await async_client.post("/token/revoke", json={"name": token_name})
        assert response.status_code == 200
        assert response.json() == {"revoked": True}
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": token_name})


async def test_revoke_token_not_found(async_client):
    response = await async_client.post("/token/revoke", json={"name": "nonexistent"})
    assert response.status_code == 403


async def test_revoke_token_already_revoked(async_client):
    try:
        name = "already-revoked"
        await async_client.post(
            "/token",
            json={
                "name": name,
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(days=1)
                ).isoformat(),
            },
        )
        await async_client.post("/token/revoke", json={"name": name})
        response = await async_client.post("/token/revoke", json={"name": name})
        assert response.status_code == 403
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": name})


async def test_revoke_expired_token(async_client):
    token_name = "expired-revoke"
    expired_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()

    await async_client.post(
        "/token", json={"name": token_name, "expires_at": expired_at}
    )

    response = await async_client.post("/token/revoke", json={"name": token_name})
    assert response.status_code == 403  # Revocation fails because it's no longer active


async def test_token_last_used_updated(async_client):
    try:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        response = await async_client.post(
            "/token", json={"name": "used-token", "expires_at": expires_at}
        )
        token_value = response.json()["token"]

        await async_client.post(
            "/token/verify", headers={"Authorization": f"Bearer {token_value}"}
        )

        list_response = await async_client.get("/token")
        token = next(t for t in list_response.json() if t["name"] == "used-token")
        assert datetime.now(timezone.utc) - datetime.fromisoformat(
            token["last_used"]
        ) < timedelta(seconds=1)
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": "used-token"})


async def test_list_tokens_excludes_revoked_and_expired(async_client):
    try:
        now = datetime.now(timezone.utc)
        expired_token_name = "expired-for-list"
        revoked_token_name = "revoked-for-list"
        active_token_name = "active-for-list"

        # Expired token
        await async_client.post(
            "/token",
            json={
                "name": expired_token_name,
                "expires_at": (now - timedelta(seconds=1)).isoformat(),
            },
        )

        # Revoked token
        await async_client.post(
            "/token",
            json={
                "name": revoked_token_name,
                "expires_at": (now + timedelta(days=1)).isoformat(),
            },
        )
        await async_client.post("/token/revoke", json={"name": revoked_token_name})

        # Active token
        await async_client.post(
            "/token",
            json={
                "name": active_token_name,
                "expires_at": (now + timedelta(days=1)).isoformat(),
            },
        )

        # List
        response = await async_client.get("/token")
        tokens = response.json()
        names = {t["name"] for t in tokens}
        assert active_token_name in names
        assert revoked_token_name not in names
        assert expired_token_name not in names
    finally:
        # Clean up
        await async_client.post("/token/revoke", json={"name": active_token_name})
