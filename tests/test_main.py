import asyncio
import base64
import secrets
from datetime import datetime, timedelta, timezone

from httpx import AsyncClient


async def test_healthz_ok(async_client: AsyncClient):
    resp = await async_client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_readyz_ok(async_client: AsyncClient):
    resp = await async_client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


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

        assert response.status_code == 201
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
        response = await async_client.post(
            "/token", json={"name": token_name, "expires_at": expires_at}
        )
        token = response.json()["token"]
        await async_client.post("/token/revoke", json={"name": token_name})

        response = await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token}'.encode()).decode()}"
            },
        )
        assert response.status_code == 401  # Token should be revoked

        # Should be able to reuse
        response = await async_client.post(
            "/token", json={"name": token_name, "expires_at": expires_at}
        )
        assert response.status_code == 201
        token = response.json()["token"]

        response = await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token}'.encode()).decode()}"
            },
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
        response = await async_client.post(
            "/token", json={"name": token_name, "expires_at": expired_at}
        )
        token = response.json()["token"]

        response = await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token}'.encode()).decode()}"
            },
        )
        assert response.status_code == 401  # Token should be expired

        # Should be able to reuse
        response = await async_client.post(
            "/token", json={"name": token_name, "expires_at": fresh_at}
        )
        assert response.status_code == 201
        token = response.json()["token"]

        response = await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token}'.encode()).decode()}"
            },
        )
        assert response.status_code == 200
        assert response.json()["valid"] is True
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
        assert response.status_code == 201
        token = response.json()["token"]

        response = await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token}'.encode()).decode()}"
            },
        )
        assert response.status_code == 200
        assert response.json()["valid"] is True
        assert response.json()["user"] == "testuser"

        response = await async_client.get("/token")
        assert response.status_code == 200
        tokens = response.json()
        token = next((t for t in tokens if t["name"] == "no-expiry"), None)
        assert token is not None
        assert token["expires_at"] is None
        assert datetime.now(timezone.utc) - datetime.fromisoformat(
            token["created_at"]
        ) < timedelta(seconds=1)
        assert datetime.now(timezone.utc) - datetime.fromisoformat(
            token["last_used"]
        ) < timedelta(seconds=1)
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


async def test_list_tokens_sorted_by_last_used(async_client: AsyncClient):
    """
    create 3 tokens -> verify #A then #B -> list should come back
    [B, A, C] where C.last_used is None.
    """
    try:
        # ------------------------------------------------------------------
        # 1. create three distinct tokens
        # ------------------------------------------------------------------
        names = ["token-A", "token-B", "token-C"]
        expires_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

        token_strings: dict[str, str] = {}
        for name in names:
            resp = await async_client.post(
                "/token", json={"name": name, "expires_at": expires_at}
            )
            assert resp.status_code == 201
            token_strings[name] = resp.json()["token"]

        # ------------------------------------------------------------------
        # 2. verify A, wait a tick, verify B  (B should be most-recent)
        # ------------------------------------------------------------------
        await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token_strings['token-A']}'.encode()).decode()}"
            },
        )
        # await asyncio.sleep(0.5)
        await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token_strings['token-B']}'.encode()).decode()}"
            },
        )

        # ------------------------------------------------------------------
        # 3. list – expect B, then A, then C   (C.last_used == None)
        # ------------------------------------------------------------------
        list_resp = await async_client.get("/token")
        assert list_resp.status_code == 200

        listed = list_resp.json()
        order = [t["name"] for t in listed]

        assert order[:3] == [
            "token-B",
            "token-A",
            "token-C",
        ], "list not sorted by last_used desc"

        # sanity-check timestamp ordering
        ts_B = datetime.fromisoformat(
            next(t for t in listed if t["name"] == "token-B")["last_used"]
        )
        ts_A = datetime.fromisoformat(
            next(t for t in listed if t["name"] == "token-A")["last_used"]
        )
        assert ts_B >= ts_A  # B touched after A
        assert next(t for t in listed if t["name"] == "token-C")["last_used"] is None
    finally:
        # ------------------------------------------------------------------
        # clean-up (revoke regardless of test outcome)
        # ------------------------------------------------------------------
        for name in names:
            await async_client.post("/token/revoke", json={"name": name})


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
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token_value}'.encode()).decode()}"
            },
        )
        assert verify_response.status_code == 200
        assert verify_response.headers["x-token-user"] == "testuser"
        assert verify_response.json()["valid"] is True
        assert verify_response.json()["user"] == "testuser"
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": "verify-token"})


async def test_token_verify_invalid_token_format(async_client):
    headers = {"Authorization": "Bearer invalidtokenformat"}
    response = await async_client.post("/token/verify", headers=headers)
    assert response.status_code == 401


async def test_token_verify_invalid_token(async_client):
    headers = {
        "Authorization": f"Bearer tk_{secrets.token_hex(16)}_{secrets.token_urlsafe(64)}"
    }
    response = await async_client.post("/token/verify", headers=headers)
    assert response.status_code == 401


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
        assert verify_response.status_code == 401
    finally:
        # Clean up by revoking the token after test
        await async_client.post("/token/revoke", json={"name": "expired-token"})


async def test_token_verify_empty_bearer_token(async_client):
    headers = {"Authorization": "Bearer "}
    response = await async_client.post("/token/verify", headers=headers)
    assert response.status_code == 401


async def test_token_verify_missing_bearer_prefix(async_client):
    headers = {"Authorization": "tokenwithoutbearerprefix"}
    response = await async_client.post("/token/verify", headers=headers)
    assert response.status_code == 401


async def test_token_verify_missing_authorization_header(async_client):
    response = await async_client.post("/token/verify")
    assert response.status_code == 422


async def test_last_used_not_updated_on_failed_verify(async_client: AsyncClient):
    token_name = "fail-touch"
    expires_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    try:
        # ------------------------------------------------------------------
        # 1. Create token
        # ------------------------------------------------------------------
        create_resp = await async_client.post(
            "/token", json={"name": token_name, "expires_at": expires_at}
        )
        assert create_resp.status_code == 201
        good_token = create_resp.json()["token"]

        # ------------------------------------------------------------------
        # 2. Successful verify → sets last_used
        # ------------------------------------------------------------------
        ok_resp = await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{good_token}'.encode()).decode()}"
            },
        )
        assert ok_resp.status_code == 200

        # Fetch list & capture last_used timestamp
        list_resp = await async_client.get("/token")
        token_row = next(t for t in list_resp.json() if t["name"] == token_name)
        ts_success = datetime.fromisoformat(token_row["last_used"])

        # ------------------------------------------------------------------
        # 3. Failed verify (tamper with secret) – expect 401
        # ------------------------------------------------------------------
        prefix = good_token.split("_", 2)[1]
        bad_token = f"tk_{prefix}_{secrets.token_urlsafe(64)}"

        fail_resp = await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{bad_token}'.encode()).decode()}"
            },
        )
        assert fail_resp.status_code == 401

        # ------------------------------------------------------------------
        # 4. Re-list – last_used should be unchanged
        # ------------------------------------------------------------------
        list_resp2 = await async_client.get("/token")
        token_row2 = next(t for t in list_resp2.json() if t["name"] == token_name)
        ts_after_fail = datetime.fromisoformat(token_row2["last_used"])

        assert (
            ts_after_fail == ts_success
        ), "last_used was incorrectly updated on failed verify"

    finally:
        await async_client.post("/token/revoke", json={"name": token_name})


async def test_last_used_monotonically_increases(async_client: AsyncClient):
    """
    1. Create a token
    2. verify -> last_used = ts₁
    3. wait 0.2 s, verify again -> last_used = ts₂  (ts₂ > ts₁)
    4. wait 0.2 s, verify once more -> last_used = ts₃ (ts₃ > ts₂)
    """

    token_name = "monotonic-token"
    expires_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    try:
        # ------------------------------------------------------------------
        # 1. create token
        # ------------------------------------------------------------------
        create_resp = await async_client.post(
            "/token", json={"name": token_name, "expires_at": expires_at}
        )
        assert create_resp.status_code == 201
        token = create_resp.json()["token"]
        auth_hdr = {
            "Authorization": f"Basic {base64.b64encode(f'podpilot:{token}'.encode()).decode()}"
        }

        timestamps: list[datetime] = []

        # helper to verify & grab latest last_used
        async def verify_and_get_ts() -> datetime:
            v = await async_client.post("/token/verify", headers=auth_hdr)
            assert v.status_code == 200
            lst = await async_client.get("/token")
            row = next(t for t in lst.json() if t["name"] == token_name)
            return datetime.fromisoformat(row["last_used"])

        # ------------------------------------------------------------------
        # 2-4. perform 3 verifies with small delay
        # ------------------------------------------------------------------
        for _ in range(3):
            timestamps.append(await verify_and_get_ts())
            await asyncio.sleep(0.2)  # ensure distinct DB times

        ts1, ts2, ts3 = timestamps
        assert ts2 > ts1
        assert ts3 > ts2

    finally:
        # cleanup regardless of assertion outcome
        await async_client.post("/token/revoke", json={"name": token_name})


async def test_revoke_token(async_client):
    try:
        token_name = "revoke-token"
        response = await async_client.post(
            "/token",
            json={
                "name": token_name,
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(days=1)
                ).isoformat(),
            },
        )
        token = response.json()["token"]

        response = await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token}'.encode()).decode()}"
            },
        )
        assert response.status_code == 200
        assert response.json()["valid"] is True
        assert response.json()["user"] == "testuser"

        response = await async_client.post("/token/revoke", json={"name": token_name})
        assert response.status_code == 200
        assert response.json() == {"revoked": True}

        response = await async_client.post(
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token}'.encode()).decode()}"
            },
        )
        assert response.status_code == 401
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
            "/token/verify",
            headers={
                "Authorization": f"Basic {base64.b64encode(f'podpilot:{token_value}'.encode()).decode()}"
            },
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
