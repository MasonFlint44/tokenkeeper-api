from httpx import AsyncClient


async def test_list_tokens(async_client: AsyncClient):
    response = await async_client.get("/token")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    for token in response.json():
        assert "name" in token
        assert "created_at" in token
        assert "last_used" in token
        assert "expires_at" in token
