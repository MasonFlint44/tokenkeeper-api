import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from tokenkeeper import app
from tokenkeeper.auth import get_current_username


@pytest.fixture(scope="session", autouse=True)
def anyio_backend():
    return ("asyncio", {"use_uvloop": True})


@pytest.fixture(scope="session", autouse=True)
def mock_get_current_user():
    app.dependency_overrides[get_current_username] = lambda: {
        "username": "testuser",
    }


@pytest.fixture(scope="session")
async def async_client():
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac,
        LifespanManager(app),
    ):
        yield ac
