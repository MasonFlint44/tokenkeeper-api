from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..tables import User


class UsersDataAccess:
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self.session = session

    async def ensure_user_exists(self, username: str) -> None:
        user_exists = await self.session.scalar(
            select(User.username).where(User.username == username).limit(1)
        )
        if not user_exists:
            self.session.add(User(username=username))
            await self.session.commit()
