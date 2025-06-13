from contextlib import asynccontextmanager
from typing import AsyncGenerator, Iterable

from fastapi import Depends
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..tables import Token


class TokensDataAccess:
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self.session = session

    async def list_active_tokens(self, username: str) -> Iterable[Token]:
        result = await self.session.scalars(
            select(Token)
            .where(
                Token.user == username,
                Token.revoked.is_(False),
                (Token.expires_at.is_(None) | (Token.expires_at > func.now())),
            )
            .order_by(Token.created_at.desc())
        )
        return result.all()

    async def get_active_token_by_name(self, username: str, name: str) -> Token | None:
        result = await self.session.scalars(
            select(Token)
            .where(
                Token.user == username,
                Token.name == name,
                Token.revoked.is_(False),
                (Token.expires_at.is_(None) | (Token.expires_at > func.now())),
            )
            .limit(1)
        )
        return result.one_or_none()

    async def create_token(self, token: Token) -> bool:
        self.session.add(token)
        try:
            await self.session.commit()
            return True
        except IntegrityError:
            await self.session.rollback()
            return False

    @asynccontextmanager
    async def lock_active_token(
        self, prefix: str
    ) -> AsyncGenerator[Token | None, None]:
        """
        Yield the active Token row (if any) locked FOR UPDATE inside a TX.
        """
        async with self.session.begin():  # opens TX, handles commit/rollback
            stmt = (
                select(Token)
                .where(
                    Token.prefix == prefix,
                    Token.revoked.is_(False),
                    (Token.expires_at.is_(None) | (Token.expires_at > func.now())),
                )
                .with_for_update()
                .limit(1)
            )

            token: Token | None = await self.session.scalar(stmt)

            try:
                yield token
            finally:
                # Nothing else to do; session.begin() handles commit/rollback.
                pass

    async def revoke_token_by_name(self, username: str, name: str) -> bool:
        stmt = (
            update(Token)
            .where(
                Token.user == username,
                Token.name == name,
                Token.revoked.is_(False),
                (Token.expires_at.is_(None) | (Token.expires_at > func.now())),
            )
            .values(revoked=True)
            .returning(Token.prefix)
        )

        result = await self.session.execute(stmt)
        await self.session.commit()

        return result.first() is not None

    def touch_token(self, token: Token) -> None:
        token.last_used = func.now()
