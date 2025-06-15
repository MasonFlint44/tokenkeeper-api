import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

db_host = os.environ["TOKENKEEPER_DB_HOST"]
db_name = os.environ["TOKENKEEPER_DB_NAME"]
db_user = os.environ["TOKENKEEPER_DB_USER"]
db_pass = os.environ["TOKENKEEPER_DB_PASSWORD"]

DATABASE_URL = f"postgresql+asyncpg://{db_user}:{db_pass}@{db_host}/{db_name}"
engine = create_async_engine(DATABASE_URL)
async_session = async_sessionmaker(engine, expire_on_commit=False)
Base = declarative_base()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session
