from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "postgresql+asyncpg://postgres:root@localhost/phishing_db"

engine = create_async_engine(DATABASE_URL, echo=True)

# Фабрика сесій, через неї відбуваються запити
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

# Функція для отримання сесії
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
    