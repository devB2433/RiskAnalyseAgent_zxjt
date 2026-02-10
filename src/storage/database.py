"""
数据库管理类

提供数据库连接、初始化和会话管理
"""
from typing import Optional
from contextlib import contextmanager, asynccontextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from .models import Base


class Database:
    """
    数据库管理类

    支持SQLite和PostgreSQL
    """

    def __init__(self, database_url: str, echo: bool = False):
        """
        初始化数据库

        Args:
            database_url: 数据库连接URL
                - SQLite: sqlite:///./data.db
                - PostgreSQL: postgresql://user:pass@localhost/dbname
            echo: 是否打印SQL语句
        """
        self.database_url = database_url
        self.echo = echo
        self.engine = None
        self.SessionLocal = None

    def init_db(self):
        """初始化数据库（同步）"""
        self.engine = create_engine(
            self.database_url,
            echo=self.echo,
            pool_pre_ping=True  # 连接池预检查
        )

        # 创建会话工厂
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )

        # 创建所有表
        Base.metadata.create_all(bind=self.engine)

    @contextmanager
    def get_session(self):
        """
        获取数据库会话（同步）

        使用方式:
            with db.get_session() as session:
                # 使用session进行数据库操作
                pass
        """
        if self.SessionLocal is None:
            raise RuntimeError("Database not initialized. Call init_db() first.")

        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def drop_all_tables(self):
        """删除所有表（谨慎使用）"""
        if self.engine is None:
            raise RuntimeError("Database not initialized. Call init_db() first.")

        Base.metadata.drop_all(bind=self.engine)

    def close(self):
        """关闭数据库连接"""
        if self.engine:
            self.engine.dispose()


class AsyncDatabase:
    """
    异步数据库管理类

    支持异步操作
    """

    def __init__(self, database_url: str, echo: bool = False):
        """
        初始化异步数据库

        Args:
            database_url: 数据库连接URL
                - SQLite: sqlite+aiosqlite:///./data.db
                - PostgreSQL: postgresql+asyncpg://user:pass@localhost/dbname
            echo: 是否打印SQL语句
        """
        self.database_url = database_url
        self.echo = echo
        self.engine = None
        self.AsyncSessionLocal = None

    async def init_db(self):
        """初始化数据库（异步）"""
        self.engine = create_async_engine(
            self.database_url,
            echo=self.echo,
            pool_pre_ping=True
        )

        # 创建会话工厂
        self.AsyncSessionLocal = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

        # 创建所有表
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    @asynccontextmanager
    async def get_session(self):
        """
        获取数据库会话（异步）

        使用方式:
            async with db.get_session() as session:
                # 使用session进行数据库操作
                pass
        """
        if self.AsyncSessionLocal is None:
            raise RuntimeError("Database not initialized. Call init_db() first.")

        async with self.AsyncSessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def drop_all_tables(self):
        """删除所有表（谨慎使用）"""
        if self.engine is None:
            raise RuntimeError("Database not initialized. Call init_db() first.")

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    async def close(self):
        """关闭数据库连接"""
        if self.engine:
            await self.engine.dispose()


# 全局数据库实例
_db_instance: Optional[Database] = None
_async_db_instance: Optional[AsyncDatabase] = None


def get_database(database_url: str = "sqlite:///./security_analysis.db", echo: bool = False) -> Database:
    """
    获取数据库实例（单例模式）

    Args:
        database_url: 数据库连接URL
        echo: 是否打印SQL语句

    Returns:
        Database实例
    """
    global _db_instance

    if _db_instance is None:
        _db_instance = Database(database_url, echo)
        _db_instance.init_db()

    return _db_instance


def get_async_database(
    database_url: str = "sqlite+aiosqlite:///./security_analysis.db",
    echo: bool = False
) -> AsyncDatabase:
    """
    获取异步数据库实例（单例模式）

    Args:
        database_url: 数据库连接URL
        echo: 是否打印SQL语句

    Returns:
        AsyncDatabase实例
    """
    global _async_db_instance

    if _async_db_instance is None:
        _async_db_instance = AsyncDatabase(database_url, echo)

    return _async_db_instance
