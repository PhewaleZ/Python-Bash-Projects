from sqlalchemy import String, ForeignKey, DateTime, func
from datetime import datetime
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase
from sqlalchemy.dialects.postgresql import UUID, JSONB
from uuid6 import uuid7

class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        unique=True
    )

    user_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid7
    )

    user_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=False
    )

    is_admin: Mapped[bool] = mapped_column(
        default=False,
        nullable=False
    )

class Log(Base):
    __tablename__ = "logs"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.user_id"),
        nullable=False)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    data: Mapped[JSONB] = mapped_column(
        nullable=None
    )