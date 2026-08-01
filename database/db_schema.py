from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.dialects.postgresql import JSONB
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
