from sqlalchemy import String
from sqlalchemy import ForeignKey
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

class Scan(Base):
    __tablename__ = "scans"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey('User.user_id'),
        nullable=False
    )

    scan: Mapped[dict] = mapped_column(
        JSONB
    )

    #The reference isnt meant to be unique
    reference: Mapped[str] = mapped_column(
        String(24),
        nullable=False
    )
