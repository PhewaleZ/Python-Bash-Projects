from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from os import getenv

load_dotenv()
postgres_password =getenv("POSTGRES_PASS")
DATABASE_URL = f"postgresql+psycopg://postgres:{postgres_password}@localhost:5432/cybersecurity_api"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()