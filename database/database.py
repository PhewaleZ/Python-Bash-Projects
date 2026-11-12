from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from os import getenv

load_dotenv()
POSTGRES_PASS = getenv("POSTGRES_PASS")
DATABASE_NAME = getenv("DATABASE_NAME")
POSTGRES_USER =  getenv("POSTGRES_USER")
POSTGRES_HOSTNAME = getenv("POSTGRES_HOSTNAME")
DATABASE_URL = f"postgresql+psycopg://{POSTGRES_USER}:{POSTGRES_PASS}@{POSTGRES_HOSTNAME}:5432/{DATABASE_NAME}"


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