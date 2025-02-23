from sqlalchemy import create_engine

SQLALCHEMY_DATABASE_URL = (
    "postgresql://postgres:test1234!@localhost/TodoApplicationDatabase"
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine(SQLALCHEMY_DATABASE_URL)

sessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
