from pydantic import BaseModel
from typing import Optional

# Transaction Schemas
class TransactionCreate(BaseModel):
    title: str
    amount: float
    category: str

class TransactionOut(TransactionCreate):
    id: int

    class Config:
        orm_mode = True

# User Schemas
class UserCreate(BaseModel):
    username: str
    password: str

# Token Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
