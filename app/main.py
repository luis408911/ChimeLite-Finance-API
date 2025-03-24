from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List

from database import Base, engine, get_db
from models import User, Transaction
from schemas import UserCreate, Token, TransactionCreate, TransactionOut
from auth import authenticate_user, create_access_token, get_password_hash, get_current_user

from datetime import timedelta

app = FastAPI()

Base.metadata.create_all(bind=engine)

# --- User Routes ---
@app.post("/users/")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User created", "user_id": db_user.id}

@app.post("/token", response_model=Token)
def login_for_access_token(user: UserCreate, db: Session = Depends(get_db)):
    user_db = authenticate_user(db, user.username, user.password)
    if not user_db:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user_db.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- Transaction Routes ---
@app.post("/transactions/", response_model=TransactionOut)
def create_transaction(transaction: TransactionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_transaction = Transaction(**transaction.dict(), user_id=current_user.id)
    db.add(db_transaction)
    db.commit()
    db.refresh(db_transaction)
    return db_transaction

@app.get("/transactions/", response_model=List[TransactionOut])
def get_transactions(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    transactions = db.query(Transaction).filter(Transaction.user_id == current_user.id).all()
    return transactions

@app.get("/analytics/")
def spending_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    transactions = db.query(Transaction).filter(Transaction.user_id == current_user.id).all()
    total_spent = sum(t.amount for t in transactions)
    by_category = {}
    for t in transactions:
        by_category[t.category] = by_category.get(t.category, 0) + t.amount
    return {"total_spent": total_spent, "breakdown": by_category}

# Run with: uvicorn main:app --reload
