from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import secrets
import os
from dotenv import load_dotenv

load_dotenv()
Words = os.getenv("Words")

# Constants
SECRET_KEY = "supersecretkey123"   # In production, keep it secure
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_schemes = OAuth2PasswordBearer(tokenUrl="token")

DB_URL = "sqlite:///./Database.db"
engine = create_engine(DB_URL, connect_args={"check_same_thread":False})
session = sessionmaker(autoflush=False,autocommit=False,bind=engine)
Base = declarative_base()

app = FastAPI()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer,unique=True,index=True,primary_key=True)
    username = Column(String,unique=True,index=True)
    password = Column(String,index=True)
    token = Column(String, index=True)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

def get_password_hash(passowrd):
    return pwd_context.hash(passowrd)

def verify_password(plain_password,hashed_password):
    return pwd_context.verify(plain_password,hashed_password)

def create_access_token(data:dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = session()
    try:
        yield db
    finally:
        db.close()

@app.post("/register/")
def register(username:str,password:str, db:Session = Depends(get_db)):
    user = db.query(User).filter(User.username==username).first()
    if user:
        return {"data":"Username already exists"}
    else:
        hashed_password = get_password_hash(password)
        random_token = secrets.token_hex(16)
        new_user = User(username=username,password=hashed_password, token = random_token)
        db.add(new_user)
        db.commit()
        return {"message":"User has been created","token":new_user.token}
    
@app.get("/users/")
def show_users(db:Session = Depends(get_db)):
    users = db.query(User).all()
    return users

@app.post("/change_token/")
def change_token(username:str,password:str,db:Session = Depends(get_db)):
    user = db.query(User).filter(User.username==username).first()
    if user:
        if verify_password(password,user.password):
                random_token = secrets.token_hex(16)
                user.token=random_token
                db.commit()
                return {"message":"token changed","token":user.token}        
    else:
        return {"Invalid Credentials"}


@app.post("/login/")
def login(username:str,password:str,db:Session = Depends(get_db)):
    user = db.query(User).filter(User.username==username).first()
    if user:
        if verify_password(password,user.password):
            return {"message":"welcome User","token":user.token}        
    else:
        return {"Invalid Credentials"}
    
@app.get("/api/{token}/{sentence}")
def api(token:str,sentence:str,db:Session = Depends(get_db)):
    check_token = db.query(User).filter(User.token==token).first()
    if check_token:
        curse_words = Words.split(",")
        user_sentence = sentence.split(" ")
        condition = False
        for x in user_sentence:
            for y in curse_words:
                if x==y:
                    condition = True
                    break
        return {"curse words":condition}
    else:
        return {"messgae":"user does not exists"}