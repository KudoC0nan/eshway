from uuid import uuid4
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import Annotated, List

SECRET_KEY = "c400dca013a11c69b7b65b8bda1e13055f75a18d0e25f2523a0e8bec88d49d3d"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "1": {
        "user_id":"1",
        "username":"Shreyas",
        "role":"admin",
        "full_name":"Shreyas Patil",
        "email":"sp@gmail.com",
        "hashed_password":"$2b$12$f7VsXk8zZ589p57tZiIFUuyvBbWnv/NY/EQuZ5RXl1ndPXrASzTGa",
        "disabled":False,
    }
}

documents = {"session": {}, "database": {}}

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    # username: str | None = None
    user_id: str | None = None

class User(BaseModel):
    user_id: str
    username: str
    role: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class UserLogin(BaseModel):
    username: str
    password: str

class UserSignup(BaseModel):
    username: str
    email: str
    full_name: str
    password: str

class UserInDB(User):
    hashed_password: str

class DocumentMetadata(BaseModel):
    document_id: str
    name: str
    type: str
    size: int
    timestamp: str
    storage: str
    status: str
    message: str
    user_id: str
    session_id: str = None

class DocumentResponse(BaseModel):
    documents: List[DocumentMetadata]

class DocumentContentResponse(BaseModel):
    document_id: str
    name: str
    type: str
    content: str
    content_url: str
    preview_html: str

class DocumentDeleteResponse(BaseModel):
    message: str
    count: int = None
    document_id: str = None

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, user_id: str):
    if user_id in db:
        user_dict = db[user_id]
        return UserInDB(**user_dict) 

def authenticate_user(fake_users_db, username: str, password: str):
    user = next((u for u in fake_users_db.values() if u["username"] == username), None)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(user_id: str, expires_delta: timedelta | None = None):
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode = {"user_id": user_id, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        # tenant_id = payload.get("tenant_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# later when databse will be added the looping for cheching the exisiting user is straight frwrd
@app.post("/signup", response_model=Token)
async def signup(user: UserSignup):
    if any(existing_user["username"] == user.username for existing_user in fake_users_db.values()):
        raise HTTPException(status_code=400, detail="Username already exists")
    user_id = str(uuid4())
    hashed_password = get_password_hash(user.password)
    fake_users_db[user.username] = {
        "user_id": user_id,
        "username":user.username,
        "full_name":user.full_name,
        "email":user.email,
        "hashed_password":hashed_password,
    }
    token = create_access_token(user_id=user_id)
    return {"access_token": token, "token_type": "bearer"}

# @app.post("/login", response_model=Token)
# async def login(user: UserLogin):
#     curr_user = fake_users_db.get(user.username)
#     if not curr_user or not verify_password(user.password,curr_user["hashed_password"]):
#         raise HTTPException(status_code=401, detail="Could not validate credentials")
#     token = create_access_token(user_id=user.username)
#     return {"access_token": token, "token_type": "bearer"}

# @app.post("/login")
# async def login(
#     form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
# ) -> Token:
#     user = authenticate_user(fake_users_db, form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user.username}, expires_delta=access_token_expires
#     )
#     return Token(access_token=access_token, token_type="bearer")

# authorisation dependancy
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user_id = decode_token(token)
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, user_id=token_data.user_id)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        user_id=user["user_id"], expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@app.post("/documents/session/upload", response_model=DocumentMetadata)
async def upload_documents(file: UploadFile = File(...), session_id: str = Form(...), user: UserInDB = Depends(get_current_user)):
    doc_id = str(uuid4())
    doc_meta = DocumentMetadata(
        document_id=doc_id,
        name=file.filename,
        type=file.content_type,
        size=0,
        timestamp=datetime.now(timezone.utc).isoformat(),
        storage="session",
        status="processed",
        message="uploaded",
        user_id=user.user_id,
        session_id=session_id
    )
    documents["session"].setdefault(session_id, {})[doc_id] = doc_meta
    return doc_meta

@app.post("/documents/database/upload", response_model=DocumentMetadata)
async def upload_documents(file: UploadFile = File(...), user: UserInDB = Depends(get_current_user)):
    doc_id = str(uuid4())
    doc_meta = DocumentMetadata(
        document_id=doc_id,
        name=file.filename,
        type=file.content_type,
        size=0,
        timestamp=datetime.now(timezone.utc).isoformat(),
        storage="database",
        status="processed",
        message="uploaded",
        user_id=user.user_id,
    )
    documents["database"][doc_id] = doc_meta
    return doc_meta

@app.get("/documents/session/{session_id}", response_model=DocumentResponse)
async def get_session_documents(session_id: str, user: UserInDB = Depends(get_current_user)):
    session_docs = [doc for doc in documents["session"].get(session_id, {}).values() if doc.user_id == user.user_id]
    return {"documents": session_docs}

@app.get("/documents/database/", response_model=DocumentResponse)
async def get_database_documents(user: UserInDB = Depends(get_current_user)):
    db_docs = [doc for doc in documents["database"].values() if doc.user_id == user.user_id]
    return {"documents": db_docs}

@app.get("/documents/session/{session_id}/{document_id}", response_model=DocumentContentResponse)
async def get_session_document_content(session_id: str, document_id: str, user: UserInDB = Depends(get_current_user)):
    doc = documents["session"].get(session_id, {}).get(document_id)
    if not doc or doc.user_id != user.user_id:
        raise HTTPException(status_code=404, detail="Document not found")
    return DocumentContentResponse(**doc.dict(), content="", content_url="", preview_html="")

@app.get("/documents/database/{document_id}", response_model=DocumentContentResponse)
async def get_database_document_content(document_id: str, user: UserInDB = Depends(get_current_user)):
    doc = documents["database"].get(document_id)
    if not doc or doc.user_id != user.user_id:
        raise HTTPException(status_code=404, detail="Document not found")
    return DocumentContentResponse(**doc.dict(), content="", content_url="", preview_html="")

@app.get("/system/status")
async def get_status():
    return {"status": "healthy", "version": "1.0.0", "message": "OK"} # to set up

# should we use user_id in url as the user is already logged in
# if admin then add role to the db
# @app.delete("/users/{user_id}/documents/{document_id}", response_model=DocumentDeleteResponse)
# async def delete_document(user_id: str, document_id: str, user: UserInDB = Depends(get_current_user)):
#     if user["role"] != "admin" and user["user_id"] != user_id:
#         raise HTTPException(status_code=403, detail="Not authorized to delete this document")
#     for storage in ["session", "database"]:
#         if storage == "session":
#             for sid in documents["session"]:
#                 if document_id in documents["session"][sid]:
#                     del documents["session"][sid][document_id]
#                     return {"message": "Document deleted successfully", "document_id": document_id}
#         else:
#             if document_id in documents["database"]:
#                 del documents["database"][document_id]
#                 return {"message": "Document deleted successfully", "document_id": document_id}
#     raise HTTPException(status_code=404, detail="Document not found")
@app.delete("/users/documents/{document_id}", response_model=DocumentDeleteResponse)
async def delete_document(document_id: str, user: UserInDB = Depends(get_current_user)):
    for storage in ["session", "database"]:
        if storage == "session":
            for sid in documents["session"]:
                if document_id in documents["session"][sid]:
                    del documents["session"][sid][document_id]
                    return {"message": "Document deleted successfully", "document_id": document_id}
        else:
            if document_id in documents["database"]:
                del documents["database"][document_id]
                return {"message": "Document deleted successfully", "document_id": document_id}
    raise HTTPException(status_code=404, detail="Document not found")
    

# @app.delete("/users/{user_id}/documents/session", response_model=DocumentDeleteResponse)

@app.delete("/users/documents/session/", response_model=DocumentDeleteResponse)
async def clear_session_documents(user: UserInDB = Depends(get_current_user)):
    print(documents["session"].keys())
    count = 0
    for sid in list(documents["session"].keys()):
        session_docs = documents["session"].get(sid, {})
        to_delete = [doc_id for doc_id, doc in session_docs.items() if doc.user_id == user.user_id]
        for doc_id in to_delete:
            del documents["session"][sid][doc_id]
            count += 1
        if not documents["session"][sid]:
            del documents["session"][sid]
    return {
        "message": "Session documents cleared successfully", "count": count
    }

# @app.delete("/users/{user_id}/documents/database", response_model=DocumentDeleteResponse)

@app.delete("/users/documents/database/", response_model=DocumentDeleteResponse)
async def clear_database_documents(user: UserInDB = Depends(get_current_user)):
    to_delete = [doc_id for doc_id, doc in documents["database"].items() if doc.user_id == user.user_id]
    for document_id in to_delete:
        del documents["database"][document_id]
    return {
        "message": "Database documents cleared successfully",
        "count": len(to_delete)
    }
