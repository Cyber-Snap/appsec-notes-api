from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext

# -----------------------------
# App + Security Configuration
# -----------------------------
app = FastAPI(title="AppSec Notes API")

# NOTE: In real apps, keep secrets out of code (env vars / secrets manager).
SECRET_KEY = "change-me-in-real-life"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# -----------------------------
# In-memory "database"
# (We’ll replace this later with a real DB)
# -----------------------------
users_db: Dict[str, Dict] = {}
notes_db: Dict[str, List[Dict]] = {}  # username -> list of notes


# -----------------------------
# Helpers
# -----------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_access_token(subject: str, role: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {"sub": subject, "role": role, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if not username or username not in users_db:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return {"username": username, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")


def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# -----------------------------
# Routes (Endpoints)
# -----------------------------
@app.get("/")
def home():
    return {"status": "ok", "message": "Welcome to the AppSec Notes API"}


@app.post("/register")
def register(username: str, password: str, role: str = "user"):
    """
    Register a new user.
    SECURITY NOTE: This is intentionally simple for learning.
    We'll harden it later (validation, role assignment rules, DB, etc.)
    """
    if username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    if role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role")

    users_db[username] = {"username": username, "password_hash": hash_password(password), "role": role}
    notes_db[username] = []
    return {"created": True, "username": username, "role": role}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login using username + password.
    Returns a JWT token.
    """
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token = create_access_token(subject=user["username"], role=user["role"])
    return {"access_token": token, "token_type": "bearer"}


@app.get("/notes")
def list_notes(user: Dict = Depends(get_current_user)):
    return {"username": user["username"], "notes": notes_db.get(user["username"], [])}


@app.post("/notes")
def create_note(text: str, user: Dict = Depends(get_current_user)):
    note = {"id": len(notes_db[user["username"]]) + 1, "text": text}
    notes_db[user["username"]].append(note)
    return {"created": True, "note": note}


@app.get("/admin")
def admin_panel(admin: Dict = Depends(require_admin)):
    return {"message": f"Welcome, admin {admin['username']}!", "users": list(users_db.keys())}


@app.get("/notes/{note_id}")
def get_note(note_id: int, user: Dict = Depends(get_current_user)):
    # search all notes regardless of owner
    for owner in notes_db:
        for note in notes_db[owner]:
            if note["id"] == note_id:
                return note

    raise HTTPException(status_code=404, detail="Note not found")
