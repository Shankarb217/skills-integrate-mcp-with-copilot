"""High School Management System API

This FastAPI application has been extended with a small, self-contained
JWT-based authentication system and a simple JSON-backed user store.

Notes:
- On first run the app will bootstrap a default admin user (username: admin,
  password: adminpass). Change this in production.
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# Simple in-memory activity database (unchanged)
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
}

# --- Simple JSON-backed user store + JWT setup ---
USERS_FILE = current_dir / "users.json"
PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")
HTTP_BEARER = HTTPBearer()

# NOTE: in production, keep the SECRET_KEY secret and rotate periodically
SECRET_KEY = os.environ.get("MHS_SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day


def load_users() -> Dict[str, Dict]:
    if not USERS_FILE.exists():
        # bootstrap a default admin user
        admin_pw = PWD_CONTEXT.hash("adminpass")
        data = {
            "admin": {"username": "admin", "password_hash": admin_pw, "role": "admin"}
        }
        USERS_FILE.write_text(json.dumps(data, indent=2))
        return data
    return json.loads(USERS_FILE.read_text())


def save_users(users: Dict[str, Dict]):
    USERS_FILE.write_text(json.dumps(users, indent=2))


def authenticate_user(username: str, password: str):
    users = load_users()
    user = users.get(username)
    if not user:
        return None
    if not PWD_CONTEXT.verify(password, user["password_hash"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTP_BEARER)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = load_users().get(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return user


@app.post("/auth/login")
def login(payload: dict):
    """Login endpoint. Expects JSON: {"username": "...", "password": "..."}
    Returns an access token on success.
    """
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": username, "role": user.get("role")})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str, _: dict = Depends(require_admin)):
    """Unregister a student from an activity (admin only)"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}

