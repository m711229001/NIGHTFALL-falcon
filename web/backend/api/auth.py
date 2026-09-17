"""Falcon MAG - Authentication API"""
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from core.security import create_access_token, get_current_user
from models.user import create_user, authenticate_user, init_users_db

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@router.on_event("startup")
async def startup():
    init_users_db()


@router.post("/register")
async def register(req: RegisterRequest):
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    try:
        user = create_user(req.username, req.email, req.password)
        token = create_access_token({"sub": user["username"], "role": user["role"]})
        return {"access_token": token, "token_type": "bearer", "user": user, "token": token}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login")
async def login(req: LoginRequest):
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]},
        "token": token,
    }


@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    return current_user
