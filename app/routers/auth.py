import secrets

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Невірний email або пароль"},
            status_code=401,
        )
    request.session["user_id"] = user.id
    request.session["user_email"] = user.email
    request.session["is_admin"] = user.is_admin
    return RedirectResponse("/" if user.is_active else "/pending", status_code=302)


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "error": None, "email": ""})


@router.post("/register")
async def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    if password != password2:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Паролі не збігаються", "email": email},
            status_code=400,
        )
    if len(password) < 8:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Пароль має бути не менше 8 символів", "email": email},
            status_code=400,
        )
    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none():
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Цей email вже зареєстровано", "email": email},
            status_code=400,
        )
    user = User(
        email=email,
        hashed_password=pwd_context.hash(password),
        api_key=secrets.token_hex(32),
        is_active=False,
        is_admin=False,
    )
    db.add(user)
    await db.commit()
    request.session["user_id"] = user.id
    request.session["user_email"] = user.email
    return RedirectResponse("/pending", status_code=302)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@router.get("/pending", response_class=HTMLResponse)
async def pending_page(request: Request):
    if not request.session.get("user_id"):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("pending.html", {"request": request})


@router.get("/profile", response_class=HTMLResponse)
async def profile(
    request: Request,
    user: User = Depends(get_current_user),
):
    return templates.TemplateResponse("profile.html", {"request": request, "user": user})


@router.post("/profile/regenerate-key")
async def regenerate_key(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user.api_key = secrets.token_hex(32)
    await db.commit()
    return RedirectResponse("/profile", status_code=302)
