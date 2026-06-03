import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.database import async_session_factory
from app.models.user import User
from app.routers.api import router as api_router
from app.routers.auth import pwd_context
from app.routers.auth import router as auth_router
from app.routers.hx import router as hx_router
from app.routers.pages import router as pages_router


async def _seed_admin():
    async with async_session_factory() as db:
        result = await db.execute(select(User))
        if result.scalar_one_or_none() is None:
            password = secrets.token_urlsafe(16)
            user = User(
                email=settings.admin_email,
                hashed_password=pwd_context.hash(password),
                api_key=secrets.token_hex(32),
            )
            db.add(user)
            await db.commit()
            print("\n" + "=" * 52)
            print("  ContainerGuard — обліковий запис адміна")
            print(f"  Email:    {settings.admin_email}")
            print(f"  Пароль:   {password}")
            print("  Збережіть ці дані — пароль більше не з'явиться")
            print("=" * 52 + "\n", flush=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _seed_admin()
    yield


app = FastAPI(title="ContainerGuard", version="1.0.0", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.app_secret_key)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth_router)
app.include_router(pages_router)
app.include_router(hx_router)
app.include_router(api_router)
