from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import require_admin
from app.models.user import User

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="app/templates")


@router.get("/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).order_by(User.created_at))
    users = result.scalars().all()
    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "users": users, "current_user": current_user},
    )


@router.post("/users/{user_id}/activate")
async def activate_user(
    user_id: str,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if user:
        user.is_active = True
        await db.commit()
    return RedirectResponse("/admin/users", status_code=302)


@router.post("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if user and user.id != current_user.id:
        user.is_active = False
        await db.commit()
    return RedirectResponse("/admin/users", status_code=302)


@router.post("/users/{user_id}/promote")
async def promote_user(
    user_id: str,
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if user:
        user.is_admin = True
        user.is_active = True
        await db.commit()
    return RedirectResponse("/admin/users", status_code=302)


@router.post("/users/{user_id}/demote")
async def demote_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if user and user.id != current_user.id:
        user.is_admin = False
        await db.commit()
    return RedirectResponse("/admin/users", status_code=302)


@router.post("/users/{user_id}/delete")
async def delete_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if user and user.id != current_user.id:
        await db.delete(user)
        await db.commit()
    return RedirectResponse("/admin/users", status_code=302)
