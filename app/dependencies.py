from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Returns logged-in user or redirects to /login."""
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    user = await db.get(User, user_id)
    if not user:
        request.session.clear()
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return user


async def require_active(user: User = Depends(get_current_user)) -> User:
    """Logged-in AND activated by admin."""
    if not user.is_active:
        raise HTTPException(status_code=307, headers={"Location": "/pending"})
    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    """Logged-in AND is_admin=True."""
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Доступ заборонено")
    return user


async def require_auth(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> User:
    """For API routes — accepts session cookie OR X-API-Key header. User must be active."""
    if x_api_key:
        result = await db.execute(select(User).where(User.api_key == x_api_key))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=403, detail="Invalid API key")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is not activated")
        return user
    user_id = request.session.get("user_id")
    if user_id:
        user = await db.get(User, user_id)
        if user and user.is_active:
            return user
        if user and not user.is_active:
            raise HTTPException(status_code=403, detail="Account is not activated")
    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide X-API-Key header or log in.",
    )


# Keep for backward compat with hx.py router-level dependency
require_session = require_active
