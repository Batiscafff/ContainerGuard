from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User


async def require_session(request: Request) -> str:
    """For HTML routes — redirects to /login if no session."""
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return user_id


async def require_auth(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> str:
    """For API routes — accepts session cookie OR X-API-Key header."""
    if x_api_key:
        result = await db.execute(select(User).where(User.api_key == x_api_key))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=403, detail="Invalid API key")
        return user.id
    user_id = request.session.get("user_id")
    if user_id:
        return user_id
    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide X-API-Key header or log in.",
    )
