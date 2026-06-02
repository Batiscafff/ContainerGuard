from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routers.api import router as api_router
from app.routers.hx import router as hx_router
from app.routers.pages import router as pages_router

app = FastAPI(title="ContainerGuard", version="1.0.0")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(pages_router)
app.include_router(hx_router)
app.include_router(api_router)
