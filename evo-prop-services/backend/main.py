from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from config import settings

app = FastAPI(
    title="FastAPI",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    max_request_size=1024 * 1024 * 1024,
)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        app.mongodb_client = AsyncIOMotorClient(settings.DB_URL)
        app.mongodb = app.mongodb_client[settings.BUSINESS_DB]
        return await call_next(request)


app.add_middleware(AuthMiddleware)


@app.get('/')
def initialization():
    """
    Initialization Endpoint.
    """
    return "The server is running."


from apps.projects.routers import router as projects_router
app.include_router(projects_router, tags=["projects"], prefix="/api/projects")

from apps.wishlist.routers import router as wishlist_router
app.include_router(wishlist_router, tags=["wishlist"], prefix="/api/wishlist")
