"""
Auth Service - Main application
"""
from fastapi import FastAPI, status, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from shared.config.settings import settings
from shared.utils.logger import setup_logger
from .database import init_db, close_db
from .routes import auth, users, partners, pos
import time

# Setup logger
logger = setup_logger("auth-service", settings.log_level, settings.log_format)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    # Startup
    logger.info("Starting Auth Service...")
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down Auth Service...")
    await close_db()
    logger.info("Database connections closed")


# Create FastAPI app
app = FastAPI(
    title="Restaurant Management - Auth Service",
    description="Authentication and Authorization Service",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Debug middleware to log headers
@app.middleware("http")
async def log_headers(request: Request, call_next):
    """Log incoming request headers for debugging"""
    if "/api/v1/auth/users" in request.url.path:
        print(f"DEBUG AUTH SERVICE: Received request to {request.url.path}")
        print(f"DEBUG AUTH SERVICE: Authorization header = {request.headers.get('authorization', 'NOT FOUND')}")
        print(f"DEBUG AUTH SERVICE: All headers = {dict(request.headers)}")
    response = await call_next(request)
    return response

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/v1/auth", tags=["User Management"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(partners.router, prefix="/api/v1/partners", tags=["Partners"])
app.include_router(pos.router, prefix="/api/v1/auth", tags=["POS Auth"])


@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    """Root endpoint"""
    return {
        "service": "Auth Service",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "auth-service"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.auth_service_port,
        reload=True if settings.environment == "development" else False,
        log_level=settings.log_level.lower()
    )
