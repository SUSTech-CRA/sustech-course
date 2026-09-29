from fastapi import APIRouter

from app.api.v1 import admin, auth, challenge, courses, meta, reviews, search, stats, teachers, upload, users

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(challenge.router, prefix="/challenge", tags=["challenge"])
api_router.include_router(courses.router, prefix="/course", tags=["courses"])
api_router.include_router(reviews.router, prefix="/review", tags=["reviews"])
api_router.include_router(users.router, prefix="/user", tags=["users"])
api_router.include_router(teachers.router, prefix="/teacher", tags=["teachers"])
api_router.include_router(search.router, prefix="/search", tags=["search"])
api_router.include_router(stats.router, prefix="/stats", tags=["stats"])
api_router.include_router(meta.router, prefix="/meta", tags=["meta"])
api_router.include_router(upload.router, prefix="/upload", tags=["upload"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
