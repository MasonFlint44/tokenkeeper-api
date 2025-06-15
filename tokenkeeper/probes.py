import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_session
from .models import HealthResponse, ReadyResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/healthz", response_model=HealthResponse)
async def get_health():
    """
    Health check endpoint to verify the service is running.
    """
    logger.debug("Health check successful")
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=ReadyResponse)
async def get_ready(session: AsyncSession = Depends(get_session)):
    """
    Readiness check endpoint to verify the service is ready to accept requests.
    """
    try:
        async with session as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        logger.info("Readiness check unsuccessful")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service is not ready",
        ) from exc

    logger.debug("Readiness check successful")
    return ReadyResponse(status="ready")
