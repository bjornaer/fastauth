import asyncio
import contextlib

from contextlib import asynccontextmanager
from fastapi import FastAPI

from .token import clear_expired_revocations


async def periodic_token_cleanup(seconds: int = 3600) -> None:
    """Periodic task to clean up expired tokens"""
    while True:
        try:
            clear_expired_revocations()
        except Exception as e:
            print(f"Error cleaning up tokens: {e}")
        finally:
            await asyncio.sleep(seconds)


@asynccontextmanager
async def token_cleanup_lifespan(app: FastAPI, cleanup_interval_seconds: int = 3600):
    # Startup: Create the background task
    cleanup_task = asyncio.create_task(periodic_token_cleanup(cleanup_interval_seconds))

    yield  # FastAPI operates inside this yield

    # Shutdown: Cancel the background task
    cleanup_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await cleanup_task


def setup_periodic_tasks(app: FastAPI, cleanup_interval_seconds: int = 3600) -> None:
    """Setup periodic background tasks"""
    # Use the newer lifespan approach instead of on_event
    app.lifespan_context = token_cleanup_lifespan(app, cleanup_interval_seconds)
