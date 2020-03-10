import asyncio
import json
import logging
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile, mkdtemp
from time import time
from typing import Any, Dict, Optional, Tuple
from zipfile import ZipFile

from pydantic import BaseModel, BaseSettings, ValidationError
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

# from .storage import Storage

logger = logging.getLogger('termsend')
THIS_DIR = Path(__file__).parent.resolve()


class Settings(BaseSettings):
    pg: str = None

    class Config:
        env_file = THIS_DIR / '.env'


# storage: Storage
loop: asyncio.AbstractEventLoop
settings: Settings


class PrettyJSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        return json.dumps(content, indent=2).encode() + b'\n'


def index(request):
    return JSONResponse({'name': 'termsend'})


def send_file(request):
    return JSONResponse({'name': 'termsend'})


async def startup():
    global settings, storage, loop
    settings = Settings()
    # storage = Storage(settings.bucket)
    loop = asyncio.get_event_loop()


async def shutdown():
    try:
        await storage.close()
    except NameError:
        pass


routes = [
    Route('/', index, methods=['GET']),
    Route('/cli/send/', send_file, methods=['POST']),
]

