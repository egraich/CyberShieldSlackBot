import os
import asyncio
from dotenv import load_dotenv
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from database import init_db
from services import SecurityService
from handlers import register_handlers

load_dotenv()

async def main():
    app = AsyncApp(token=os.environ.get("SLACK_BOT_TOKEN"))
    await init_db()

    try:
        security = SecurityService()
        register_handlers(app, security)
        handler = AsyncSocketModeHandler(app, os.environ.get("SLACK_APP_TOKEN"))
        await handler.start_async()
    finally:
        if 'security' in locals():
            await security.close()

if __name__ == "__main__":
    asyncio.run(main())