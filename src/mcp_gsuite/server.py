import logging
from collections.abc import Sequence
from typing import Any
import sys

from dotenv import load_dotenv
from mcp.server import Server
from mcp.types import (
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)

from . import gauth
from . import tools_gmail
from . import tools_calendar
from . import toolhandler

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("quantumcrew-mail")


def setup_oauth2(user_id: str):
    """Ensure valid OAuth2 credentials exist for the given user.

    If no credentials are stored, runs the interactive OAuth flow.
    If credentials are expired, refreshes them automatically.
    """
    accounts = gauth.get_account_info()
    if not accounts:
        raise RuntimeError("No accounts configured in accounts file")

    known_emails = [a.email.lower() for a in accounts]
    if user_id.lower() not in known_emails:
        raise RuntimeError(f"Account '{user_id}' not found in accounts configuration")

    credentials = gauth.get_stored_credentials(user_id=user_id)
    if not credentials:
        logger.info(f"No credentials for {user_id}, starting OAuth flow...")
        gauth.run_oauth_flow(user_id=user_id)
    elif credentials.expired or not credentials.valid:
        logger.info(f"Refreshing expired credentials for {user_id}")
        credentials = gauth.refresh_credentials(credentials)
        gauth.store_credentials(credentials=credentials, user_id=user_id)


# --- MCP Server ---

app = Server("quantumcrew-mail")

tool_handlers: dict[str, toolhandler.ToolHandler] = {}


def add_tool_handler(tool_class: toolhandler.ToolHandler):
    tool_handlers[tool_class.name] = tool_class


def get_tool_handler(name: str) -> toolhandler.ToolHandler | None:
    return tool_handlers.get(name)


# Gmail tools
add_tool_handler(tools_gmail.QueryEmailsToolHandler())
add_tool_handler(tools_gmail.GetEmailByIdToolHandler())
add_tool_handler(tools_gmail.CreateDraftToolHandler())
add_tool_handler(tools_gmail.DeleteDraftToolHandler())
add_tool_handler(tools_gmail.ReplyEmailToolHandler())
add_tool_handler(tools_gmail.SendEmailToolHandler())
add_tool_handler(tools_gmail.ArchiveEmailToolHandler())
add_tool_handler(tools_gmail.BatchArchiveEmailToolHandler())
add_tool_handler(tools_gmail.LabelEmailToolHandler())
add_tool_handler(tools_gmail.MarkEmailToolHandler())
add_tool_handler(tools_gmail.TrashEmailToolHandler())
add_tool_handler(tools_gmail.GetLabelsToolHandler())
add_tool_handler(tools_gmail.GetAttachmentToolHandler())
add_tool_handler(tools_gmail.BulkGetEmailsByIdsToolHandler())
add_tool_handler(tools_gmail.BulkSaveAttachmentsToolHandler())

# Calendar tools
add_tool_handler(tools_calendar.ListCalendarsToolHandler())
add_tool_handler(tools_calendar.GetCalendarEventsToolHandler())
add_tool_handler(tools_calendar.CreateCalendarEventToolHandler())
add_tool_handler(tools_calendar.DeleteCalendarEventToolHandler())


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [th.get_tool_description() for th in tool_handlers.values()]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    try:
        if not isinstance(arguments, dict):
            raise RuntimeError("Arguments must be a dictionary")

        if toolhandler.USER_ID_ARG not in arguments:
            raise RuntimeError(f"Missing required argument: {toolhandler.USER_ID_ARG}")

        # Resolve alias to email — raises ValueError if unknown account
        arguments[toolhandler.USER_ID_ARG] = gauth.resolve_user_id(
            arguments[toolhandler.USER_ID_ARG]
        )

        setup_oauth2(user_id=arguments[toolhandler.USER_ID_ARG])

        tool_handler = get_tool_handler(name)
        if not tool_handler:
            raise ValueError(f"Unknown tool: {name}")

        return tool_handler.run_tool(arguments)
    except ValueError as e:
        # Known validation errors — safe to surface
        raise RuntimeError(str(e))
    except RuntimeError:
        raise
    except Exception as e:
        # Sanitize unexpected errors — don't leak internal details
        logger.error(f"Unexpected error in {name}: {type(e).__name__}: {e}")
        raise RuntimeError(f"Tool '{name}' failed. Check server logs for details.")


async def main():
    accounts = gauth.get_account_info()
    for account in accounts:
        creds = gauth.get_stored_credentials(user_id=account.email)
        if creds:
            logger.info(f"Found stored credentials for {account.alias or account.email}")

    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )
