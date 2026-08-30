"""Local integration planes (Burp observation and Playwright workflows)."""

from .burp import BurpMCPClient, burp_mcp_health
from .playwright import playwright_health, write_program_mcp_config

__all__ = [
    "BurpMCPClient", "burp_mcp_health", "playwright_health",
    "write_program_mcp_config",
]
