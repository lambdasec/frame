import sqlite3
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")
db = sqlite3.connect("tickets.db")


@mcp.tool()
def disk_usage(path: str) -> str:
    return subprocess.check_output(["du", "-sh", "--", path]).decode()


@mcp.tool()
def find_ticket(title: str) -> list:
    return db.execute("SELECT * FROM tickets WHERE title = ?", (title,)).fetchall()
