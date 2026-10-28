import sqlite3
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")
db = sqlite3.connect("tickets.db")


@mcp.tool()
def disk_usage(path: str) -> str:
    return subprocess.check_output(f"du -sh {path}", shell=True).decode()  # frame-expect: CWE-78


@mcp.tool()
def find_ticket(title: str) -> list:
    return db.execute(f"SELECT * FROM tickets WHERE title = '{title}'").fetchall()  # frame-expect: CWE-89
