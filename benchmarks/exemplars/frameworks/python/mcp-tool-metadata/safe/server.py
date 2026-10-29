from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES: list = []
SEARCH_DESCRIPTION = "Search the notes."


@mcp.tool()
def add_note(text: str, notes: str = "") -> str:
    """Save a note."""
    NOTES.append(text)
    return "saved"


@mcp.tool(description=SEARCH_DESCRIPTION + " Returns matching notes.")
def search_notes(query: str) -> list:
    return [n for n in NOTES if query in n]
