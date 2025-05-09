# Intruder MCP

A Claude MCP server for the Intruder API.

## Installation

1. Install [uv](https://github.com/astral-sh/uv)
2. Clone this repository
3. Install dependencies:
```bash
uv pip install -e .
```

## Get and Intruder API Key
See [the docs](https://developers.intruder.io/docs/creating-an-access-token).

## Claude Configuration

Add this to your Claude config:

```json
{
  "mcpServers": {
    "intruder": {
      "command": "uv",
      "args": [
        "--directory",
        "path/to/intruder-mcp/intruder_mcp",
        "run",
        "server.py"
      ],
      "env": {
        "INTRUDER_API_KEY": "your-api-key"
      }
    }
  }
}
```