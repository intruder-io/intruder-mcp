# Intruder MCP

Let MCP clients like Claude and Cursor control [Intruder](https://www.intruder.io/). For more information and sample use cases, please see [our blog post](https://www.intruder.io/blog/claude-intruder-mcp#intruder-mcp-use-cases).

## Installation
There are three ways to use the MCP server:
- Through [smithery](https://smithery.ai/server/@intruder-io/intruder-mcp)
- Locally on your machine with Python
- In a Docker container

All of these methods require you to provide an Intruder API key. To generate a key, see [the documentation](https://developers.intruder.io/docs/creating-an-access-token).

### Smithery
Follow the instructions on [smithery](https://smithery.ai/server/@intruder-io/intruder-mcp).

### Running Locally
Install [uv](https://github.com/astral-sh/uv) if it isn't already present, and then clone this repository and run the following from the root directory:

```bash
uv venv
uv pip install -e .
```

Then, add the following to your MCP client configuration, making sure to fill in your API key, and update the path to where you have cloned this repository:

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

### Running in a Container

Add the following to your MCP client configuration, making sure to fill in your API key:

```json
{
  "mcpServers": {
    "intruder": {
      "command": "docker",
      "args": [
        "container",
        "run",
        "--interactive",
        "--rm",
        "--init",
        "--env",
        "INTRUDER_API_KEY=<your-api-key>",
        "ghcr.io/intruder-io/intruder-mcp"
      ]
    }
  }
}
```
