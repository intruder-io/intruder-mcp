# Intruder MCP

A Model Controller Protocol (MCP) server for the Intruder API.

## Installation

The MCP server is a Python application that can be run locally or in a container.

### Running Locally

* Install [uv](https://github.com/astral-sh/uv)
* Clone this repository
* Install dependencies:

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
```

### Running in a Container

* Build the container used by the MCP client. Client configuration is explained in the next section.

```bash
docker image build --tag mcp/intruder .
```

## Get and Intruder API Key

See [the docs](https://developers.intruder.io/docs/creating-an-access-token).

## MCP client configuration

The MCP client is a tool that allows you to interact with the MCP server. It is a CLI tool that is used to send messages to the MCP server. Available clients are:

* [Claude](https://docs.anthropic.com/en/docs/mcp/claude)
* [Docker Toolkit](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/) and [MCP Program](https://www.docker.com/products/mcp-catalog-and-toolkit/)
* [Cursor](https://docs.cursor.com/context/model-context-protocol)

Clients are configured in the `mcp.json` file. Each client file is in a different local directory. The structure has a principal block with a list of clients called `mcpServers`.

Each client has a `command` and `args` field. The `command` is the command to run the client. The `args` is an array of arguments to pass to the command. The `command` field can use local processes or containers.

* Local process:

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

* Container:

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
        "mcp/intruder"
      ]
    }
  }
}
```
