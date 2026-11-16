<img src="intruder_mcp/assets/icon.svg" alt="Intruder logo" width="80">

# Intruder MCP

Connect [Intruder](https://www.intruder.io/) to Claude, Cursor and other MCP clients, so you can ask questions like:

- "Which of my targets are exposing SSH?"
- "List all critical issues on my production targets."
- "Start a scan of everything tagged `external`."
- "Which TLS certificates expire in the next 30 days?"

For more examples, see [our blog post](https://www.intruder.io/blog/claude-intruder-mcp#intruder-mcp-use-cases).

> **Heads up:** this server runs on your own computer, so it works with **Claude Desktop**, **Claude Code**, **Cursor** and other desktop or CLI clients. It does not work with Claude in a web browser (claude.ai).

---

## Get started

### 1. Get an Intruder API key

Create an access token in the Intruder portal by following [Creating an access token](https://developers.intruder.io/docs/creating-an-access-token).

Treat it like a password: anyone with this key can see your targets and issues, and can start scans, add or delete targets, snooze issues, and start AI pentest release tests.

### 2. Add Intruder to Claude Desktop

1. [Download `intruder.mcpb`](https://github.com/intruder-io/intruder-mcp/releases/latest/download/intruder.mcpb) from the latest [GitHub release](https://github.com/intruder-io/intruder-mcp/releases/latest).
2. Double-click the file (or drag it into **Settings → Extensions** in Claude Desktop) and click **Install**.
3. Paste your API key when asked.

That's it: there's nothing else to install. Claude Desktop stores your key encrypted and runs the server for you.

> Claude Desktop warns that the extension can access everything on your computer and that its developer details aren't verified by Anthropic. It shows this for every extension installed from a file. This extension only talks to the Intruder API (`api.intruder.io`), and its source is in this repository.

**Using Claude Code, Cursor or another client?** Follow [Manual setup](#manual-setup) instead.

### 3. Check it works

Ask Claude:

> Who am I authenticated as in Intruder?

You should see the email address of the account your API key belongs to. If you do, you're all set.

---

## Manual setup

Use this for Claude Code, Cursor and other MCP clients, or if you'd rather configure Claude Desktop yourself. You'll need your [API key](#1-get-an-intruder-api-key).

### Choose how to run it

|                           | **uvx** (recommended)                                 | **Docker**                                                    |
| ------------------------- | ----------------------------------------------------- | ------------------------------------------------------------- |
| **Best if…**              | You want the quickest, lightest setup                 | You already use Docker, or want the server isolated from your machine |
| **You need to install**   | [uv](https://docs.astral.sh/uv/) (a single small tool) | Docker Desktop, OrbStack, Colima or similar                   |
| **Python required?**      | No, uv downloads it for you                           | No                                                            |
| **Needs to be running?**  | No                                                    | Yes, your container runtime must be running when you start your MCP client |
| **Isolation**             | Runs as your user, like any other app                 | Runs in a container, isolated from your files                 |

**Not sure? Use uvx.** If you are contributing to this project, see [Running from source](#running-from-source-for-contributors) instead.

#### uvx

Install uv if you don't have it already:

```bash
# macOS
brew install uv

# macOS or Linux, without Homebrew
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

You don't need to clone this repository: uvx downloads and runs the server for you the first time your MCP client starts it.

Next, find the full path to `uvx`, because Claude Desktop and some other apps don't see the same `PATH` as your terminal:

```bash
which uvx        # macOS / Linux, e.g. /opt/homebrew/bin/uvx
where uvx        # Windows
```

#### Docker

Make sure Docker (or another container runtime) is installed and running. You don't need to clone this repository or build anything: the image is published at `ghcr.io/intruder-io/intruder-mcp`.

Optionally, pull it now so the first start is quick:

```bash
docker pull ghcr.io/intruder-io/intruder-mcp
```

### Add it to your client

Pick your client below, then use the uvx **or** Docker snippet. In every snippet, replace `your-api-key` with your key. Afterwards, [check it works](#3-check-it-works).

#### Claude Code

Run one of these in your terminal:

```bash
# uvx
claude mcp add intruder -e INTRUDER_API_KEY=your-api-key -- \
  uvx --from git+https://github.com/intruder-io/intruder-mcp intruder-mcp

# Docker
claude mcp add intruder -e INTRUDER_API_KEY=your-api-key -- \
  docker run --interactive --rm --init --env INTRUDER_API_KEY ghcr.io/intruder-io/intruder-mcp
```

Run `claude mcp list` to confirm it's connected.

#### Claude Desktop

Open **Settings → Developer → Edit Config**, or open the file directly:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

If the file doesn't exist yet, create it. If it already has an `mcpServers` section, add the `"intruder"` entry inside it rather than adding a second `mcpServers`.

**uvx** (replace `/opt/homebrew/bin/uvx` with your path from `which uvx`):

```json
{
  "mcpServers": {
    "intruder": {
      "command": "/opt/homebrew/bin/uvx",
      "args": ["--from", "git+https://github.com/intruder-io/intruder-mcp", "intruder-mcp"],
      "env": {
        "INTRUDER_API_KEY": "your-api-key"
      }
    }
  }
}
```

**Docker:**

```json
{
  "mcpServers": {
    "intruder": {
      "command": "docker",
      "args": ["run", "--interactive", "--rm", "--init", "--env", "INTRUDER_API_KEY", "ghcr.io/intruder-io/intruder-mcp"],
      "env": {
        "INTRUDER_API_KEY": "your-api-key"
      }
    }
  }
}
```

Then **fully quit Claude Desktop** (Cmd+Q on macOS, or quit from the system tray on Windows) and open it again. Closing the window is not enough.

#### Cursor

Edit `~/.cursor/mcp.json` (for all projects) or `.cursor/mcp.json` (for one project), and add the same uvx or Docker snippet shown for Claude Desktop above.

#### Other MCP clients

Any client that supports local (stdio) MCP servers will work. Use the `command`, `args` and `env` values from the Claude Desktop snippets.

---

## Troubleshooting

**The Intruder tools don't appear**

- If you installed the Claude Desktop extension, check Intruder is turned on in **Settings → Extensions**, and that the API key there is correct.
- Make sure you fully quit and reopened your client after editing the config.
- Check the JSON is valid. A missing or extra comma is the most common problem; paste it into a JSON validator if unsure.
- For uvx, make sure `command` is the **full path** from `which uvx`, not just `uvx`.
- For Docker, make sure Docker is running.
- Make sure `INTRUDER_API_KEY` is set in your config. Without it, the server exits straight away with an error in the log.
- If you use Claude Desktop through a Team or Enterprise organization, your admin may have disabled local MCP servers.

**Tools appear but every request fails**

Your API key is probably mistyped or revoked. Check the `INTRUDER_API_KEY` value in your config, or create a new key.

**Test it outside your MCP client**

Running the server in a terminal shows errors that MCP clients often hide:

```bash
INTRUDER_API_KEY=your-api-key uvx --from git+https://github.com/intruder-io/intruder-mcp intruder-mcp
```

If it sits waiting with no error, it has started correctly (it's waiting for a client to talk to it). Press Ctrl+C to stop. This doesn't check your API key is valid: to do that, ask your client who you're authenticated as ([step 3](#3-check-it-works)).

**Logs**

- Claude Desktop on macOS: `~/Library/Logs/Claude/mcp-server-intruder.log`
- Claude Desktop on Windows: `%APPDATA%\Claude\logs\mcp-server-intruder.log`

---

## Updating

- **uvx:** uv caches the server after the first run. To get the latest version, run the command once with `--refresh`:
  ```bash
  uvx --refresh --from git+https://github.com/intruder-io/intruder-mcp intruder-mcp
  ```
  then press Ctrl+C and restart your MCP client.
- **Docker:** run `docker pull ghcr.io/intruder-io/intruder-mcp` and restart your MCP client.
- **Claude Desktop extension:** download and open the latest `intruder.mcpb` again.

**Want a fixed version?** For uvx, add a commit or tag to the URL, for example `git+https://github.com/intruder-io/intruder-mcp@<commit-sha>`. Updates then only happen when you change it.

---

## Keeping your API key safe

- If you configure the server manually, your key is stored in plain text in your MCP client's config file (the Claude Desktop extension stores it encrypted instead). On macOS or Linux you can make that file readable only by you with `chmod 600 <path-to-config>`.
- Never commit a config file containing your key to a repository, or paste the key into a chat.
- If you think your key has been exposed, revoke it in the Intruder portal and create a new one.

---

## What it can do

| Area | Tools |
| --- | --- |
| **Account** | `get_user`, `get_status`, `list_licenses` |
| **Targets and tags** | `list_targets`, `create_targets`, `delete_target`, `list_tags`, `create_target_tag`, `delete_target_tag` |
| **Attack surface** | `list_network_services` (open ports, products, versions, TLS certificate expiry) |
| **Issues** | `list_issues`, `list_occurrences`, `get_scanner_output`, `snooze_occurrence` |
| **Scans** | `list_scans`, `get_scan`, `create_scan`, `cancel_scan` |
| **Schedules** | `list_scan_schedules`, `create_scan_schedule`, `update_scan_schedule`, `delete_scan_schedule` |
| **AI pentests** | `list_ai_pentests`, `get_ai_pentest`, `list_ai_pentest_findings`, `start_ai_pentest_release_test` |

Some tools make changes to your Intruder account (creating or deleting targets, starting or cancelling scans, snoozing issues, starting AI pentest release tests). Most MCP clients ask you to approve each tool call before it runs, so review these carefully.

---

## Running from source (for contributors)

```bash
git clone https://github.com/intruder-io/intruder-mcp
cd intruder-mcp
uv sync
```

Then point your MCP client at your local copy, using the absolute path to the repository:

```json
{
  "mcpServers": {
    "intruder": {
      "command": "/opt/homebrew/bin/uv",
      "args": ["--directory", "/absolute/path/to/intruder-mcp", "run", "intruder-mcp"],
      "env": {
        "INTRUDER_API_KEY": "your-api-key"
      }
    }
  }
}
```

To build the Docker image locally: `docker build -t intruder-mcp .`

To build the Claude Desktop extension locally (needs Node): `npx @anthropic-ai/mcpb pack . intruder.mcpb`

---

## License

BSD 3-Clause. See [LICENSE.md](LICENSE.md).
