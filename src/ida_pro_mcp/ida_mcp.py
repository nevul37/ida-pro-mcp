"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import os
import re
import sys
import json
import socket
import idaapi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337
MCP_SERVER_NAME = "ida-pro-mcp"


# ---------------------------------------------------------------------------
# Port helpers
# ---------------------------------------------------------------------------

def _is_port_in_use(host: str, port: int) -> bool:
    """Return True if something is already listening on the port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def _find_free_port(host: str, start_port: int, max_scan: int = 20) -> int:
    for port in range(start_port, start_port + max_scan):
        if not _is_port_in_use(host, port):
            return port
    raise OSError(
        f"[MCP] No free port found in range {start_port}–{start_port + max_scan - 1}"
    )


# ---------------------------------------------------------------------------
# MCP config registration helpers
# ---------------------------------------------------------------------------

def _mcp_config_paths() -> list[tuple[str, str]]:
    """Return (dir, filename) pairs for known MCP client config files that exist."""
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        appdata = os.getenv("APPDATA", "")
        candidates = [
            (os.path.join(home, ".cursor"), "mcp.json"),
            (home, ".claude.json"),  # Claude Code
            (os.path.join(appdata, "Claude"), "claude_desktop_config.json"),
            (os.path.join(appdata, "Code", "User", "globalStorage",
                          "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            (os.path.join(appdata, "Code", "User", "globalStorage",
                          "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
        ]
    elif sys.platform == "darwin":
        candidates = [
            (os.path.join(home, ".cursor"), "mcp.json"),
            (home, ".claude.json"),  # Claude Code
            (os.path.join(home, "Library", "Application Support", "Claude"),
             "claude_desktop_config.json"),
        ]
    else:
        candidates = [
            (os.path.join(home, ".cursor"), "mcp.json"),
            (home, ".claude.json"),  # Claude Code
        ]
    return [(d, f) for d, f in candidates if os.path.exists(os.path.join(d, f))]


def _get_binary_name() -> str:
    """Return a sanitized filename of the binary currently loaded in IDA."""
    try:
        path = idaapi.get_input_file_path()
        if path:
            name = os.path.basename(path)
            # Keep alphanumerics, dots, hyphens; replace everything else with _
            name = re.sub(r"[^a-zA-Z0-9.\-]", "_", name)
            name = name.strip("_.-")
            if name:
                return name
    except Exception:
        pass
    return "unknown"


def _make_server_name(port: int) -> str:
    """Build the MCP server entry name for a non-default IDA instance."""
    binary = _get_binary_name()
    return f"{MCP_SERVER_NAME}-{binary}-{port}"


def _register_mcp_server(host: str, port: int) -> tuple[str, list[str]]:
    """Add/update an MCP client config entry for this IDA instance.

    - Default port → keep the existing "ida-pro-mcp" entry unchanged.
    - Non-default port → clone it as "ida-pro-mcp-{binary}-{port}".

    Returns (server_name, list_of_updated_config_paths).
    """
    if port == DEFAULT_PORT:
        return MCP_SERVER_NAME, []

    server_name = _make_server_name(port)
    ida_rpc_url = f"http://{host}:{port}"
    updated: list[str] = []

    for config_dir, config_file in _mcp_config_paths():
        config_path = os.path.join(config_dir, config_file)
        try:
            with open(config_path, encoding="utf-8") as f:
                config = json.load(f)
        except Exception:
            continue

        servers: dict = config.get("mcpServers", {})
        base_entry: dict | None = servers.get(MCP_SERVER_NAME)
        if base_entry is None:
            continue  # ida-pro-mcp not configured in this client, skip

        if "url" in base_entry:
            # HTTP-type entry — point directly at IDA's HTTP server
            new_entry = {"type": "http", "url": f"{ida_rpc_url}/mcp"}
        else:
            # stdio-type entry — clone and update --ida-rpc argument
            new_entry = dict(base_entry)
            args: list[str] = list(new_entry.get("args", []))
            if "--ida-rpc" in args:
                idx = args.index("--ida-rpc")
                if idx + 1 < len(args):
                    args[idx + 1] = ida_rpc_url
                else:
                    args.append(ida_rpc_url)
            else:
                args += ["--ida-rpc", ida_rpc_url]
            new_entry["args"] = args

        servers[server_name] = new_entry
        config["mcpServers"] = servers

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            updated.append(config_path)
        except Exception as e:
            print(f"[MCP] Warning: could not update {config_path}: {e}")

    return server_name, updated


def _unregister_mcp_server(server_name: str) -> None:
    """Remove the named MCP entry from all client configs."""
    if server_name == MCP_SERVER_NAME:
        return  # Never remove the base entry

    for config_dir, config_file in _mcp_config_paths():
        config_path = os.path.join(config_dir, config_file)
        try:
            with open(config_path, encoding="utf-8") as f:
                config = json.load(f)
        except Exception:
            continue

        servers: dict = config.get("mcpServers", {})
        if server_name not in servers:
            continue

        del servers[server_name]
        config["mcpServers"] = servers
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"[MCP] Warning: could not update {config_path}: {e}")


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    HOST = DEFAULT_HOST
    PORT = DEFAULT_PORT

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self._active_port: int = self.PORT
        self._registered_server_name: str = MCP_SERVER_NAME
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.mcp:
            self.mcp.stop()
            _unregister_mcp_server(self._registered_server_name)
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        try:
            port = _find_free_port(self.HOST, self.PORT)
            if port != self.PORT:
                print(f"[MCP] Port {self.PORT} is in use, using port {port} instead")
            MCP_SERVER.serve(
                self.HOST, port, request_handler=IdaMcpHttpRequestHandler
            )
            self._active_port = port
            print(f"  Config: http://{self.HOST}:{port}/config.html")
            self.mcp = MCP_SERVER
        except OSError as e:
            print(f"[MCP] Error: {e}")
            raise

        # Register this instance in MCP client configs (non-default port only)
        server_name, updated_paths = _register_mcp_server(self.HOST, port)
        self._registered_server_name = server_name
        if updated_paths:
            print(f"[MCP] Added '{server_name}' to MCP client config(s):")
            for path in updated_paths:
                print(f"  {path}")
            print("[MCP] Reload MCP servers in your client to connect to this IDA instance")

    def term(self):
        if self.mcp:
            self.mcp.stop()
            _unregister_mcp_server(self._registered_server_name)


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
