"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import os
import sys
import socket
import tempfile
import idaapi
from typing import TYPE_CHECKING

MCP_PORT_FILE = os.path.join(tempfile.gettempdir(), "ida_mcp_port.txt")


def _find_free_port(host: str, start_port: int, max_scan: int = 20) -> int:
    for port in range(start_port, start_port + max_scan):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
                s.bind((host, port))
            return port
        except OSError:
            continue
    raise OSError(
        f"[MCP] No free port found in range {start_port}–{start_port + max_scan - 1}"
    )


if TYPE_CHECKING:
    from . import ida_mcp


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

    # TODO: make these configurable
    HOST = "127.0.0.1"
    PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.mcp:
            self.mcp.stop()
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
            try:
                with open(MCP_PORT_FILE, "w") as f:
                    f.write(str(port))
            except Exception as e:
                print(f"[MCP] Warning: could not write port file: {e}")
            print(f"  Config: http://{self.HOST}:{port}/config.html")
            self.mcp = MCP_SERVER
        except OSError as e:
            print(f"[MCP] Error: {e}")
            raise

    def term(self):
        if self.mcp:
            self.mcp.stop()
            try:
                os.remove(MCP_PORT_FILE)
            except OSError:
                pass


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
