"""Claude Desktop integration: OpsBrain as a Desktop extension (.mcpb), installed like any other extension.

    Claude Desktop --stdio--> launcher (the .mcpb, `extension/`, Node, no dependencies) --stdio--> opsbrain serve

The bundle is a zip: manifest.json + server/index.js. The absolute path of the `opsbrain` binary, the config file
and a usable PATH are baked into the manifest at build time, because a GUI app starts servers with a bare
environment (no ~/.local/bin, no Homebrew, no SSH_AUTH_SOCK - the executor resolves the agent socket itself).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from importlib import resources
from pathlib import Path
from typing import Any

from . import __version__
from .util import OpsError

EXTENSION_NAME = "opsbrain"
_PACKAGED = ("manifest.json", "server/index.js")
_PATH_DIRS = ("~/.local/bin", "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")


def binary_path() -> str:
    found = shutil.which("opsbrain") or str(Path(sys.argv[0]).resolve())
    if not Path(found).is_file():
        raise OpsError("cannot locate the `opsbrain` binary: install it with `uv tool install`")
    return str(Path(found).absolute())


def build(config_file: Path, output_dir: Path, *, binary: str | None = None) -> Path:
    source = resources.files("opsbrain").joinpath("extension")
    manifest: dict[str, Any] = json.loads(source.joinpath("manifest.json").read_text(encoding="utf-8"))
    manifest["version"] = __version__
    manifest["server"]["mcp_config"]["env"] = {
        "OPSBRAIN_BIN": binary or binary_path(),
        "OPSBRAIN_CONFIG": str(config_file.expanduser().absolute()),
        "PATH": os.pathsep.join(str(Path(directory).expanduser()) for directory in _PATH_DIRS),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle = output_dir / f"{EXTENSION_NAME}-{__version__}.mcpb"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        for relative in _PACKAGED[1:]:
            archive.writestr(relative, source.joinpath(relative).read_text(encoding="utf-8"))
    return bundle


def claude_data_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Claude"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "Claude"


def installed_extension(data_dir: Path | None = None) -> dict[str, Any] | None:
    """What Claude Desktop itself recorded about the extension (read-only)."""
    data_dir = data_dir or claude_data_dir()
    try:
        registry = json.loads((data_dir / "extensions-installations.json").read_text()).get("extensions", {})
    except (OSError, ValueError):
        return None
    for extension_id, record in registry.items():
        if (record.get("manifest") or {}).get("name") == EXTENSION_NAME:
            return {"id": extension_id, "version": record.get("version"), "installed_at": record.get("installedAt")}
    return None


def legacy_config_entry(data_dir: Path | None = None) -> bool:
    """True when claude_desktop_config.json also starts OpsBrain: two copies of every tool."""
    try:
        config = json.loads(((data_dir or claude_data_dir()) / "claude_desktop_config.json").read_text())
    except (OSError, ValueError):
        return False
    return any(name.lower() == EXTENSION_NAME for name in config.get("mcpServers", {}))


def open_with_desktop(bundle: Path) -> bool:
    argv = ["open", "-a", "Claude", str(bundle)] if sys.platform == "darwin" else ["xdg-open", str(bundle)]
    try:
        return subprocess.run(argv, capture_output=True, timeout=30, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
