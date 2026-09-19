import json
import zipfile

from opsbrain import __version__, desktop


def test_bundle_bakes_in_binary_config_and_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    bundle = desktop.build(tmp_path / "config.yaml", tmp_path / "dist", binary="/opt/bin/opsbrain")
    assert bundle.name == f"opsbrain-{__version__}.mcpb"
    with zipfile.ZipFile(bundle) as archive:
        assert sorted(archive.namelist()) == ["manifest.json", "server/index.js"]
        manifest = json.loads(archive.read("manifest.json"))
        launcher = archive.read("server/index.js").decode()
    env = manifest["server"]["mcp_config"]["env"]
    assert manifest["version"] == __version__ and manifest["name"] == "opsbrain"
    assert env["OPSBRAIN_BIN"] == "/opt/bin/opsbrain" and env["OPSBRAIN_CONFIG"].endswith("config.yaml")
    assert "/usr/bin" in env["PATH"].split(":")
    assert set(env) == {"OPSBRAIN_BIN", "OPSBRAIN_CONFIG", "PATH"}  # nothing secret is ever baked in
    assert 'stdio: "inherit"' in launcher


def test_detects_installed_extension_and_duplicate_config_entry(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert desktop.installed_extension(tmp_path) is None and not desktop.legacy_config_entry(tmp_path)
    (tmp_path / "extensions-installations.json").write_text(json.dumps({"extensions": {
        "local.mcpb.opsbrain": {"version": "0.1.0", "installedAt": "now", "manifest": {"name": "opsbrain"}}}}))
    (tmp_path / "claude_desktop_config.json").write_text(json.dumps({"mcpServers": {"OpsBrain": {}}}))
    assert desktop.installed_extension(tmp_path)["id"] == "local.mcpb.opsbrain"  # type: ignore[index]
    assert desktop.legacy_config_entry(tmp_path)
