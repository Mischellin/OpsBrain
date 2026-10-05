import asyncio
import json

from opsbrain.server import build_server

EXPECTED = {"overview", "docs", "hosts", "tofu", "ansible", "k8s", "network", "drift", "observe", "artifact", "job",
            "change"}


def test_tool_surface_is_small_and_has_no_shell_or_approve(ops) -> None:  # type: ignore[no-untyped-def]
    tools = asyncio.run(build_server(ops).list_tools())
    assert {tool.name for tool in tools} == EXPECTED
    schema_size = sum(len(json.dumps(tool.input_schema)) + len(tool.description or "") for tool in tools)
    assert schema_size < 9000, schema_size  # the schemas are paid for in every conversation
