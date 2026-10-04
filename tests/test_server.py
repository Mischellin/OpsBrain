import asyncio
import json

from opsbrain.server import AUTONOMOUS_FLOW, build_server

EXPECTED = {"overview", "docs", "hosts", "tofu", "ansible", "k8s", "network", "drift", "observe", "artifact", "job",
            "change", "autonomy"}


def test_tool_surface_is_small_and_has_no_shell_or_approve(ops) -> None:  # type: ignore[no-untyped-def]
    tools = asyncio.run(build_server(ops).list_tools())
    assert {tool.name for tool in tools} == EXPECTED
    schema_size = sum(len(json.dumps(tool.input_schema)) + len(tool.description or "") for tool in tools)
    assert schema_size < 9000, schema_size  # the schemas are paid for in every conversation


def test_every_advertised_step_is_named_in_the_description_that_carries_it(ops) -> None:  # type: ignore[no-untyped-def]
    """A flow a client is told about, in a description that does not name it, is not advertised.

    The description is the only place a client learns the order. The steps were listed once as a literal
    `AUTONOMOUS_FLOW in order:` - the name of the tuple, not its contents - and the surface test still
    passed, because a description can be wrong and still be short. Naming the tuple's members here is
    what makes adding a step fail loudly instead of silently omitting it from the docs.
    """
    tools = asyncio.run(build_server(ops).list_tools())
    autonomy = next(tool for tool in tools if tool.name == "autonomy")
    description = autonomy.description or ""
    chain = " -> ".join(AUTONOMOUS_FLOW)
    assert chain in description, f"the flow is not spelled out in order: {description}"
    assert "AUTONOMOUS_FLOW" not in description, (
        "the description quotes the tuple's name instead of its contents, so it documents nothing")


def test_a_docstring_that_is_not_a_plain_string_still_reaches_the_client(ops) -> None:  # type: ignore[no-untyped-def]
    """An f-string docstring is not a docstring to the decorator, and the tool silently loses it.

    The tool descriptions are extracted from the source AST, which recognises only a plain string literal.
    Turning the `autonomy` docstring into an f-string - to interpolate `AUTONOMOUS_FLOW` instead of
    repeating it - therefore emptied the description and nothing failed: the tool stayed in the list with
    an empty description, and a client asking `autonomy action=capabilities` got no usage at all. The
    surface test passed throughout, because a missing description is smaller than a present one.
    """
    tools = asyncio.run(build_server(ops).list_tools())
    for tool in tools:
        assert (tool.description or "").strip(), f"tool {tool.name} reaches the client with no description"
