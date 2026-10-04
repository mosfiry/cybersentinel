from pathlib import Path

from tools.registry import MAX_ARG_LENGTH, REGISTRY


def test_tool_model_documents_every_canonical_registry_tool() -> None:
    document = Path("docs/TOOL_MODEL.md").read_text(encoding="utf-8")

    assert f"contains {len(REGISTRY)} tools" in document
    assert all(f"`{name}`" in document for name in REGISTRY)


def test_tool_model_argument_counts_and_bounds_match_registry() -> None:
    document = Path("docs/TOOL_MODEL.md").read_text(encoding="utf-8")
    argument_tools = [name for name, spec in REGISTRY.items() if spec.argument_type is str]
    no_argument_tools = [name for name, spec in REGISTRY.items() if spec.argument_type is None]
    number_words = {0: "zero", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}

    assert f"The {number_words[len(argument_tools)]} current string-input tools are" in document
    assert all(f"`{name}`" in document for name in argument_tools)
    assert f"maximum argument length of {MAX_ARG_LENGTH} characters" in document
    assert f"The other {number_words[len(no_argument_tools)]} tools accept no arguments." in document
    assert "metadata-only placeholder and does not issue a network request" in document
