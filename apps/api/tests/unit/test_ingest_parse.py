from __future__ import annotations

from sentinelx.api.routes.ingest import parse_body


def test_single_line_json_object() -> None:
    assert parse_body(b'{"a": 1}', "wazuh") == [{"a": 1}]


def test_pretty_printed_json_object() -> None:
    body = b'{\n  "a": 1,\n  "b": 2\n}\n'
    assert parse_body(body, "wazuh") == [{"a": 1, "b": 2}]


def test_json_array() -> None:
    assert parse_body(b'[{"a": 1}, {"a": 2}]', "wazuh") == [{"a": 1}, {"a": 2}]


def test_ndjson_lines() -> None:
    body = b'{"a": 1}\n{"a": 2}\n'
    assert parse_body(body, "wazuh") == [{"a": 1}, {"a": 2}]


def test_ndjson_bad_line_is_quarantined_not_fatal() -> None:
    body = b'{"a": 1}\nnot json\n'
    out = parse_body(body, "wazuh")
    assert out[0] == {"a": 1}
    assert out[1]["__unparseable_line__"] == 2
