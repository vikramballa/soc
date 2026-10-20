"""Zeek logs -> canonical events.

Supports JSON (preferred, ``LogAscii::use_json=T``) and the default TSV format with ``#fields`` headers.
Logs: conn, dns, http, ssl, ssh, files, notice.
Reference: https://docs.zeek.org/en/current/logs/index.html
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

from sentinelx.domain.events import CanonicalEvent, deterministic_event_id, parse_timestamp, summarize

SUPPORTED = {"conn", "dns", "http", "ssl", "ssh", "files", "notice"}

# conn_state values that indicate a failed / rejected / scan-like connection attempt
FAILED_CONN_STATES = {"REJ", "S0", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}


class ParseError(ValueError):
    pass


def _g(rec: dict[str, Any], key: str) -> Any:
    """Zeek JSON uses dotted keys (``id.orig_h``); some shippers nest them. Support both."""
    if key in rec:
        v = rec[key]
    else:
        v = rec
        for part in key.split("."):
            if not isinstance(v, dict) or part not in v:
                return None
            v = v[part]
    if v in ("-", "(empty)"):
        return None
    return v


def _int(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def log_type_from_filename(name: str) -> str | None:
    stem = name.rsplit("/", 1)[-1].split(".", 1)[0]
    return stem if stem in SUPPORTED else None


def parse(rec: dict[str, Any], tenant_id: uuid.UUID, log_type: str | None = None) -> CanonicalEvent:
    lt = log_type or rec.get("_path")
    if lt not in SUPPORTED:
        raise ParseError(f"unsupported zeek log type: {lt!r}")
    if _g(rec, "ts") is None:
        raise ParseError("missing ts")
    uid = _g(rec, "uid") or _g(rec, "fuid") or ""
    native = f"{lt}|{uid}|{_g(rec, 'ts')}|{_g(rec, 'query') or _g(rec, 'note') or _g(rec, 'uri') or ''}"
    base: dict[str, Any] = {
        "event_id": deterministic_event_id(tenant_id, "zeek", native),
        "tenant_id": tenant_id,
        "timestamp": parse_timestamp(_g(rec, "ts")),
        "source_type": "zeek",
        "src_ip": _g(rec, "id.orig_h"),
        "src_port": _int(_g(rec, "id.orig_p")),
        "dest_ip": _g(rec, "id.resp_h"),
        "dest_port": _int(_g(rec, "id.resp_p")),
        "raw_event": rec,
        "metadata": {"zeek_log": lt, "uid": uid or None},
    }

    if lt == "conn":
        state = _g(rec, "conn_state")
        base.update(
            event_type="network",
            event_action="connection_attempt" if state in FAILED_CONN_STATES else "connection",
            outcome="failure" if state in FAILED_CONN_STATES else "success",
            protocol=_g(rec, "service") or _g(rec, "proto"),
            bytes_out=_int(_g(rec, "orig_bytes")),
            bytes_in=_int(_g(rec, "resp_bytes")),
        )
        base["metadata"].update(
            conn_state=state, duration=_g(rec, "duration"), transport=_g(rec, "proto"), history=_g(rec, "history")
        )
    elif lt == "dns":
        base.update(event_type="dns", event_action="dns_query", domain=_g(rec, "query"), protocol="dns")
        base["metadata"].update(
            qtype=_g(rec, "qtype_name"), rcode=_g(rec, "rcode_name"), answers=(_g(rec, "answers") or [])[:10]
        )
    elif lt == "http":
        base.update(
            event_type="http", event_action="http_request", domain=_g(rec, "host"), url=_g(rec, "uri"), protocol="http"
        )
        base["metadata"].update(
            method=_g(rec, "method"), status=_g(rec, "status_code"), user_agent=_g(rec, "user_agent")
        )
    elif lt == "ssl":
        base.update(event_type="tls", event_action="tls_handshake", domain=_g(rec, "server_name"), protocol="tls")
        base["metadata"].update(version=_g(rec, "version"), established=_g(rec, "established"), ja3=_g(rec, "ja3"))
    elif lt == "ssh":
        success = _g(rec, "auth_success")
        base.update(
            event_type="ssh",
            event_action="logon",
            protocol="ssh",
            outcome="success"
            if success is True or success == "T"
            else ("failure" if success is False or success == "F" else "unknown"),
        )
        base["metadata"].update(
            auth_attempts=_int(_g(rec, "auth_attempts")), client=_g(rec, "client"), direction=_g(rec, "direction")
        )
    elif lt == "files":
        src = _g(rec, "tx_hosts")
        dst = _g(rec, "rx_hosts")
        base.update(
            event_type="file",
            event_action="file_transfer",
            file_path=_g(rec, "filename"),
            file_hash=_g(rec, "sha256") or _g(rec, "sha1") or _g(rec, "md5"),
        )
        if not base["src_ip"] and isinstance(src, list) and src:
            base["src_ip"] = src[0]
        if not base["dest_ip"] and isinstance(dst, list) and dst:
            base["dest_ip"] = dst[0]
        base["metadata"].update(mime_type=_g(rec, "mime_type"), size=_g(rec, "total_bytes"))
    elif lt == "notice":
        note = _g(rec, "note")
        base.update(
            event_type="alert",
            event_action="zeek_notice",
            severity=50,
            rule_id=note,
            rule_name=_g(rec, "msg") or note,
            event_category=note,
            src_ip=base["src_ip"] or _g(rec, "src"),
            dest_ip=base["dest_ip"] or _g(rec, "dst"),
            dest_port=base["dest_port"] or _int(_g(rec, "p")),
        )
        base["metadata"].update(sub=_g(rec, "sub"))

    ev = CanonicalEvent(**base)
    ev.summary = summarize(ev)
    return ev


def iter_tsv(lines: Iterator[str]) -> Iterator[dict[str, Any]]:
    """Parse Zeek's default ASCII/TSV log format into dicts using the ``#fields`` header."""
    fields: list[str] = []
    sep = "\t"
    set_sep = ","
    for line in lines:
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("#separator"):
            raw = line.split(" ", 1)[1].strip()
            sep = raw.encode().decode("unicode_escape") if raw.startswith("\\x") else raw
            continue
        if line.startswith("#set_separator"):
            set_sep = line.split(sep, 1)[1]
            continue
        if line.startswith("#fields"):
            fields = line.split(sep)[1:]
            continue
        if line.startswith("#"):
            continue
        if not fields:
            raise ParseError("TSV record before #fields header")
        values = line.split(sep)
        rec: dict[str, Any] = {}
        for k, v in zip(fields, values, strict=False):
            if v in ("-", "(empty)"):
                continue
            if k in ("answers", "tx_hosts", "rx_hosts"):
                rec[k] = v.split(set_sep)
            elif k == "auth_success":
                rec[k] = v == "T"
            else:
                rec[k] = v
        yield rec
