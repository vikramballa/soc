"""Suricata EVE JSON -> canonical events.

Reference: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
Supported event types: alert, dns (v2 + v3), http, tls, flow, fileinfo, ssh, anomaly.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sentinelx.domain.events import CanonicalEvent, deterministic_event_id, parse_timestamp, summarize

# Suricata alert.severity: 1 = high, 3 = low (inverted). Map onto SentinelX 0-100.
_ALERT_SEVERITY = {1: 80, 2: 55, 3: 30, 4: 15}

SUPPORTED = {"alert", "dns", "http", "tls", "flow", "fileinfo", "ssh", "anomaly", "netflow"}


class ParseError(ValueError):
    pass


def _native_key(rec: dict[str, Any]) -> str:
    # flow_id + event_type + timestamp identify a record; tx_id/signature disambiguate multi-alerts
    parts = [
        str(rec.get("flow_id", "")),
        str(rec.get("event_type", "")),
        str(rec.get("timestamp", "")),
        str(rec.get("tx_id", "")),
        str((rec.get("alert") or {}).get("signature_id", "")),
        str((rec.get("dns") or {}).get("id", "")),
    ]
    if not rec.get("flow_id"):
        parts.append(hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest())
    return "|".join(parts)


def _dns_query(dns: dict[str, Any]) -> tuple[str | None, str | None]:
    # v3: dns.queries[] ; v2: dns.rrname
    queries = dns.get("queries")
    if isinstance(queries, list) and queries:
        return queries[0].get("rrname"), queries[0].get("rrtype")
    return dns.get("rrname"), dns.get("rrtype")


def parse(rec: dict[str, Any], tenant_id: uuid.UUID) -> CanonicalEvent:
    et = rec.get("event_type")
    if et not in SUPPORTED:
        raise ParseError(f"unsupported suricata event_type: {et!r}")
    if "timestamp" not in rec:
        raise ParseError("missing timestamp")

    base: dict[str, Any] = {
        "event_id": deterministic_event_id(tenant_id, "suricata", _native_key(rec)),
        "tenant_id": tenant_id,
        "timestamp": parse_timestamp(rec["timestamp"]),
        "source_type": "suricata",
        "src_ip": rec.get("src_ip"),
        "src_port": rec.get("src_port"),
        "dest_ip": rec.get("dest_ip"),
        "dest_port": rec.get("dest_port"),
        "protocol": (rec.get("app_proto") or rec.get("proto") or None),
        "hostname": rec.get("host") if isinstance(rec.get("host"), str) else None,
        "raw_event": rec,
        "metadata": {"flow_id": rec.get("flow_id"), "suricata_event_type": et, "in_iface": rec.get("in_iface")},
    }

    if et == "alert":
        a = rec.get("alert") or {}
        meta = a.get("metadata") or {}
        techniques = [t for t in meta.get("mitre_technique_id", []) if isinstance(t, str)]
        base.update(
            event_type="alert",
            event_action="ids_alert",
            severity=_ALERT_SEVERITY.get(int(a.get("severity", 3) or 3), 30),
            rule_id=str(a.get("signature_id")) if a.get("signature_id") is not None else None,
            rule_name=a.get("signature"),
            event_category=a.get("category"),
            mitre_techniques=techniques,
        )
        base["metadata"]["action"] = a.get("action")
        if rec.get("http", {}).get("hostname"):
            base["domain"] = rec["http"]["hostname"]
        elif rec.get("dns"):
            base["domain"] = _dns_query(rec["dns"])[0]
    elif et == "dns":
        dns = rec.get("dns") or {}
        q, qtype = _dns_query(dns)
        base.update(event_type="dns", event_action=f"dns_{dns.get('type', 'query')}", domain=q)
        base["metadata"].update(qtype=qtype, rcode=dns.get("rcode"))
        if dns.get("answers"):
            base["metadata"]["answers"] = [x.get("rdata") for x in dns["answers"][:10] if isinstance(x, dict)]
    elif et == "http":
        h = rec.get("http") or {}
        base.update(event_type="http", event_action="http_request", domain=h.get("hostname"), url=h.get("url"))
        base["metadata"].update(
            method=h.get("http_method"), status=h.get("status"), user_agent=h.get("http_user_agent")
        )
    elif et == "tls":
        t = rec.get("tls") or {}
        base.update(event_type="tls", event_action="tls_handshake", domain=t.get("sni"))
        base["metadata"].update(
            subject=t.get("subject"),
            issuer=t.get("issuerdn"),
            version=t.get("version"),
            ja3=(t.get("ja3") or {}).get("hash"),
        )
    elif et in ("flow", "netflow"):
        f = rec.get("flow") or rec.get("netflow") or {}
        unanswered = f.get("pkts_toclient") == 0 or (f.get("state") == "new" and not f.get("bytes_toclient"))
        base.update(
            event_type="network",
            event_action="connection_attempt" if unanswered else "connection",
            outcome="failure" if unanswered else "success",
            bytes_out=f.get("bytes_toserver"),
            bytes_in=f.get("bytes_toclient"),
        )
        base["metadata"].update(
            state=f.get("state"),
            reason=f.get("reason"),
            pkts_toserver=f.get("pkts_toserver"),
            pkts_toclient=f.get("pkts_toclient"),
        )
    elif et == "fileinfo":
        fi = rec.get("fileinfo") or {}
        base.update(
            event_type="file",
            event_action="file_transfer",
            file_path=fi.get("filename"),
            file_hash=fi.get("sha256") or fi.get("sha1") or fi.get("md5"),
        )
        base["metadata"].update(size=fi.get("size"), magic=fi.get("magic"))
        if rec.get("http", {}).get("hostname"):
            base["domain"] = rec["http"]["hostname"]
    elif et == "ssh":
        s = rec.get("ssh") or {}
        base.update(event_type="ssh", event_action="ssh_session")
        base["metadata"].update(
            client=(s.get("client") or {}).get("software_version"),
            server=(s.get("server") or {}).get("software_version"),
        )
    elif et == "anomaly":
        an = rec.get("anomaly") or {}
        base.update(event_type="other", event_action="protocol_anomaly", event_category=an.get("event"))

    ev = CanonicalEvent(**base)
    ev.summary = summarize(ev)
    return ev
