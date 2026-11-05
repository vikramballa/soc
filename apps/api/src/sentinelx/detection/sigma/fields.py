"""Field mapping from the Sigma taxonomy to SentinelX canonical fields (processing pipeline).

Sigma rules are portable: they reference generic taxonomy fields (``Image``, ``CommandLine`` ...).
This mapping plays the role of a pySigma processing pipeline for the in-process evaluator.
Unknown fields fall back to canonical names, then ``metadata.<field>``, then ``raw_event`` dotted paths.
"""

from __future__ import annotations

from typing import Any

CANONICAL_FIELDS = {
    "timestamp",
    "source_type",
    "event_type",
    "event_action",
    "outcome",
    "severity",
    "hostname",
    "host_ip",
    "os",
    "username",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "protocol",
    "bytes_out",
    "bytes_in",
    "process_name",
    "process_path",
    "process_command_line",
    "parent_process_name",
    "parent_process_path",
    "domain",
    "url",
    "file_path",
    "file_hash",
    "event_category",
    "rule_id",
    "rule_name",
    "summary",
}

SIGMA_TO_CANONICAL: dict[str, str] = {
    # process_creation
    "Image": "process_path",
    "OriginalFileName": "process_name",
    "CommandLine": "process_command_line",
    "ParentImage": "parent_process_path",
    "User": "username",
    "Hashes": "file_hash",
    "ParentCommandLine": "metadata.parent_command_line",
    # process_access / create_remote_thread (Sysmon 10 / 8)
    "SourceImage": "process_path",
    "TargetImage": "metadata.target_image",
    "GrantedAccess": "metadata.granted_access",
    # registry (Sysmon 12-14)
    "TargetObject": "metadata.registry_key",
    "Details": "metadata.registry_value",
    # services / kerberos / directory service
    "ImagePath": "process_path",
    "ServiceName": "metadata.service_name",
    "TicketEncryptionType": "metadata.ticket_encryption",
    "PreAuthType": "metadata.pre_auth_type",
    "Properties": "metadata.properties",
    "AccessMask": "metadata.access_mask",
    "TaskName": "metadata.task_name",
    "ImageLoaded": "metadata.image_loaded",
    # authentication / windows security
    "TargetUserName": "username",
    "SubjectUserName": "username",
    "IpAddress": "src_ip",
    "WorkstationName": "hostname",
    "Computer": "hostname",
    "EventID": "metadata.windows_event_id",
    "LogonType": "metadata.logon_type",
    # network
    "SourceIp": "src_ip",
    "SourcePort": "src_port",
    "DestinationIp": "dest_ip",
    "DestinationPort": "dest_port",
    "DestinationHostname": "domain",
    "Protocol": "protocol",
    "Initiated": "metadata.initiated",
    # dns
    "QueryName": "domain",
    "query": "domain",
    "QueryType": "metadata.qtype",
    "qtype_name": "metadata.qtype",
    # file
    "TargetFilename": "file_path",
    # zeek-style
    "id.orig_h": "src_ip",
    "id.resp_h": "dest_ip",
    "id.resp_p": "dest_port",
    "conn_state": "metadata.conn_state",
    # web / proxy
    "c-uri": "url",
    "cs-host": "domain",
    "cs-method": "metadata.method",
    "c-useragent": "metadata.user_agent",
    "cs-user-agent": "metadata.user_agent",
    "user_agent": "metadata.user_agent",
    "ja3": "metadata.ja3",
    "ja4": "metadata.ja4",
}

# Entity fields recorded with every rule match so correlation rules can group / count on them.
MATCH_FIELDS = (
    "hostname",
    "username",
    "src_ip",
    "dest_ip",
    "dest_port",
    "domain",
    "process_name",
    "file_path",
    "file_hash",
    "protocol",
)


def resolve_field(name: str) -> str:
    if name in CANONICAL_FIELDS:
        return name
    return SIGMA_TO_CANONICAL.get(name, name)


def get_value(event: dict[str, Any], field: str) -> Any:
    """Look up a resolved field in a flattened event dict.

    Last resort for Windows telemetry shipped by Wazuh: the original Event Log field under
    ``data.win.eventdata`` (Wazuh lower-camel-cases names: ``ScriptBlockText`` -> ``scriptBlockText``),
    so portable SigmaHQ rules work without a mapping entry for every field."""
    if field in event:
        return event[field]
    if field.startswith("metadata."):
        return _dig(event.get("metadata") or {}, field[9:])
    meta = event.get("metadata") or {}
    if field in meta:
        return meta[field]
    raw = event.get("raw_event") or {}
    found = _dig(raw, field)
    if found is None and field[:1].isupper() and "." not in field:
        ed = ((raw.get("data") or {}).get("win") or {}).get("eventdata") if isinstance(raw, dict) else None
        if isinstance(ed, dict):
            found = ed.get(field[0].lower() + field[1:])
    return found


def _dig(obj: Any, dotted: str) -> Any:
    if isinstance(obj, dict) and dotted in obj:
        return obj[dotted]
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur
