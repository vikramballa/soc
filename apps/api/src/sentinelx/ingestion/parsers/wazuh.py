"""Wazuh alerts (``alerts.json`` / ``wazuh-alerts-*`` index documents) -> canonical events.

Wazuh preserves the original decoded fields under ``data``; Windows events under ``data.win``,
Sysmon fields under ``data.win.eventdata``, FIM under ``syscheck``.
Reference: https://documentation.wazuh.com/current/user-manual/ruleset/
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sentinelx.domain.events import (
    CanonicalEvent,
    basename,
    deterministic_event_id,
    parse_timestamp,
    summarize,
)


class ParseError(ValueError):
    pass


_AUTH_FAIL_GROUPS = {"authentication_failed", "authentication_failures", "win_authentication_failed", "invalid_login"}
_AUTH_OK_GROUPS = {"authentication_success"}
_ADMIN_GROUP_HINTS = ("admin", "sudo", "wheel", "domain admins", "enterprise admins")


_SYSMON_REGISTRY = {"12": "registry_key_change", "13": "registry_set", "14": "registry_rename"}


def _strip_realm(user: Any) -> Any:
    if isinstance(user, str) and "@" in user:
        return user.split("@", 1)[0]
    return user


def _windows_specific(event_id: str, sysmon: bool, ed: dict[str, Any], base: dict[str, Any]) -> bool:
    """Windows/Sysmon events that need their own mapping. Returns True when ``base`` was filled in."""
    meta = base["metadata"]
    if event_id in ("4768", "4769") and not sysmon:
        status = str(ed.get("status") or "0x0").lower()
        base.update(
            event_type="authentication",
            event_action="kerberos_tgt" if event_id == "4768" else "kerberos_service_ticket",
            outcome="success" if status in ("0x0", "0") else "failure",
            username=_strip_realm(_first(ed.get("targetUserName"), base.get("username"))),
            src_ip=(ed.get("ipAddress") or "").replace("::ffff:", "") or base.get("src_ip"),
        )
        meta.update(
            service_name=ed.get("serviceName"),
            ticket_encryption=ed.get("ticketEncryptionType"),
            ticket_options=ed.get("ticketOptions"),
            pre_auth_type=ed.get("preAuthType"),
            logon_type="3",
        )
        return True
    if event_id == "4662" and not sysmon:
        base.update(event_type="other", event_action="directory_object_access", username=ed.get("subjectUserName"))
        meta.update(properties=ed.get("properties"), access_mask=ed.get("accessMask"), object_type=ed.get("objectType"))
        return True
    if event_id == "7045" and not sysmon:
        image = ed.get("imagePath")
        base.update(event_type="other", event_action="service_installed", process_path=image)
        base["process_name"] = basename(
            image.split('"')[1] if isinstance(image, str) and image.startswith('"') else image
        )
        meta.update(service_name=ed.get("serviceName"), service_account=ed.get("accountName"))
        return True
    if event_id == "4698" and not sysmon:
        base.update(event_type="other", event_action="scheduled_task_created", username=ed.get("subjectUserName"))
        meta.update(task_name=ed.get("taskName"))
        return True
    if event_id == "4104" and not sysmon:
        base.update(event_type="process", event_action="powershell_script", process_name="powershell.exe")
        meta.update(script_block_id=ed.get("scriptBlockId"))
        return True
    if not sysmon:
        return False
    if event_id == "10":
        src = ed.get("sourceImage")
        base.update(event_type="process", event_action="process_access", process_path=src, process_name=basename(src))
        meta.update(target_image=ed.get("targetImage"), granted_access=ed.get("grantedAccess"))
        return True
    if event_id == "8":
        src = ed.get("sourceImage")
        base.update(
            event_type="process", event_action="create_remote_thread", process_path=src, process_name=basename(src)
        )
        meta.update(target_image=ed.get("targetImage"))
        return True
    if event_id == "11":
        image = ed.get("image")
        base.update(
            event_type="file",
            event_action="file_created",
            file_path=ed.get("targetFilename"),
            process_path=image,
            process_name=basename(image),
        )
        return True
    if event_id in _SYSMON_REGISTRY:
        image = ed.get("image")
        base.update(
            event_type="registry",
            event_action=_SYSMON_REGISTRY[event_id],
            process_path=image,
            process_name=basename(image),
        )
        meta.update(registry_key=ed.get("targetObject"), registry_value=ed.get("details"))
        return True
    if event_id == "7":
        image = ed.get("image")
        base.update(event_type="other", event_action="image_load", process_path=image, process_name=basename(image))
        meta.update(image_loaded=ed.get("imageLoaded"))
        return True
    return False


def _level_to_severity(level: int) -> int:
    # Wazuh levels 0..15 -> 0..100
    return max(0, min(100, round(level * 100 / 15)))


def _hash_from_sysmon(hashes: str | None) -> str | None:
    if not hashes:
        return None
    parts = dict(p.split("=", 1) for p in hashes.split(",") if "=" in p)
    for k in ("SHA256", "SHA1", "MD5"):
        if k in parts:
            return parts[k]
    return None


def _first(*vals: Any) -> Any:
    for v in vals:
        if v not in (None, "", "-"):
            return v
    return None


def parse(rec: dict[str, Any], tenant_id: uuid.UUID) -> CanonicalEvent:
    rule = rec.get("rule") or {}
    if not rule or "timestamp" not in rec:
        raise ParseError("not a wazuh alert: missing rule/timestamp")
    agent = rec.get("agent") or {}
    data = rec.get("data") or {}
    win = data.get("win") or {}
    ed = win.get("eventdata") or {}
    sysd = win.get("system") or {}
    groups = set(rule.get("groups") or [])
    level = int(rule.get("level", 0) or 0)
    event_id_win = str(sysd.get("eventID") or "")

    native = rec.get("id") or hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
    mitre = (rule.get("mitre") or {}).get("id") or []

    base: dict[str, Any] = {
        "event_id": deterministic_event_id(tenant_id, "wazuh", f"{native}|{rule.get('id')}"),
        "tenant_id": tenant_id,
        "timestamp": parse_timestamp(rec["timestamp"]),
        "source_type": "wazuh",
        "severity": _level_to_severity(level),
        "hostname": agent.get("name") if agent.get("id") != "000" or agent.get("name") else None,
        "host_ip": agent.get("ip"),
        "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
        "rule_name": rule.get("description"),
        "event_category": ",".join(sorted(groups))[:120] or None,
        "mitre_techniques": [m for m in mitre if isinstance(m, str)],
        "raw_event": rec,
        "metadata": {
            "wazuh_level": level,
            "agent_id": agent.get("id"),
            "decoder": (rec.get("decoder") or {}).get("name"),
            "location": rec.get("location"),
            "groups": sorted(groups),
            "windows_event_id": event_id_win or None,
        },
    }
    if "windows" in groups or win:
        base["os"] = "windows"
    elif {"syslog", "sshd", "pam", "sudo"} & groups:
        base["os"] = "linux"

    base["src_ip"] = _first(data.get("srcip"), ed.get("ipAddress"), ed.get("sourceIp"))
    base["src_port"] = int(_first(data.get("srcport"), ed.get("ipPort"), ed.get("sourcePort")) or 0) or None
    user = _first(
        data.get("dstuser"), data.get("srcuser"), ed.get("targetUserName"), ed.get("user"), ed.get("subjectUserName")
    )
    if isinstance(user, str) and "\\" in user:
        user = user.split("\\", 1)[1]
    base["username"] = user

    sysmon = "sysmon" in str(sysd.get("channel") or "").lower() or "sysmon" in groups
    if event_id_win and _windows_specific(event_id_win, sysmon, ed, base):
        pass
    elif groups & _AUTH_FAIL_GROUPS or event_id_win == "4625":
        base.update(event_type="authentication", event_action="logon", outcome="failure")
    elif groups & _AUTH_OK_GROUPS or event_id_win == "4624":
        base.update(event_type="authentication", event_action="logon", outcome="success")
        base["metadata"]["logon_type"] = ed.get("logonType")
    elif event_id_win == "4720" or "adduser" in groups:
        target = _first(ed.get("targetUserName"), data.get("dstuser"), data.get("user"))
        base.update(event_type="iam", event_action="user_created", outcome="success")
        base["metadata"]["target_user"] = target
    elif event_id_win in ("4728", "4732", "4756") or "group_changed" in groups or "usermod" in groups:
        group = _first(ed.get("targetUserName") if event_id_win else None, data.get("group"))
        member = _first(ed.get("memberName"), data.get("dstuser"), data.get("user"))
        base.update(event_type="iam", event_action="group_member_added", outcome="success")
        base["metadata"].update(
            group=group,
            target_user=member,
            privileged_group=bool(group and any(h in str(group).lower() for h in _ADMIN_GROUP_HINTS)),
        )
    elif event_id_win == "3":  # Sysmon network connection
        base.update(
            event_type="network",
            event_action="connection",
            dest_ip=ed.get("destinationIp"),
            dest_port=int(ed.get("destinationPort") or 0) or None,
            protocol=ed.get("protocol"),
            process_path=ed.get("image"),
            process_name=basename(ed.get("image")),
        )
    elif event_id_win == "22":  # Sysmon DNS query
        base.update(
            event_type="dns",
            event_action="dns_query",
            domain=ed.get("queryName"),
            process_path=ed.get("image"),
            process_name=basename(ed.get("image")),
        )
    elif event_id_win in ("1", "4688") or ed.get("commandLine") or ed.get("image"):
        image = _first(ed.get("image"), ed.get("newProcessName"))
        parent = _first(ed.get("parentImage"), ed.get("parentProcessName"))
        base.update(
            event_type="process",
            event_action="process_start",
            process_path=image,
            process_name=basename(image),
            process_command_line=ed.get("commandLine"),
            parent_process_path=parent,
            parent_process_name=basename(parent),
            file_hash=_hash_from_sysmon(ed.get("hashes")),
        )
    elif "sudo" in groups:
        cmd = data.get("command")
        base.update(
            event_type="process",
            event_action="sudo",
            process_command_line=cmd,
            process_name=basename(cmd.split()[0]) if isinstance(cmd, str) and cmd.split() else None,
            outcome="success",
        )
        base["metadata"]["sudo_target_user"] = data.get("dstuser")
        base["username"] = data.get("srcuser") or base["username"]
    elif rec.get("syscheck"):
        sc = rec["syscheck"]
        base.update(
            event_type="file",
            event_action=sc.get("event") or "modified",
            file_path=sc.get("path"),
            file_hash=sc.get("sha256_after") or sc.get("sha1_after") or sc.get("md5_after"),
        )
        base["username"] = base["username"] or (sc.get("uname_after") if sc.get("uname_after") != "root" else None)
    elif event_id_win in ("1102", "104"):
        base.update(event_type="other", event_action="log_cleared")
    else:
        base.update(event_type="alert", event_action="wazuh_alert")

    if data.get("dstip") and not base.get("dest_ip"):
        base["dest_ip"] = data.get("dstip")

    ev = CanonicalEvent(**base)
    ev.summary = summarize(ev)
    return ev
