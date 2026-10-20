"""Feature extraction (SQL), training, scoring and ML alerts."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import numpy as np
from sqlalchemy import and_, func, or_, select, text, true, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.correlation.engine import correlate
from sentinelx.detection.alerts import AlertSpec, upsert_alert
from sentinelx.logging import get_logger
from sentinelx.metrics import ML_INFERENCE_DURATION
from sentinelx.ml.model import MODEL_NAME, MODEL_VERSION_TAG, TrainedModel, explain, score, train
from sentinelx.persistence.models import MlModel, MlPrediction, SecurityEvent

log = get_logger(__name__)

ML_RULE = "sx-ml-host-anomaly"
ANOMALY_THRESHOLD = 0.8
MIN_TOP_Z = 4.0

FEATURES = [
    "events",
    "auth_failures",
    "auth_successes",
    "distinct_users",
    "processes",
    "distinct_processes",
    "powershell",
    "dns_queries",
    "distinct_domains",
    "connections",
    "distinct_dest_ips",
    "distinct_dest_ports",
    "rare_port_connections",
    "bytes_out",
    "file_changes",
]

FEATURE_LABELS = {
    "events": "total events",
    "auth_failures": "failed logins",
    "auth_successes": "successful logins",
    "distinct_users": "distinct users",
    "processes": "process starts",
    "distinct_processes": "distinct programs",
    "powershell": "PowerShell starts",
    "dns_queries": "DNS queries",
    "distinct_domains": "distinct domains",
    "connections": "network connections",
    "distinct_dest_ips": "distinct destinations",
    "distinct_dest_ports": "distinct destination ports",
    "rare_port_connections": "connections on unusual ports",
    "bytes_out": "bytes sent",
    "file_changes": "file changes",
}

_RARE_PORT_OK = (20, 21, 22, 25, 53, 80, 110, 123, 143, 389, 443, 445, 465, 587, 636, 993, 995, 3389, 8080)
_AUTH = SecurityEvent.event_type.in_(["authentication", "ssh"])
FEATURE_EVENTS = {
    "auth_failures": and_(_AUTH, SecurityEvent.outcome == "failure"),
    "auth_successes": and_(_AUTH, SecurityEvent.outcome == "success"),
    "processes": SecurityEvent.event_type == "process",
    "distinct_processes": SecurityEvent.event_type == "process",
    "powershell": func.lower(SecurityEvent.process_name).in_(["powershell.exe", "pwsh.exe", "pwsh"]),
    "dns_queries": SecurityEvent.event_type == "dns",
    "distinct_domains": SecurityEvent.event_type == "dns",
    "connections": SecurityEvent.event_type == "network",
    "distinct_dest_ips": SecurityEvent.event_type == "network",
    "distinct_dest_ports": SecurityEvent.event_type == "network",
    "rare_port_connections": and_(SecurityEvent.event_type == "network", SecurityEvent.dest_port.notin_(_RARE_PORT_OK)),
    "bytes_out": and_(SecurityEvent.event_type == "network", SecurityEvent.bytes_out > 100_000),
    "file_changes": SecurityEvent.event_type == "file",
}

_FEATURE_SQL = text(
    """
    SELECT hostname, date_trunc('hour', timestamp) AS hour,
      count(*) AS events,
      count(*) FILTER (WHERE event_type IN ('authentication','ssh') AND outcome = 'failure') AS auth_failures,
      count(*) FILTER (WHERE event_type IN ('authentication','ssh') AND outcome = 'success') AS auth_successes,
      count(DISTINCT username) AS distinct_users,
      count(*) FILTER (WHERE event_type = 'process') AS processes,
      count(DISTINCT lower(process_name)) FILTER (WHERE event_type = 'process') AS distinct_processes,
      count(*) FILTER (WHERE event_type = 'process' AND lower(process_name) IN ('powershell.exe','pwsh.exe','pwsh'))
        AS powershell,
      count(*) FILTER (WHERE event_type = 'dns') AS dns_queries,
      count(DISTINCT domain) FILTER (WHERE event_type = 'dns') AS distinct_domains,
      count(*) FILTER (WHERE event_type = 'network') AS connections,
      count(DISTINCT dest_ip) FILTER (WHERE event_type = 'network') AS distinct_dest_ips,
      count(DISTINCT dest_port) FILTER (WHERE event_type = 'network') AS distinct_dest_ports,
      count(*) FILTER (WHERE event_type = 'network' AND dest_port IS NOT NULL
                       AND dest_port NOT IN (20,21,22,25,53,80,110,123,143,389,443,445,465,587,636,993,995,3389,8080))
        AS rare_port_connections,
      coalesce(sum(bytes_out) FILTER (WHERE event_type = 'network'), 0) AS bytes_out,
      count(*) FILTER (WHERE event_type = 'file') AS file_changes
    FROM security_events
    WHERE tenant_id = :t AND hostname IS NOT NULL AND timestamp >= :start AND timestamp < :end
    GROUP BY hostname, hour
    ORDER BY hour
    """
)


async def extract_features(
    session: AsyncSession, tenant_id: uuid.UUID, start: datetime, end: datetime
) -> list[tuple[str, datetime, np.ndarray]]:
    rows = (await session.execute(_FEATURE_SQL, {"t": tenant_id, "start": start, "end": end})).mappings().all()
    return [(r["hostname"], r["hour"], np.array([float(r[f] or 0) for f in FEATURES])) for r in rows]


async def _incident_host_hours(
    session: AsyncSession, tenant_id: uuid.UUID, start: datetime
) -> set[tuple[str, datetime]]:
    """Host-hours touched by incident evidence - excluded from training to resist baseline poisoning."""
    rows = (
        await session.execute(
            text(
                """
        SELECT DISTINCT snapshot->>'hostname' AS host, date_trunc('hour', timestamp) AS hour
        FROM incident_evidence WHERE tenant_id = :t AND timestamp >= :start AND snapshot->>'hostname' IS NOT NULL
        """
            ),
            {"t": tenant_id, "start": start},
        )
    ).all()
    return {(h, hr) for h, hr in rows}


async def train_model(session: AsyncSession, tenant_id: uuid.UUID, days: int = 14) -> dict[str, Any]:
    end = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)
    rows = await extract_features(session, tenant_id, start, end)
    excluded = await _incident_host_hours(session, tenant_id, start)
    train_rows = [r for r in rows if (r[0], r[1]) not in excluded]
    if len(train_rows) < 24:
        return {
            "status": "insufficient_data",
            "windows": len(train_rows),
            "message": "At least 24 host-hours of normal activity are needed to build a baseline.",
        }
    x = np.vstack([r[2] for r in train_rows])
    model = train(x, FEATURES)
    version = (
        int(
            (
                await session.execute(
                    select(func.coalesce(func.max(MlModel.version), 0)).where(
                        MlModel.tenant_id == tenant_id, MlModel.name == MODEL_NAME
                    )
                )
            ).scalar_one()
        )
        + 1
    )
    await session.execute(
        update(MlModel)
        .where(MlModel.tenant_id == tenant_id, MlModel.name == MODEL_NAME, MlModel.status == "active")
        .values(status="retired")
    )
    metrics = {
        "training_windows": len(train_rows),
        "excluded_windows": len(rows) - len(train_rows),
        "hosts": len({r[0] for r in train_rows}),
        "train_start": start.isoformat(),
        "train_end": end.isoformat(),
    }
    m = MlModel(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        name=MODEL_NAME,
        version=version,
        status="active",
        feature_names=FEATURES,
        params={
            "n_estimators": 200,
            "contamination": "auto",
            "transform": "log1p",
            "threshold": ANOMALY_THRESHOLD,
            "min_top_z": MIN_TOP_Z,
            "model_tag": MODEL_VERSION_TAG,
        },
        metrics=metrics,
        baseline={"median": dict(zip(FEATURES, np.expm1(model.median).round(2).tolist(), strict=True))},
        artifact=model.to_bytes(),
    )
    session.add(m)
    await session.flush()
    log.info("ml_model_trained", version=version, **metrics)
    return {"status": "trained", "model_id": str(m.id), "version": version, **metrics}


async def active_model(session: AsyncSession, tenant_id: uuid.UUID) -> tuple[MlModel, TrainedModel] | None:
    m = (
        await session.execute(
            select(MlModel)
            .where(MlModel.tenant_id == tenant_id, MlModel.name == MODEL_NAME, MlModel.status == "active")
            .order_by(MlModel.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if m is None:
        return None
    return m, TrainedModel.from_bytes(m.artifact)


async def score_recent(session: AsyncSession, tenant_id: uuid.UUID, hours: int = 2) -> dict[str, Any]:
    started = time.perf_counter()
    loaded = await active_model(session, tenant_id)
    if loaded is None:
        return {"status": "no_model"}
    m, model = loaded
    end = datetime.now(UTC) + timedelta(hours=1)
    start = (datetime.now(UTC) - timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)
    rows = await extract_features(session, tenant_id, start, end)
    if not rows:
        return {"status": "no_data"}
    x = np.vstack([r[2] for r in rows])
    calibrated, raw, z = score(model, x)
    anomalies = 0
    alert_ids: list[uuid.UUID] = []
    for i, (host, hour, feats) in enumerate(rows):
        contributors = explain(model, feats, z[i])
        is_anom = bool(calibrated[i] >= ANOMALY_THRESHOLD and contributors and contributors[0]["z_score"] >= MIN_TOP_Z)
        stmt = pg_insert(MlPrediction).values(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            model_id=m.id,
            entity_kind="host",
            entity_id=host,
            window_start=hour,
            window_end=hour + timedelta(hours=1),
            anomaly_score=float(calibrated[i]),
            raw_score=float(raw[i]),
            is_anomaly=is_anom,
            features=dict(zip(FEATURES, feats.tolist(), strict=True)),
            top_contributors=contributors,
        )
        await session.execute(
            stmt.on_conflict_do_update(
                index_elements=["tenant_id", "model_id", "entity_id", "window_start"],
                set_={
                    k: stmt.excluded[k]
                    for k in ("anomaly_score", "raw_score", "is_anomaly", "features", "top_contributors", "window_end")
                },
            )
        )
        if is_anom:
            anomalies += 1
            alert_ids.append(
                await _ml_alert(session, tenant_id, host, hour, float(calibrated[i]), contributors, m.version)
            )
    if alert_ids:
        await correlate(session, tenant_id, alert_ids)
    ML_INFERENCE_DURATION.observe(time.perf_counter() - started)
    return {"status": "scored", "windows": len(rows), "anomalies": anomalies, "model_version": m.version}


async def _ml_alert(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    host: str,
    hour: datetime,
    s: float,
    contributors: list[dict[str, Any]],
    version: int,
) -> uuid.UUID:
    what = "; ".join(
        f"{FEATURE_LABELS.get(c['feature'], c['feature'])}: {c['value']:.0f} (usually ~{c['baseline_median']:.0f})"
        for c in contributors[:3]
    )
    in_hour = (
        SecurityEvent.tenant_id == tenant_id,
        SecurityEvent.hostname == host,
        SecurityEvent.timestamp >= hour,
        SecurityEvent.timestamp < hour + timedelta(hours=1),
    )
    # link only the events behind the deviating features, so evidence is not diluted by normal traffic
    conds = [FEATURE_EVENTS[c["feature"]] for c in contributors[:2] if c["feature"] in FEATURE_EVENTS]
    ev_ids = list(
        (
            await session.execute(
                select(SecurityEvent.id)
                .where(*in_hour, or_(*conds) if conds else true())
                .order_by(SecurityEvent.timestamp.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    first, last = (
        await session.execute(
            select(func.min(SecurityEvent.timestamp), func.max(SecurityEvent.timestamp)).where(*in_hour)
        )
    ).one()
    spec = AlertSpec(
        rule_uid=ML_RULE,
        title=f"Behavioral anomaly on {host}",
        description=f"Activity on {host} departs from its learned baseline. {what}.",
        source="ml",
        severity=int(25 + 25 * s),
        dedup_key=f"{ML_RULE}|{host}",
        window_s=3 * 3600,
        first_ts=first or hour,
        last_ts=last or hour,
        event_ids=ev_ids,
        techniques=[],
        entities={"hostname": host},
        source_types=["ml"],
        details={
            "ml": {
                "model": MODEL_VERSION_TAG,
                "model_version": version,
                "anomaly_score": round(s, 4),
                "top_contributors": contributors,
            }
        },
    )
    aid, _ = await upsert_alert(session, tenant_id, spec)
    return aid
