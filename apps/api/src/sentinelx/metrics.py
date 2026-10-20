"""Prometheus metrics."""

from prometheus_client import Counter, Gauge, Histogram

EVENTS_INGESTED = Counter("events_ingested_total", "Events accepted into storage", ["source"])
EVENTS_DUPLICATE = Counter("events_duplicate_total", "Events skipped as duplicates (idempotency)", ["source"])
EVENTS_FAILED = Counter("events_failed_total", "Events quarantined (failed validation/parsing)", ["source"])
INGESTION_LATENCY = Histogram(
    "ingestion_latency_seconds",
    "Event timestamp to ingestion delay",
    ["source"],
    buckets=(0.5, 1, 5, 15, 60, 300, 900, 3600, 86400),
)
INGEST_BATCH_DURATION = Histogram("ingest_batch_duration_seconds", "Time to normalize+store a batch")
DETECTION_DURATION = Histogram("detection_duration_seconds", "Time to run detection on a batch")
ALERTS_CREATED = Counter("alerts_created_total", "Alerts created", ["source"])
INCIDENTS_CREATED = Counter("incidents_created_total", "Incidents promoted (visible to analysts)")
CORRELATION_DURATION = Histogram("correlation_duration_seconds", "Time to correlate alerts into incidents")
ML_INFERENCE_DURATION = Histogram("ml_inference_duration_seconds", "Time to score a tenant's host windows")
LLM_REQUEST_DURATION = Histogram(
    "llm_request_duration_seconds", "Ollama request duration", buckets=(1, 5, 10, 20, 40, 60, 120, 240)
)
LLM_ERRORS = Counter("llm_errors_total", "LLM errors", ["kind"])
TI_REQUESTS = Counter("threat_intel_requests_total", "Threat-intel lookups", ["provider"])
TI_FAILURES = Counter("threat_intel_failures_total", "Threat-intel lookup failures", ["provider"])
QUEUE_DEPTH = Gauge("queue_depth", "Queued jobs", ["kind"])
DATABASE_ERRORS = Counter("database_errors_total", "Database errors")
JOBS_PROCESSED = Counter("jobs_processed_total", "Jobs processed", ["kind", "status"])
