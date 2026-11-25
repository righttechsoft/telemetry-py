# telemetry-py

Ships logs, crashes and metrics to the telemetry ingest. Stdlib only, Python 3.9+. Protocol and token setup: `docs/telemetry.md` in the taskmaster repo.

## Install

    pip install git+https://github.com/righttechsoft/telemetry-py@v0.1.0

## Setup

    import rt_telemetry
    rt_telemetry.init(app="push_worker")

Env (arguments override): `TELEMETRY_URL`, `TELEMETRY_TOKEN`, `TELEMETRY_SPOOL_DIR` (default `/var/lib/telemetry`, temp dir if not writable), `TELEMETRY_SPOOL_MAX_MB` (default 500), `TELEMETRY_SERVER` (default hostname). No url or token: `init()` returns False and does nothing.

`app` only tags this process (`proc` field on logs). The `app` label itself comes from the token.

Docker: mount a volume so the spool survives restarts. Replicas can share it.

    volumes:
      - telemetry:/var/lib/telemetry

## What is captured

By default: `print` output (stdout as `info`, stderr as `error`), the `logging` root logger, uncaught exceptions in the main thread and in threads (`level=fatal`, stack, fingerprint), and a previous run that died without cleaning up (kill -9, OOM). Segfaults are reported on the next start through `faulthandler`. Switch each off with `capture_stdout`, `capture_logging`, `capture_exceptions`. The root logger keeps its own level: set it to `INFO` to ship info records.

Asyncio: call `rt_telemetry.install_asyncio_handler()` inside the running loop.

Secrets are scrubbed: fields named like `password|token|secret|authorization|api_key|cookie`, `Bearer ...` and `tmk_...` in messages. Repeated warn/error records with the same fingerprint inside 5 s become one line with `count`.

## API

    rt_telemetry.info("order placed", order_id=42)      # also warn, error, log(level, msg, **fields)
    rt_telemetry.counter("jobs_total", queue="mail").inc()
    rt_telemetry.gauge("queue_depth").set(12)
    h = rt_telemetry.histogram("job_seconds", job="sync")
    h.observe(1.2)

    @rt_telemetry.timer(h)          # sync or async function
    def run(): ...

    with rt_telemetry.timer(h): ...

    rt_telemetry.flush()
    rt_telemetry.shutdown()

Labels are validated and each metric is capped at 1000 series; extra series are dropped with a warn line. Built in: `process_up`, `process_resident_memory_bytes` (Linux), `telemetry_spool_bytes`, `telemetry_dropped_total`, `telemetry_send_failures_total`.

Request metrics (`http_requests_total{route,method,status}`, `http_request_duration_seconds`), with the route template only, never the raw path (`unmatched` when unknown):

    app = rt_telemetry.WSGIMiddleware(app)     # Bottle route is read; others set environ["rt_telemetry.route"]
    app = rt_telemetry.ASGIMiddleware(app)     # Starlette/FastAPI scope["route"].path

## Delivery

At-least-once. A failed send (network, 5xx, 408, 429) goes to the spool dir as a gzip file and is retried oldest first with backoff from 1 s to 5 min; new data waits behind the spool so order is kept. Other 4xx go to `dead/` and are never retried. A crash writes the buffer and the fatal record to the spool before the process dies. Over `TELEMETRY_SPOOL_MAX_MB` the oldest metrics files are dropped first, then the oldest logs. A duplicate after a crash between send and delete is possible. Metric samples carry their own timestamps, so a replay lands at the right time.

## Tests

    python -m pytest
