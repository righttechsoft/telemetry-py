import atexit
import faulthandler
import functools
import gzip
import hashlib
import inspect
import itertools
import json
import logging
import os
import re
import signal
import socket
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid

__version__ = "0.1.0"
__all__ = [
    "init", "shutdown", "flush", "log", "info", "warn", "warning", "error",
    "counter", "gauge", "histogram", "timer",
    "WSGIMiddleware", "ASGIMiddleware", "install_asyncio_handler",
]

_RESERVED = ("_time", "level", "server", "_msg")
_SECRET_KEY = re.compile(r"password|passwd|secret|token|authorization|api_key|cookie", re.I)
_BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=\-]+", re.I)
_TMK = re.compile(r"tmk_[A-Za-z0-9_\-]+")
_METRIC_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_SPOOL_RE = re.compile(r"^(logs|metrics)-(\d+)-(\d+)-(\d+)\.ndjson\.gz$")
_CLAIMED_RE = re.compile(r"^(logs|metrics)-(\d+)-(\d+)-(\d+)\.ndjson\.gz\.sending\.\d+$")
_MARKER_RE = re.compile(r"^run\.(\d+-[0-9a-f]{8})$")
_FAULT_RE = re.compile(r"^fault\.(\d+-[0-9a-f]{8})$")

DEFAULT_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)
BATCH_BYTES = 8 * 1024 * 1024
FLUSH_LINES = 1000
MAX_BUFFER = 50000
SERIES_CAP = 1000
DEDUPE_SECONDS = 5.0
HTTP_TIMEOUT = 10.0
DEFAULT_SPOOL = "/var/lib/telemetry"

_tl = threading.local()


def _diag(msg):
    try:
        if sys.__stderr__ is not None:
            sys.__stderr__.write("[rt_telemetry] %s\n" % msg)
            sys.__stderr__.flush()
    except Exception:
        pass


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)


def _scrub_text(s):
    return _TMK.sub("tmk_[redacted]", _BEARER.sub(r"\1[redacted]", s))


def _scrub_value(key, v, depth=0):
    if key is not None and _SECRET_KEY.search(str(key)):
        return "[redacted]"
    if isinstance(v, str):
        return _scrub_text(v)
    if depth < 4:
        if isinstance(v, dict):
            return {str(a): _scrub_value(a, b, depth + 1) for a, b in v.items()}
        if isinstance(v, (list, tuple)):
            return [_scrub_value(None, x, depth + 1) for x in v]
    return v


def _sha(s):
    return hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:12]


def _msg_fp(level, msg):
    return _sha(level + "|" + re.sub(r"\d+", "N", msg)[:200])


def _exc_fp(exc_type, tb):
    frames = traceback.extract_tb(tb)[-3:] if tb is not None else []
    return _sha(exc_type.__name__ + "|" + "|".join("%s:%s" % (os.path.basename(f.filename), f.name) for f in frames))


def _exc_fields(exc):
    tb = exc.__traceback__
    return {
        "stack": "".join(traceback.format_exception(type(exc), exc, tb))[-16384:],
        "fingerprint": _exc_fp(type(exc), tb),
        "exception": type(exc).__name__,
    }


def _rss():
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except Exception:
        pass
    try:
        import resource
        v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return v if sys.platform == "darwin" else v * 1024
    except Exception:
        return None


def _encode_logs(recs):
    chunks, cur, size = [], [], 0
    for r in recs:
        try:
            line = json.dumps(r, default=str)
        except Exception:
            line = json.dumps({"_time": r.get("_time"), "level": r.get("level"), "_msg": repr(r)})
        if cur and size + len(line) + 1 > BATCH_BYTES:
            chunks.append(cur)
            cur, size = [], 0
        cur.append(line)
        size += len(line) + 1
    if cur:
        chunks.append(cur)
    return [gzip.compress(("\n".join(c) + "\n").encode("utf-8"), 5) for c in chunks]


def _escape_label(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt_num(v):
    return str(v) if isinstance(v, int) else repr(float(v))


def _label_str(key, extra=""):
    parts = ['%s="%s"' % (k, _escape_label(v)) for k, v in key]
    if extra:
        parts.append(extra)
    return "{%s}" % ",".join(parts) if parts else ""


_REG = {}
_REG_LOCK = threading.RLock()
_capped = set()


class _Metric:
    def __init__(self, name, kind, buckets=None):
        self.name = name
        self.kind = kind
        self.buckets = buckets
        self.series = {}


class _Null:
    def inc(self, n=1):
        pass

    def dec(self, n=1):
        pass

    def set(self, v):
        pass

    def observe(self, v):
        pass


_NULL = _Null()


class Counter:
    def __init__(self, m, key):
        self._m, self._k = m, key

    def inc(self, n=1):
        if n < 0:
            return
        with _REG_LOCK:
            self._m.series[self._k] += n


class Gauge:
    def __init__(self, m, key):
        self._m, self._k = m, key

    def set(self, v):
        with _REG_LOCK:
            self._m.series[self._k] = v

    def inc(self, n=1):
        with _REG_LOCK:
            self._m.series[self._k] += n

    def dec(self, n=1):
        self.inc(-n)


class Histogram:
    def __init__(self, m, key):
        self._m, self._k = m, key

    def observe(self, v):
        with _REG_LOCK:
            st = self._m.series[self._k]
            for i, le in enumerate(self._m.buckets):
                if v <= le:
                    st[0][i] += 1
            st[1] += v
            st[2] += 1


def _handle(name, kind, labels, buckets=None):
    if not _METRIC_NAME.match(name):
        raise ValueError("invalid metric name %r" % (name,))
    for k in labels:
        if not _LABEL_NAME.match(k) or k.startswith("__") or (kind == "histogram" and k == "le"):
            raise ValueError("invalid label name %r" % (k,))
    key = tuple(sorted((k, str(v)) for k, v in labels.items()))
    with _REG_LOCK:
        m = _REG.get(name)
        if m is None:
            b = tuple(sorted(float(x) for x in (buckets or DEFAULT_BUCKETS))) if kind == "histogram" else None
            m = _REG[name] = _Metric(name, kind, b)
        elif m.kind != kind:
            raise ValueError("metric %r is a %s" % (name, m.kind))
        if key not in m.series:
            if len(m.series) >= SERIES_CAP:
                if name not in _capped:
                    _capped.add(name)
                    log("warn", "metric %s exceeds %d series, new series dropped" % (name, SERIES_CAP), metric=name)
                return _NULL
            m.series[key] = [[0] * len(m.buckets), 0.0, 0] if kind == "histogram" else 0
        cls = {"counter": Counter, "gauge": Gauge, "histogram": Histogram}[kind]
        return cls(m, key)


def counter(name, /, **labels):
    return _handle(name, "counter", labels)


def gauge(name, /, **labels):
    return _handle(name, "gauge", labels)


def histogram(name, /, buckets=None, **labels):
    return _handle(name, "histogram", labels, buckets)


class _Timer:
    def __init__(self, h):
        self._h = histogram(h) if isinstance(h, str) else h
        self._t = 0.0

    def __enter__(self):
        self._t = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self._h.observe(time.perf_counter() - self._t)
        return False

    def __call__(self, fn):
        h = self._h
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrap(*a, **k):
                t = time.perf_counter()
                try:
                    return await fn(*a, **k)
                finally:
                    h.observe(time.perf_counter() - t)
            return awrap

        @functools.wraps(fn)
        def wrap(*a, **k):
            t = time.perf_counter()
            try:
                return fn(*a, **k)
            finally:
                h.observe(time.perf_counter() - t)
        return wrap


def timer(h):
    return _Timer(h)


def _render_registry(ts):
    out = []
    with _REG_LOCK:
        for m in _REG.values():
            if not m.series:
                continue
            out.append("# TYPE %s %s" % (m.name, m.kind))
            for key, v in m.series.items():
                if m.kind == "histogram":
                    for le, c in zip(m.buckets, v[0]):
                        out.append("%s_bucket%s %d %d" % (m.name, _label_str(key, 'le="%g"' % le), c, ts))
                    out.append("%s_bucket%s %d %d" % (m.name, _label_str(key, 'le="+Inf"'), v[2], ts))
                    out.append("%s_sum%s %s %d" % (m.name, _label_str(key), repr(float(v[1])), ts))
                    out.append("%s_count%s %d %d" % (m.name, _label_str(key), v[2], ts))
                else:
                    out.append("%s%s %s %d" % (m.name, _label_str(key), _fmt_num(v), ts))
    return out


def _reset_registry():
    with _REG_LOCK:
        _REG.clear()
        _capped.clear()


class _Tee:
    def __init__(self, real, level, client):
        self._real, self._level, self._c = real, level, client
        self._part = ""
        self._lock = threading.Lock()

    def write(self, s):
        n = self._real.write(s)
        if isinstance(s, str) and s and not getattr(_tl, "in_log", 0):
            self._feed(s)
        return len(s) if n is None else n

    def _feed(self, s):
        with self._lock:
            *lines, self._part = (self._part + s).split("\n")
            if len(self._part) > 65536:
                lines.append(self._part)
                self._part = ""
        self._emit_lines(lines)

    def _emit_lines(self, lines):
        for ln in lines:
            ln = ln.rstrip("\r")
            if ln.strip():
                self._c.emit(self._level, ln[:8192], {})

    def drain_partial(self):
        with self._lock:
            part, self._part = self._part, ""
        self._emit_lines([part])

    def flush(self):
        return self._real.flush()

    def __getattr__(self, name):
        return getattr(self._real, name)


class _LogHandler(logging.Handler):
    def __init__(self, client):
        super().__init__()
        self._c = client

    def emit(self, record):
        if getattr(_tl, "emitting", False):
            return
        _tl.emitting = True
        try:
            n = record.levelno
            level = "debug" if n < 20 else "info" if n < 30 else "warn" if n < 40 else "error" if n < 50 else "critical"
            fields = {"logger": record.name}
            if record.exc_info and record.exc_info[1] is not None:
                fields.update(_exc_fields(record.exc_info[1]))
            elif record.stack_info:
                fields["stack"] = record.stack_info
            self._c.emit(level, record.getMessage(), fields, t=record.created)
        except Exception:
            pass
        finally:
            _tl.emitting = False


_orig_handle = logging.Handler.handle


def _patched_handle(self, record):
    if isinstance(self, _LogHandler):
        return _orig_handle(self, record)
    _tl.in_log = getattr(_tl, "in_log", 0) + 1
    try:
        return _orig_handle(self, record)
    finally:
        _tl.in_log -= 1


class _Client:
    def __init__(self, o):
        self.url = o["url"].rstrip("/")
        self.token = o["token"]
        self.proc = o["app"]
        self.server = o["server"]
        self.flush_interval = o["flush_interval"]
        self.metrics_interval = o["metrics_interval"]
        self.cap_bytes = int(o["spool_max_mb"] * 1024 * 1024)
        self.opts = o
        t = o["tuning"]
        self.backoff_min = t.get("backoff_min", 1.0)
        self.backoff_max = t.get("backoff_max", 300.0)
        self.unclean_after = t.get("unclean_after", 120.0)
        self.stale_claim = t.get("stale_claim", 300.0)
        self.spool = o["spool"]
        self.id = "%d-%s" % (os.getpid(), uuid.uuid4().hex[:8])
        self.dropped = {"logs": 0, "metrics": 0, "buffer": 0}
        self.send_failures = 0
        self._buf = []
        self._dd = {}
        self._bl = threading.RLock()
        self._io = threading.RLock()
        self._seq = itertools.count()
        self._backoff = self.backoff_min
        self._next_attempt = 0.0
        self._next_metrics = time.monotonic() + self.metrics_interval
        self._last_drop_warn = 0.0
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self._fault = None
        self._tees = []
        self._restore = []
        self._closed = False

    def start(self):
        o = self.opts
        if self.spool:
            os.makedirs(os.path.join(self.spool, "dead"), exist_ok=True)
            try:
                self._scan_previous()
            except Exception as e:
                _diag("previous-run scan failed: %s" % e)
            self._touch()
        if o["capture_exceptions"]:
            self._install_exception_hooks()
        if o["capture_stdout"]:
            self._install_tees()
        if o["capture_logging"]:
            self._install_logging()
        self._start_thread()

    def _start_thread(self):
        self._thread = threading.Thread(target=self._run, name="rt-telemetry", daemon=True)
        self._thread.start()

    def _after_fork(self):
        self._bl = threading.RLock()
        self._io = threading.RLock()
        self._buf = []
        self._dd = {}
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.id = "%d-%s" % (os.getpid(), uuid.uuid4().hex[:8])
        self._fault = None
        if self.spool:
            self._touch()
        self._start_thread()

    def emit(self, level, msg, fields, dedupe=True, t=None):
        rec = {"_time": _iso(t or time.time()), "level": level, "server": self.server, "_msg": _scrub_text(str(msg))}
        if self.proc:
            rec["proc"] = self.proc
        for k, v in fields.items():
            rec[("f_" + k) if k in _RESERVED else k] = _scrub_value(k, v)
        with self._bl:
            if dedupe and level in ("warn", "error", "fatal") and len(self._dd) < 1000:
                fp = rec.setdefault("fingerprint", _msg_fp(level, rec["_msg"]))
                e = self._dd.get(fp)
                if e:
                    e[2] += 1
                else:
                    self._dd[fp] = [time.monotonic(), rec, 1]
                return
            self._buf.append(rec)
            n = len(self._buf)
            if n > MAX_BUFFER:
                del self._buf[: n // 2]
                self.dropped["buffer"] += n // 2
        if n >= FLUSH_LINES:
            self._wake.set()

    def _collect(self, force):
        now = time.monotonic()
        with self._bl:
            for fp in [k for k, e in self._dd.items() if force or now - e[0] >= DEDUPE_SECONDS]:
                _, rec, count = self._dd.pop(fp)
                if count > 1:
                    rec["count"] = count
                self._buf.append(rec)
            recs, self._buf = self._buf, []
        return recs

    def _post(self, kind, body, timeout):
        req = urllib.request.Request(
            "%s/%s" % (self.url, kind),
            data=body,
            method="POST",
            headers={
                "Authorization": "Bearer " + self.token,
                "Content-Encoding": "gzip",
                "Content-Type": "application/x-ndjson" if kind == "logs" else "text/plain",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                r.read()
            return "ok"
        except urllib.error.HTTPError as e:
            code = e.code
            e.close()
            if code in (408, 429) or code >= 500 or code < 400:
                return "retry"
            _diag("%s rejected with HTTP %d, moved to dead/" % (kind, code))
            return "dead"
        except Exception:
            return "retry"

    def _fail(self):
        self.send_failures += 1
        self._next_attempt = time.monotonic() + self._backoff
        self._backoff = min(self._backoff * 2, self.backoff_max)

    def _ok(self):
        self._backoff = self.backoff_min
        self._next_attempt = 0.0

    def _backlog(self):
        if not self.spool:
            return False
        try:
            return any(_SPOOL_RE.match(n) or _CLAIMED_RE.match(n) for n in os.listdir(self.spool))
        except OSError:
            return False

    def _write_file(self, directory, name, data):
        path = os.path.join(directory, name)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _write_spool(self, kind, data, directory=None):
        if not self.spool:
            self.dropped[kind] += 1
            return
        name = "%s-%d-%d-%06d.ndjson.gz" % (kind, int(time.time() * 1000), os.getpid(), next(self._seq))
        try:
            self._write_file(directory or self.spool, name, data)
        except OSError as e:
            self.dropped[kind] += 1
            _diag("spool write failed: %s" % e)
            return
        if directory is None:
            self._enforce_cap()

    def _deliver(self, kind, body, timeout):
        if timeout <= 0 or self._backlog():
            self._write_spool(kind, body)
            return
        r = self._post(kind, body, timeout)
        if r == "ok":
            return
        if r == "dead":
            self._write_spool(kind, body, os.path.join(self.spool, "dead") if self.spool else None)
            return
        self._fail()
        self._write_spool(kind, body)

    def _send_logs(self, recs, timeout=HTTP_TIMEOUT):
        for body in _encode_logs(recs):
            self._deliver("logs", body, timeout)

    def _metrics_text(self):
        ts = int(time.time() * 1000)
        out = _render_registry(ts)
        out.append("# TYPE process_up gauge")
        out.append("process_up 1 %d" % ts)
        rss = _rss()
        if rss is not None:
            out.append("# TYPE process_resident_memory_bytes gauge")
            out.append("process_resident_memory_bytes %d %d" % (rss, ts))
        out.append("# TYPE telemetry_spool_bytes gauge")
        out.append("telemetry_spool_bytes %d %d" % (self._spool_bytes(), ts))
        out.append("# TYPE telemetry_dropped_total counter")
        for k, v in self.dropped.items():
            out.append('telemetry_dropped_total{kind="%s"} %d %d' % (k, v, ts))
        out.append("# TYPE telemetry_send_failures_total counter")
        out.append("telemetry_send_failures_total %d %d" % (self.send_failures, ts))
        return "\n".join(out) + "\n"

    def _send_metrics(self, timeout=HTTP_TIMEOUT):
        self._deliver("metrics", gzip.compress(self._metrics_text().encode("utf-8"), 5), timeout)

    def _spool_bytes(self):
        total = 0
        if self.spool:
            for n in os.listdir(self.spool):
                if _SPOOL_RE.match(n) or _CLAIMED_RE.match(n):
                    try:
                        total += os.path.getsize(os.path.join(self.spool, n))
                    except OSError:
                        pass
        return total

    def _unclaimed(self):
        names = []
        for n in os.listdir(self.spool):
            m = _SPOOL_RE.match(n)
            if m:
                names.append(((int(m.group(2)), int(m.group(3)), int(m.group(4))), m.group(1), n))
        names.sort()
        return names

    def _reclaim(self):
        now = time.time()
        for n in os.listdir(self.spool):
            p = os.path.join(self.spool, n)
            try:
                if _CLAIMED_RE.match(n) and now - os.path.getmtime(p) > self.stale_claim:
                    os.replace(p, os.path.join(self.spool, n.split(".sending.")[0]))
                elif n.endswith(".tmp") and now - os.path.getmtime(p) > self.stale_claim:
                    os.unlink(p)
            except OSError:
                pass

    def _drain(self, deadline=None, wait=0.0):
        if not self.spool or not self._io.acquire(timeout=wait):
            return
        try:
            self._reclaim()
            for _, kind, name in self._unclaimed():
                timeout = HTTP_TIMEOUT if deadline is None else min(HTTP_TIMEOUT, deadline - time.monotonic())
                if timeout <= 0:
                    return
                src = os.path.join(self.spool, name)
                claim = "%s.sending.%d" % (src, os.getpid())
                try:
                    os.replace(src, claim)
                    os.utime(claim)
                    with open(claim, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                r = self._post(kind, data, timeout)
                try:
                    if r == "ok":
                        os.unlink(claim)
                        self._ok()
                    elif r == "dead":
                        os.replace(claim, os.path.join(self.spool, "dead", name))
                    else:
                        os.replace(claim, src)
                        self._fail()
                        return
                except OSError:
                    pass
        finally:
            self._io.release()

    def _enforce_cap(self):
        files, total = [], 0
        try:
            names = os.listdir(self.spool)
        except OSError:
            return
        for n in names:
            m = _SPOOL_RE.match(n)
            if not (m or _CLAIMED_RE.match(n)):
                continue
            try:
                size = os.path.getsize(os.path.join(self.spool, n))
            except OSError:
                continue
            total += size
            if m:
                files.append((m.group(1), (int(m.group(2)), int(m.group(3)), int(m.group(4))), n, size))
        if total <= self.cap_bytes:
            return
        order = sorted(f for f in files if f[0] == "metrics") + sorted(f for f in files if f[0] == "logs")
        dropped = 0
        for kind, _, n, size in order:
            if total <= self.cap_bytes:
                break
            try:
                os.unlink(os.path.join(self.spool, n))
            except OSError:
                continue
            total -= size
            self.dropped[kind] += 1
            dropped += 1
        now = time.monotonic()
        if dropped and now - self._last_drop_warn > 60:
            self._last_drop_warn = now
            self.emit("warn", "telemetry spool over its size cap, dropped %d oldest files" % dropped, {}, dedupe=False)

    def _touch(self):
        p = os.path.join(self.spool, "run." + self.id)
        try:
            os.utime(p, None)
        except OSError:
            try:
                open(p, "ab").close()
            except OSError:
                pass

    def _scan_previous(self):
        now = time.time()
        for n in os.listdir(self.spool):
            p = os.path.join(self.spool, n)
            mm, fm = _MARKER_RE.match(n), _FAULT_RE.match(n)
            try:
                if mm and mm.group(1) != self.id:
                    mt = os.path.getmtime(p)
                    if now - mt < self.unclean_after:
                        continue
                    os.rename(p, p + ".reported")
                    os.unlink(p + ".reported")
                    fp = os.path.join(self.spool, "fault." + mm.group(1))
                    if os.path.exists(fp) and os.path.getsize(fp) == 0:
                        os.unlink(fp)
                    self.emit("fatal", "previous process ended uncleanly (killed/OOM?)",
                              {"marker": mm.group(1), "last_seen": _iso(mt)}, dedupe=False)
                elif fm and fm.group(1) != self.id and os.path.getsize(p) > 0:
                    os.rename(p, p + ".reading")
                    with open(p + ".reading", "rb") as f:
                        text = f.read(32768).decode("utf-8", "replace")
                    os.unlink(p + ".reading")
                    self.emit("fatal", "previous process crashed (faulthandler)",
                              {"marker": fm.group(1), "stack": text}, dedupe=False)
            except OSError:
                pass

    def _run(self):
        while not self._stop.is_set():
            self._wake.wait(self.flush_interval)
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                self._tick()
            except Exception as e:
                _diag("tick failed: %s" % e)

    def _tick(self):
        if self.spool:
            self._touch()
        now = time.monotonic()
        if self._backlog() and now >= self._next_attempt:
            self._drain()
        self._send_logs(self._collect(False))
        if now >= self._next_metrics:
            self._next_metrics = now + self.metrics_interval
            self._send_metrics()

    def flush(self):
        self._send_logs(self._collect(True))
        self._send_metrics()
        if self._backlog() and time.monotonic() >= self._next_attempt:
            self._drain()

    def crash(self, exc):
        f = _exc_fields(exc)
        self.emit("fatal", "%s: %s" % (type(exc).__name__, exc), f, dedupe=False)
        for body in _encode_logs(self._collect(True)):
            self._write_spool("logs", body)

    def _install_exception_hooks(self):
        prev_hook = sys.excepthook
        prev_thread = threading.excepthook

        def hook(et, ev, tb):
            if not issubclass(et, KeyboardInterrupt):
                try:
                    self.crash(ev)
                except Exception:
                    pass
            prev_hook(et, ev, tb)

        def thook(args):
            if args.exc_type is not SystemExit and args.exc_value is not None:
                try:
                    self.emit("fatal", "%s: %s" % (args.exc_type.__name__, args.exc_value),
                              dict(_exc_fields(args.exc_value), thread=getattr(args.thread, "name", None)))
                except Exception:
                    pass
            prev_thread(args)

        sys.excepthook, threading.excepthook = hook, thook
        self._restore.append(lambda: (setattr(sys, "excepthook", prev_hook) if sys.excepthook is hook else None))
        self._restore.append(lambda: (setattr(threading, "excepthook", prev_thread) if threading.excepthook is thook else None))

        if self.spool:
            was_on = faulthandler.is_enabled()
            try:
                self._fault = open(os.path.join(self.spool, "fault." + self.id), "wb")
                faulthandler.enable(file=self._fault, all_threads=True)

                def undo():
                    faulthandler.disable()
                    if was_on and sys.__stderr__ is not None:
                        faulthandler.enable(file=sys.__stderr__)
                self._restore.append(undo)
            except Exception as e:
                _diag("faulthandler not enabled: %s" % e)

        if threading.current_thread() is threading.main_thread():
            try:
                prev_sig = signal.getsignal(signal.SIGTERM)

                def on_term(signum, frame):
                    shutdown()
                    if callable(prev_sig):
                        prev_sig(signum, frame)
                    elif prev_sig != signal.SIG_IGN:
                        signal.signal(signal.SIGTERM, signal.SIG_DFL)
                        os.kill(os.getpid(), signal.SIGTERM)

                signal.signal(signal.SIGTERM, on_term)
                self._restore.append(lambda: signal.signal(signal.SIGTERM, prev_sig if prev_sig is not None else signal.SIG_DFL)
                                     if signal.getsignal(signal.SIGTERM) is on_term else None)
            except (ValueError, OSError):
                pass

    def _install_tees(self):
        for name, level in (("stdout", "info"), ("stderr", "error")):
            real = getattr(sys, name)
            if real is None:
                continue
            tee = _Tee(real, level, self)
            setattr(sys, name, tee)
            self._tees.append(tee)

            def undo(name=name, tee=tee):
                tee.drain_partial()
                if getattr(sys, name) is tee:
                    setattr(sys, name, tee._real)
            self._restore.append(undo)

    def _install_logging(self):
        h = _LogHandler(self)
        logging.getLogger().addHandler(h)
        self._restore.append(lambda: logging.getLogger().removeHandler(h))
        if self.opts["capture_stdout"]:
            logging.Handler.handle = _patched_handle
            self._restore.append(lambda: setattr(logging.Handler, "handle", _orig_handle))

    def close(self, timeout=3.0):
        if self._closed:
            return
        self._closed = True
        deadline = time.monotonic() + timeout
        self._stop.set()
        self._wake.set()
        for undo in reversed(self._restore):
            try:
                undo()
            except Exception:
                pass
        try:
            left = max(0.0, deadline - time.monotonic())
            self._send_logs(self._collect(True), left)
            self._send_metrics(max(0.0, deadline - time.monotonic()))
            if self._backlog():
                self._drain(deadline, wait=max(0.0, deadline - time.monotonic()))
        except Exception as e:
            _diag("final flush failed: %s" % e)
        if self.spool:
            for n in ("run." + self.id, "fault." + self.id):
                try:
                    if self._fault is not None and n.startswith("fault"):
                        self._fault.close()
                    os.unlink(os.path.join(self.spool, n))
                except OSError:
                    pass


_client = None
_atexit_set = False


def _resolve_spool(path):
    cands = [path] if path else ([] if os.name == "nt" else [DEFAULT_SPOOL])
    fallback = os.path.join(tempfile.gettempdir(), "rt_telemetry")
    for p in cands + [fallback]:
        try:
            os.makedirs(p, exist_ok=True)
            probe = os.path.join(p, ".probe.%d" % os.getpid())
            with open(probe, "wb"):
                pass
            os.unlink(probe)
            if p == fallback and cands:
                _diag("spool dir %s not writable, using %s" % (cands[0], fallback))
            return p
        except OSError:
            continue
    _diag("no writable spool dir, data is lost while the ingest is unreachable")
    return None


def init(app=None, url=None, token=None, spool_dir=None, spool_max_mb=None, server=None,
         capture_stdout=True, capture_logging=True, capture_exceptions=True,
         flush_interval=2.0, metrics_interval=30.0, **tuning):
    global _client, _atexit_set
    shutdown()
    env = os.environ.get
    url = url or env("TELEMETRY_URL")
    token = token or env("TELEMETRY_TOKEN")
    if not url or not token:
        return False
    unknown = set(tuning) - {"backoff_min", "backoff_max", "unclean_after", "stale_claim"}
    if unknown:
        raise TypeError("unexpected arguments: %s" % ", ".join(sorted(unknown)))
    mb = spool_max_mb if spool_max_mb is not None else float(env("TELEMETRY_SPOOL_MAX_MB") or 500)
    c = _Client({
        "app": app, "url": url, "token": token,
        "spool": _resolve_spool(spool_dir or env("TELEMETRY_SPOOL_DIR")),
        "spool_max_mb": float(mb),
        "server": server or env("TELEMETRY_SERVER") or socket.gethostname(),
        "capture_stdout": capture_stdout, "capture_logging": capture_logging,
        "capture_exceptions": capture_exceptions,
        "flush_interval": flush_interval, "metrics_interval": metrics_interval,
        "tuning": tuning,
    })
    _client = c
    c.start()
    if not _atexit_set:
        _atexit_set = True
        atexit.register(shutdown)
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=lambda: _client and _client._after_fork())
    return True


def shutdown(timeout=3.0):
    global _client
    c, _client = _client, None
    if c is not None:
        c.close(timeout)


def flush():
    c = _client
    if c is not None:
        c.flush()


def log(level, msg, /, **fields):
    c = _client
    if c is not None:
        c.emit(str(level).lower(), msg, fields)


def info(msg, /, **fields):
    log("info", msg, **fields)


def warn(msg, /, **fields):
    log("warn", msg, **fields)


warning = warn


def error(msg, /, **fields):
    log("error", msg, **fields)


def install_asyncio_handler(loop=None):
    import asyncio
    if loop is None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
    prev = loop.get_exception_handler()

    def handler(lp, ctx):
        c = _client
        if c is not None:
            exc = ctx.get("exception")
            msg = ctx.get("message", "asyncio error")
            fields = _exc_fields(exc) if exc is not None else {}
            c.emit("fatal", "%s: %s" % (type(exc).__name__, exc) if exc is not None else msg, dict(fields, source="asyncio"))
        if prev is not None:
            prev(lp, ctx)
        else:
            lp.default_exception_handler(ctx)

    loop.set_exception_handler(handler)


def _record_request(route, method, status, seconds):
    if not route or "*" in route:
        route = "unmatched"
    counter("http_requests_total", route=route, method=method, status="%dxx" % (status // 100)).inc()
    histogram("http_request_duration_seconds", route=route, method=method).observe(seconds)


class WSGIMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        t = time.perf_counter()
        status = [500]

        def sr(st, headers, exc_info=None):
            try:
                status[0] = int(str(st).split(" ", 1)[0])
            except ValueError:
                pass
            return start_response(st, headers, exc_info) if exc_info else start_response(st, headers)

        try:
            result = self.app(environ, sr)
        except BaseException:
            _record_request(self._route(environ), environ.get("REQUEST_METHOD", "GET"), 500, time.perf_counter() - t)
            raise
        _record_request(self._route(environ), environ.get("REQUEST_METHOD", "GET"), status[0], time.perf_counter() - t)
        return result

    @staticmethod
    def _route(environ):
        r = environ.get("rt_telemetry.route")
        if r:
            return r
        return getattr(environ.get("bottle.route"), "rule", None)


class ASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        t = time.perf_counter()
        status = [500]

        async def snd(message):
            if message.get("type") == "http.response.start":
                status[0] = message.get("status", 500)
            await send(message)

        try:
            await self.app(scope, receive, snd)
        finally:
            _record_request(getattr(scope.get("route"), "path", None), scope.get("method", "GET"), status[0],
                            time.perf_counter() - t)
