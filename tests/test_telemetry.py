import asyncio
import gzip
import http.server
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import rt_telemetry as t

TOKEN = "tmk_testtoken"


class FakeIngest:
    def __init__(self):
        self.logs = []
        self.metrics = []
        self.mode = "ok"
        self.lock = threading.Lock()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if outer.mode == "drop":
                    self.connection.close()
                    return
                if outer.mode in ("500", "400"):
                    self.send_response(int(outer.mode))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.headers.get("Authorization") != "Bearer " + TOKEN:
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                text = body.decode("utf-8")
                with outer.lock:
                    if self.path == "/logs":
                        outer.logs.extend(json.loads(x) for x in text.splitlines() if x)
                    else:
                        outer.metrics.append(text)
                self.send_response(204)
                self.end_headers()

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def msgs(self):
        with self.lock:
            return [r["_msg"] for r in self.logs]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def wait_for(cond, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def spool_files(d, kind=""):
    return sorted(n for n in os.listdir(d) if n.startswith(kind) and n.endswith(".ndjson.gz") and n.split("-")[0] in ("logs", "metrics"))


def read_gz_lines(path):
    with open(path, "rb") as f:
        return [json.loads(x) for x in gzip.decompress(f.read()).decode().splitlines() if x]


FAST = dict(flush_interval=0.05, metrics_interval=300, backoff_min=0.05, backoff_max=0.2)


class Base(unittest.TestCase):
    def setUp(self):
        t.shutdown()
        t._reset_registry()
        self.srv = FakeIngest()
        self.dir = tempfile.mkdtemp(prefix="rtt-")
        self.env = dict(os.environ, PYTHONPATH=ROOT, TELEMETRY_URL=self.srv.url, TELEMETRY_TOKEN=TOKEN)

    def tearDown(self):
        t.shutdown()
        self.srv.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def init(self, **kw):
        opts = dict(url=self.srv.url, token=TOKEN, spool_dir=self.dir, capture_stdout=False,
                    capture_logging=False, capture_exceptions=False, server="testhost")
        opts.update(FAST)
        opts.update(kw)
        return t.init(**opts)

    def child(self, code, **env):
        e = dict(self.env, TELEMETRY_SPOOL_DIR=self.dir, **env)
        pre = "import sys,time,os\n"
        if os.name == "nt":
            pre += "import ctypes; ctypes.windll.kernel32.SetErrorMode(0x8003)\n"
        return subprocess.Popen([sys.executable, "-c", pre + code], env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class DeliveryTests(Base):
    def test_a_records_arrive(self):
        self.init(app="w1")
        t.info("hello", order_id=7)
        t.warn("careful")
        t.log("error", "bad", user="x")
        t.counter("jobs_total", queue="mail").inc(3)
        t.flush()
        self.assertEqual(sorted(self.srv.msgs()), ["bad", "careful", "hello"])
        r = next(x for x in self.srv.logs if x["_msg"] == "hello")
        self.assertEqual((r["level"], r["server"], r["order_id"], r["proc"]), ("info", "testhost", 7, "w1"))
        self.assertRegex(r["_time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        text = self.srv.metrics[-1]
        self.assertRegex(text, r'jobs_total\{queue="mail"\} 3 \d{13}')
        self.assertRegex(text, r"process_up 1 \d{13}")
        self.assertIn("telemetry_spool_bytes", text)

    def test_disabled_is_noop(self):
        env = {k: v for k, v in self.env.items() if not k.startswith("TELEMETRY_")}
        env["TELEMETRY_SPOOL_DIR"] = self.dir
        code = "import rt_telemetry as t; print(t.init()); t.info('x'); t.counter('a').inc(); t.flush(); t.shutdown()"
        out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "False")
        self.assertEqual(os.listdir(self.dir), [])

    def test_b_outage_spools_then_drains_in_order(self):
        self.init()
        self.srv.mode = "drop"
        for i in range(5):
            t.info("m%d" % i)
            t.flush()
        self.assertTrue(spool_files(self.dir, "logs"))
        self.assertEqual(self.srv.msgs(), [])
        self.srv.mode = "ok"
        self.assertTrue(wait_for(lambda: len(self.srv.msgs()) == 5))
        self.assertEqual(self.srv.msgs(), ["m%d" % i for i in range(5)])
        self.assertTrue(wait_for(lambda: not spool_files(self.dir, "logs")))
        time.sleep(0.3)
        self.assertEqual(len(self.srv.msgs()), 5)

    def test_server_500_is_retried(self):
        self.init()
        self.srv.mode = "500"
        t.info("again")
        t.flush()
        self.assertTrue(spool_files(self.dir, "logs"))
        self.srv.mode = "ok"
        self.assertTrue(wait_for(lambda: self.srv.msgs() == ["again"]))

    def test_4xx_goes_dead(self):
        self.init()
        self.srv.mode = "400"
        t.info("poison")
        t.flush()
        self.assertEqual(spool_files(self.dir, "logs"), [])
        dead = os.listdir(os.path.join(self.dir, "dead"))
        self.assertTrue(any(n.startswith("logs-") for n in dead))
        self.srv.mode = "ok"
        time.sleep(0.3)
        self.assertEqual(self.srv.msgs(), [])


class CrashTests(Base):
    def test_c_uncaught_exception_spooled_then_sent_next_run(self):
        self.srv.mode = "drop"
        p = self.child(
            "import rt_telemetry as t\n"
            "t.init(capture_stdout=False, capture_logging=False, flush_interval=0.05, backoff_min=0.05)\n"
            "t.info('before crash')\n"
            "def boom(): raise RuntimeError('kaboom')\n"
            "boom()\n"
        )
        p.communicate(timeout=30)
        self.assertNotEqual(p.returncode, 0)
        files = spool_files(self.dir, "logs")
        self.assertTrue(files)
        recs = [r for f in files for r in read_gz_lines(os.path.join(self.dir, f))]
        fatal = next(r for r in recs if r["level"] == "fatal")
        self.assertIn("kaboom", fatal["_msg"])
        self.assertIn("Traceback", fatal["stack"])
        self.assertTrue(fatal["fingerprint"])
        self.assertIn("before crash", [r["_msg"] for r in recs])
        self.srv.mode = "ok"
        p2 = self.child(
            "import rt_telemetry as t\n"
            "t.init(capture_stdout=False, capture_logging=False, flush_interval=0.05, backoff_min=0.05)\n"
            "time.sleep(1.0)\nt.shutdown()\n"
        )
        p2.communicate(timeout=30)
        self.assertTrue(wait_for(lambda: any("kaboom" in m for m in self.srv.msgs())))

    def test_thread_exception_is_fatal(self):
        self.init(capture_exceptions=True)
        th = threading.Thread(target=lambda: 1 / 0, name="worker-x")
        th.start()
        th.join()
        t.flush()
        r = next(x for x in self.srv.logs if x["level"] == "fatal")
        self.assertIn("ZeroDivisionError", r["_msg"])
        self.assertEqual(r["thread"], "worker-x")

    def test_asyncio_handler(self):
        self.init()

        async def main():
            t.install_asyncio_handler()
            asyncio.get_running_loop().call_soon(lambda: (_ for _ in ()).throw(ValueError("in loop")))
            await asyncio.sleep(0.1)

        asyncio.run(main())
        t.flush()
        self.assertTrue(any(r["level"] == "fatal" and "in loop" in r["_msg"] for r in self.srv.logs))

    def test_d_hard_kill_reported_next_start(self):
        p = self.child(
            "import rt_telemetry as t\n"
            "t.init(capture_stdout=False, capture_logging=False, flush_interval=0.05)\n"
            "print('ready', flush=True)\ntime.sleep(60)\n"
        )
        self.assertTrue(wait_for(lambda: any(n.startswith("run.") for n in os.listdir(self.dir))))
        p.kill()
        p.communicate(timeout=30)
        time.sleep(0.6)
        self.init(unclean_after=0.5)
        t.flush()
        self.assertTrue(any("ended uncleanly" in m for m in self.srv.msgs()))
        t.flush()
        self.assertEqual(sum("ended uncleanly" in m for m in self.srv.msgs()), 1)
        t.shutdown()
        self.assertEqual([n for n in os.listdir(self.dir) if n.startswith(("run.", "fault."))], [])

    def test_live_marker_not_reported(self):
        p = self.child(
            "import rt_telemetry as t\n"
            "t.init(capture_stdout=False, capture_logging=False, flush_interval=0.05)\ntime.sleep(60)\n"
        )
        try:
            self.assertTrue(wait_for(lambda: any(n.startswith("run.") for n in os.listdir(self.dir))))
            time.sleep(0.3)
            self.init(unclean_after=0.5)
            t.flush()
            self.assertFalse(any("ended uncleanly" in m for m in self.srv.msgs()))
        finally:
            p.kill()
            p.communicate(timeout=30)

    def test_faulthandler_report(self):
        p = self.child(
            "import rt_telemetry as t, faulthandler\n"
            "t.init(capture_stdout=False, capture_logging=False, flush_interval=0.05)\n"
            "faulthandler._sigsegv()\n"
        )
        p.communicate(timeout=30)
        self.init()
        t.flush()
        r = next((x for x in self.srv.logs if "faulthandler" in x["_msg"]), None)
        self.assertIsNotNone(r)
        self.assertTrue(r["stack"].strip())

    def test_sigterm_flushes_and_terminates(self):
        if os.name == "nt":
            self.skipTest("SIGTERM is TerminateProcess on Windows")
        p = self.child(
            "import rt_telemetry as t\n"
            "t.init(capture_stdout=False, flush_interval=30, metrics_interval=30)\n"
            "t.info('last words')\nprint('ready', flush=True)\ntime.sleep(60)\n"
        )
        p.stdout.readline()
        p.terminate()
        p.communicate(timeout=30)
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(wait_for(lambda: "last words" in self.srv.msgs()))


class SpoolTests(Base):
    def test_e_cap_drops_metrics_first_then_logs(self):
        self.srv.mode = "drop"
        self.init(spool_max_mb=22500 / 1048576, flush_interval=30, metrics_interval=30)
        c = t._client
        blob = lambda n: os.urandom(n)
        for _ in range(2):
            c._write_spool("logs", blob(8000))
            time.sleep(0.003)
        for _ in range(3):
            c._write_spool("metrics", blob(3000))
            time.sleep(0.003)
        names = spool_files(self.dir)
        self.assertEqual(sum(n.startswith("logs") for n in names), 2)
        self.assertEqual(sum(n.startswith("metrics") for n in names), 2)
        self.assertEqual(c.dropped["metrics"], 1)
        for _ in range(5):
            c._write_spool("logs", blob(8000))
            time.sleep(0.003)
        names = spool_files(self.dir)
        self.assertFalse(any(n.startswith("metrics") for n in names))
        self.assertGreater(c.dropped["logs"], 0)
        self.assertLessEqual(sum(os.path.getsize(os.path.join(self.dir, n)) for n in names), 22500)

    def test_f_two_processes_share_spool_no_duplicates(self):
        self.srv.mode = "drop"
        script = (
            "import rt_telemetry as t\n"
            "t.init(capture_stdout=False, capture_logging=False, flush_interval=30, metrics_interval=300)\n"
            "for i in range(50): t.info('%s-%%d' %% i)\n"
        )
        for tag in ("p1", "p2"):
            p = self.child(script % tag)
            p.communicate(timeout=30)
        self.assertGreaterEqual(len(spool_files(self.dir, "logs")), 2)
        self.srv.mode = "ok"
        drain = (
            "import rt_telemetry as t\n"
            "t.init(capture_stdout=False, capture_logging=False, flush_interval=0.05, backoff_min=0.05, metrics_interval=300)\n"
            "end=time.time()+15\n"
            "while time.time()<end and any(n.startswith(('logs-','metrics-')) for n in os.listdir(os.environ['TELEMETRY_SPOOL_DIR'])): time.sleep(0.05)\n"
            "t.shutdown()\n"
        )
        ps = [self.child(drain) for _ in range(2)]
        for p in ps:
            p.communicate(timeout=60)
        msgs = self.srv.msgs()
        want = ["p1-%d" % i for i in range(50)] + ["p2-%d" % i for i in range(50)]
        self.assertEqual(sorted(msgs, key=lambda x: (x[:2], int(x[3:]))), want)

    def test_stale_claim_is_taken_back(self):
        self.srv.mode = "drop"
        self.init()
        t.info("orphan")
        t.flush()
        name = spool_files(self.dir, "logs")[0]
        claim = os.path.join(self.dir, name + ".sending.99999")
        os.replace(os.path.join(self.dir, name), claim)
        old = time.time() - 600
        os.utime(claim, (old, old))
        self.srv.mode = "ok"
        t.shutdown()
        self.init()
        t.info("trigger")
        self.assertTrue(wait_for(lambda: "orphan" in self.srv.msgs()))


class BehaviourTests(Base):
    def test_secret_scrubbing(self):
        self.init()
        t.info("auth Bearer abc.def-123 and tmk_AbC123 done", password="hunter2", api_key="k", cfg={"my_token": "z", "ok": 1})
        t.flush()
        r = self.srv.logs[0]
        self.assertEqual(r["_msg"], "auth Bearer [redacted] and tmk_[redacted] done")
        self.assertEqual((r["password"], r["api_key"]), ("[redacted]", "[redacted]"))
        self.assertEqual(r["cfg"], {"my_token": "[redacted]", "ok": 1})

    def test_dedupe_collapses_repeats(self):
        self.init()
        for i in range(4):
            t.error("db down for host 10.0.0.%d" % i)
        t.info("unrelated")
        t.flush()
        errs = [r for r in self.srv.logs if r["level"] == "error"]
        self.assertEqual(len(errs), 1)
        self.assertEqual(errs[0]["count"], 4)
        self.assertTrue(errs[0]["fingerprint"])

    def test_series_cap(self):
        self.init()
        for i in range(1005):
            t.counter("req_total", id=str(i)).inc()
        t.flush()
        text = self.srv.metrics[-1]
        self.assertEqual(text.count("req_total{"), 1000)
        self.assertTrue(any("exceeds" in m for m in self.srv.msgs()))

    def test_metric_validation(self):
        with self.assertRaises(ValueError):
            t.counter("bad name")
        with self.assertRaises(ValueError):
            t.counter("ok_name", **{"bad-label": 1})
        with self.assertRaises(ValueError):
            t.histogram("h", le="1")
        t.counter("same_name")
        with self.assertRaises(ValueError):
            t.gauge("same_name")

    def test_histogram_gauge_timer(self):
        self.init()
        h = t.histogram("op_seconds", buckets=[0.1, 1], op="x")
        h.observe(0.05)
        h.observe(0.5)
        t.gauge("queue_depth").set(4)

        @t.timer(h)
        def slow():
            time.sleep(0.02)

        @t.timer(h)
        async def aslow():
            await asyncio.sleep(0.02)

        slow()
        asyncio.run(aslow())
        with t.timer(h):
            pass
        t.flush()
        text = self.srv.metrics[-1]
        self.assertRegex(text, r'op_seconds_bucket\{op="x",le="0.1"\} 4 ')
        self.assertRegex(text, r'op_seconds_bucket\{op="x",le="\+Inf"\} 5 ')
        self.assertRegex(text, r'op_seconds_count\{op="x"\} 5 ')
        self.assertRegex(text, r"queue_depth 4 \d{13}")

    def test_stdout_and_logging_capture_without_duplicates(self):
        self.init(capture_stdout=True, capture_logging=True)
        print("plain print")
        print("to err", file=sys.stderr)
        sh = logging.StreamHandler(sys.stderr)
        logging.getLogger().addHandler(sh)
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger("svc").warning("from logging")
        try:
            raise KeyError("k")
        except KeyError:
            logging.getLogger("svc").exception("with trace")
        t.flush()
        by = {}
        for r in self.srv.logs:
            by.setdefault(r["_msg"], []).append(r)
        self.assertEqual(by["plain print"][0]["level"], "info")
        self.assertEqual(by["to err"][0]["level"], "error")
        self.assertEqual(len(by["from logging"]), 1)
        self.assertEqual(by["from logging"][0]["logger"], "svc")
        self.assertEqual(by["from logging"][0]["level"], "warn")
        self.assertIn("KeyError", by["with trace"][0]["stack"])
        self.assertEqual(len(by["with trace"]), 1)
        logging.getLogger().removeHandler(sh)
        logging.getLogger().setLevel(logging.WARNING)
        t.shutdown()
        self.assertNotIsInstance(sys.stdout, t._Tee)

    def test_asgi_middleware(self):
        self.init()

        class Route:
            path = "/items/{id}"

        async def app(scope, receive, send):
            scope["route"] = Route()
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        async def run(path):
            sent = []

            async def send(m):
                sent.append(m)

            await t.ASGIMiddleware(app)({"type": "http", "method": "GET", "path": path}, None, send)

        asyncio.run(run("/items/17"))

        async def bare(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})

        async def run2():
            async def send(m):
                pass
            await t.ASGIMiddleware(bare)({"type": "http", "method": "POST", "path": "/raw/123"}, None, send)

        asyncio.run(run2())
        t.flush()
        text = self.srv.metrics[-1]
        self.assertIn('http_requests_total{method="GET",route="/items/{id}",status="4xx"} 1 ', text)
        self.assertIn('http_requests_total{method="POST",route="unmatched",status="2xx"} 1 ', text)
        self.assertNotIn("/raw/123", text)
        self.assertIn("http_request_duration_seconds_count", text)

    def test_wsgi_middleware(self):
        self.init()

        def app(environ, start_response):
            start_response("201 Created", [])
            return [b"x"]

        out = t.WSGIMiddleware(app)({"REQUEST_METHOD": "PUT", "PATH_INFO": "/a/1", "rt_telemetry.route": "/a/<id>"}, lambda *a: None)
        self.assertEqual(out, [b"x"])
        t.flush()
        self.assertIn('http_requests_total{method="PUT",route="/a/<id>",status="2xx"} 1 ', self.srv.metrics[-1])

    def test_spool_dir_falls_back_when_unwritable(self):
        bad = os.path.join(self.dir, "afile")
        open(bad, "w").close()
        self.assertEqual(t._resolve_spool(os.path.join(bad, "sub")), os.path.join(tempfile.gettempdir(), "rt_telemetry"))


if __name__ == "__main__":
    unittest.main()
