"""
Screenshot capture for discovered subdomains.

Uses Playwright (async Chromium) to navigate each host and capture a PNG,
recording metadata (final URL, HTTP status, title, server header) into a JSON
index that the report server renders as a gowitness-style gallery.
"""
import asyncio
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from datetime import datetime
from typing import List, Dict, Optional

if __package__:
    from .display import ANSI
    from .navigator import Navigator
else:
    from display import ANSI
    from navigator import Navigator


class _ConnLostNoiseFilter(logging.Filter):
    """
    Drop the asyncio "socket.send()/sendto() raised exception." warnings that
    Playwright's pipe transport emits when the browser is torn down (it keeps
    writing protocol messages to the already-closed driver pipe). Harmless noise;
    real asyncio errors still pass through.
    """
    def filter(self, record):
        try:
            return 'raised exception.' not in record.getMessage()
        except Exception:
            return True


_NOISE_FILTER_INSTALLED = False


def _quiet_asyncio_connlost_noise():
    """Install the connlost-write noise filter on the asyncio logger once."""
    global _NOISE_FILTER_INSTALLED
    if not _NOISE_FILTER_INSTALLED:
        logging.getLogger('asyncio').addFilter(_ConnLostNoiseFilter())
        _NOISE_FILTER_INSTALLED = True


# Registry of live DeepTechStreamers so a SIGINT handler (which hard-exits via
# os._exit and bypasses every finally block) can still close their browsers
# cleanly before the process dies — otherwise the Playwright Node driver writes
# to a half-closed pipe and crashes with EPIPE.
_ACTIVE_STREAMERS = set()
_ACTIVE_STREAMERS_LOCK = threading.Lock()


def shutdown_active_streamers():
    """Force-close every live deep-detect browser. Safe to call from a signal
    handler; returns once the browsers/drivers have shut down."""
    with _ACTIVE_STREAMERS_LOCK:
        streamers = list(_ACTIVE_STREAMERS)
    for s in streamers:
        try:
            s.close(drain=False)
        except Exception:
            pass

# Name of the JSON index written into each scan directory.
INDEX_FILENAME = "subcat_screenshots.json"
# Per-scan metadata file (id, domain, created, counts).
SCAN_META_FILENAME = "scan.json"
# Sub-directory (inside a scan directory) that holds the PNG files.
IMAGES_SUBDIR = "screenshots"


def default_base_dir() -> str:
    """
    Base directory that holds all screenshot scans, under the user's home
    (alongside the cache/config): ``~/.subcat/screenshots``.
    """
    return os.path.join(os.path.expanduser("~"), ".subcat", "screenshots")


def _have_playwright() -> bool:
    """Return True if the playwright package is importable."""
    return Navigator.have_playwright()


def _safe_name(host: str) -> str:
    """Turn a host into a filesystem-safe screenshot filename."""
    name = re.sub(r'[^a-zA-Z0-9._-]', '_', host.strip().lower())
    return name[:120] or "host"


def safe_dir_name(domain: str) -> str:
    """Turn a domain into a filesystem-safe sub-directory name."""
    name = re.sub(r'[^a-zA-Z0-9._-]', '_', (domain or '').strip().lower())
    return name[:120] or "scan"


def make_scan_id(domain: str = None) -> str:
    """Build a short unique scan id (12-char hex). Domain is kept in metadata."""
    return uuid.uuid4().hex[:12]


def write_scan_meta(scan_dir: str, domain: str, results: List[Dict]) -> Dict:
    """Write per-scan metadata (id, domain, created, counts) and return it."""
    alive = sum(1 for r in results if r.get('status') is not None)
    meta = {
        'id': os.path.basename(os.path.normpath(scan_dir)),
        'domain': domain,
        'created': datetime.now().isoformat(timespec='seconds'),
        'total': len(results),
        'alive': alive,
    }
    try:
        os.makedirs(scan_dir, exist_ok=True)
        with open(os.path.join(scan_dir, SCAN_META_FILENAME), 'w', encoding='utf-8') as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass
    return meta


def is_scan_dir(path: str) -> bool:
    """True if ``path`` is a single scan directory (holds the index file)."""
    return os.path.exists(os.path.join(path, INDEX_FILENAME))


def list_scans(base_dir: str) -> List[Dict]:
    """
    List scans under a base directory, newest first.

    Reads each sub-directory's scan.json (falling back to deriving counts from
    its index). Returns a list of metadata dicts.
    """
    scans: List[Dict] = []
    if not os.path.isdir(base_dir):
        return scans
    for name in os.listdir(base_dir):
        sub = os.path.join(base_dir, name)
        if not os.path.isdir(sub) or not is_scan_dir(sub):
            continue
        meta = None
        meta_path = os.path.join(sub, SCAN_META_FILENAME)
        if os.path.exists(meta_path):
            try:
                with open(meta_path, encoding='utf-8') as f:
                    meta = json.load(f)
            except Exception:
                meta = None
        if meta is None:
            results = load_index(sub)
            meta = {
                'domain': name,
                'created': None,
                'total': len(results),
                'alive': sum(1 for r in results if r.get('status') is not None),
            }
        meta['id'] = name  # directory name is the authoritative id
        scans.append(meta)
    scans.sort(key=lambda s: s.get('created') or '', reverse=True)
    return scans


def prune_scans_for_domain(base_dir: str, domain: str, keep_id: str) -> int:
    """Remove older scan directories for the same domain, keeping only keep_id.

    Re-scanning a domain replaces its previous report instead of piling up
    duplicate scans. Returns the number of scan dirs removed.
    """
    if not domain or not os.path.isdir(base_dir):
        return 0
    target = domain.strip().lower()
    removed = 0
    for s in list_scans(base_dir):
        sid = s.get('id')
        if not sid or sid == keep_id:
            continue
        if (s.get('domain') or '').strip().lower() != target:
            continue
        sub = os.path.join(base_dir, sid)
        try:
            shutil.rmtree(sub, ignore_errors=True)
            removed += 1
        except Exception:
            pass
    return removed


def load_index(output_dir: str) -> List[Dict]:
    """Load the existing screenshot index from a directory (or [])."""
    path = os.path.join(output_dir, INDEX_FILENAME)
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get('results', [])
    except Exception:
        return []


class Screenshotter:
    """Capture screenshots of hosts with Playwright Chromium."""

    def __init__(self,
                 output_dir: str = None,
                 concurrency: int = 8,
                 timeout: float = 15.0,
                 full_page: bool = False,
                 width: int = 1280,
                 height: int = 800,
                 detect_tech: bool = True,
                 capture: bool = True,
                 logger=None):
        # When capture is False the page is still loaded and fingerprinted, but
        # no PNG/index is written (used by --deep-tech: detection without
        # screenshots).
        self.capture = capture
        self.output_dir = output_dir
        self.images_dir = os.path.join(output_dir, IMAGES_SUBDIR) if output_dir else None
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.full_page = full_page
        self.width = width
        self.height = height
        self.logger = logger
        self._done = 0
        self._total = 0
        self._ok = 0

        # Optional technology fingerprinting (gowitness-style icons in the
        # report). Built lazily so a missing detector never blocks captures.
        self._detector = None
        if detect_tech:
            try:
                if __package__:
                    from .detector import Detector
                else:
                    from detector import Detector
                self._detector = Detector(logger=logger, enable_tls_check=False)
            except Exception:
                self._detector = None

    # ---- public API -------------------------------------------------------

    def run(self, hosts: List[str], progress_callback=None) -> List[Dict]:
        """
        Capture screenshots for the given hosts.

        :param hosts: list of bare hostnames (no scheme)
        :param progress_callback: optional func(done, total, ok)
        :return: list of result dicts (also merged into the on-disk index)
        """
        if not _have_playwright():
            if self.logger:
                self.logger.critical(
                    "Playwright is not installed. Install it with: "
                    f"{ANSI.YELLOW}pip install playwright && playwright install chromium{ANSI.RESET}")
            return []

        # De-duplicate while preserving order
        seen = set()
        targets = []
        for h in hosts:
            h = (h or "").strip().lower()
            if h and h not in seen:
                seen.add(h)
                targets.append(h)

        if not targets:
            return []

        if self.capture:
            os.makedirs(self.images_dir, exist_ok=True)
        self._total = len(targets)
        self._done = 0
        self._ok = 0

        _quiet_asyncio_connlost_noise()
        try:
            results = asyncio.run(self._capture_all(targets, progress_callback))
        except Exception as e:
            if self.logger:
                self.logger.error(f"Screenshot capture failed: {e}")
            return []

        if self.capture:
            self._write_index(results)
        return results

    # ---- internals --------------------------------------------------------

    async def _capture_all(self, targets: List[str], progress_callback) -> List[Dict]:
        results: List[Dict] = []
        results_lock = asyncio.Lock()
        sem = asyncio.Semaphore(self.concurrency)

        nav = Navigator(timeout=self.timeout, logger=self.logger)
        try:
            await nav.start_browser()
        except Exception as e:
            msg = str(e)
            if self.logger:
                if "Executable doesn't exist" in msg or "playwright install" in msg:
                    self.logger.critical(
                        "Chromium browser not installed. Run: "
                        f"{ANSI.YELLOW}playwright install chromium{ANSI.RESET}")
                else:
                    self.logger.error(f"Failed to launch browser: {e}")
            await nav.close_browser()
            return []

        async def worker(host: str):
            async with sem:
                entry = await self._probe_host(nav, host)
            async with results_lock:
                results.append(entry)
                self._done += 1
                if entry.get('status') is not None:
                    self._ok += 1
                if progress_callback:
                    try:
                        progress_callback(self._done, self._total, self._ok)
                    except Exception:
                        pass

        try:
            await asyncio.gather(*(worker(h) for h in targets))
        finally:
            await nav.close_browser()

        # Stable ordering: alive first, then by host
        results.sort(key=lambda r: (r.get('status') is None, r.get('input', '')))
        return results

    async def _probe_host(self, nav: Navigator, host: str) -> Dict:
        """
        Navigate one host through Navigator's browser mode and build an index
        entry. Saves a PNG when in capture mode and fingerprints the live page.
        """
        filename = f"{_safe_name(host)}.png"
        filepath = (os.path.join(self.images_dir, filename)
                    if (self.capture and self.images_dir) else None)
        js_paths = self._detector.js_probe_paths() if self._detector else None

        ev = await nav.browse_host(
            host,
            screenshot_path=filepath,
            full_page=self.full_page,
            js_paths=js_paths,
            viewport=(self.width, self.height),
        )

        entry: Dict = {
            'input': host,
            'url': ev.get('url'),
            'final_url': ev.get('final_url'),
            'status': ev.get('status'),
            'title': ev.get('title'),
            'server': ev.get('server'),
            'technologies': None,
            # Stored as a URL-style relative path (forward slashes) since the
            # report gallery uses it directly as an <img src>.
            'screenshot': (f"{IMAGES_SUBDIR}/{filename}"
                           if (self.capture and ev.get('screenshot')) else None),
            'error': ev.get('error'),
            'timestamp': ev.get('timestamp', time.time()),
        }

        # Technology fingerprinting from the LIVE page evidence (rendered HTML,
        # headers, cookies, real script URLs, meta tags and window.* globals).
        if self._detector is not None and ev.get('status') is not None:
            try:
                loop = asyncio.get_event_loop()
                techs = await loop.run_in_executor(
                    None, self._detector.detect_rich, host, ev)
                entry['technologies'] = techs or None
            except Exception:
                entry['technologies'] = None

        return entry

    def _write_index(self, results: List[Dict]) -> None:
        """Merge results into the directory's JSON index (keyed by host)."""
        existing = {r.get('input'): r for r in load_index(self.output_dir)}
        for r in results:
            existing[r.get('input')] = r
        merged = sorted(existing.values(),
                        key=lambda r: (r.get('status') is None, r.get('input', '')))

        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, INDEX_FILENAME)
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(merged, f, indent=2)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to write screenshot index: {e}")


class DeepTechStreamer:
    """
    Stream hosts into browser-grade technology detection as they are discovered,
    so detection runs DURING enumeration (one pass) instead of as a separate
    trailing batch over the full result set.

    Owns a background asyncio loop with a single persistent browser (via
    ``Navigator.browse_host``). ``submit(host)`` is thread-safe and returns
    immediately; ``on_result(entry)`` fires on the background thread per host
    with a result dict (input/status/title/final_url/server/technologies/error).
    Call ``close()`` after enumeration to drain in-flight probes and shut down.
    """

    def __init__(self, concurrency: int = 8, timeout: float = 15.0,
                 logger=None, on_result=None, detect_tech: bool = True):
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.logger = logger
        self.on_result = on_result
        # Technology fingerprinting is the expensive part (JS-global probing +
        # rule matching). Skip it unless the caller actually wants tech, so
        # --deep-detect without --tech only confirms liveness/title.
        self.detect_tech = detect_tech
        self._loop = None
        self._thread = None
        self._nav = None
        self._sem = None
        self._detector = None
        self._js_paths = None
        self._ready = threading.Event()
        self._ok = False
        self._closed = False
        self._force = False
        self._pending = set()
        self._lock = threading.Lock()

    def start(self) -> bool:
        """Launch the background loop + browser. Returns True on success."""
        _quiet_asyncio_connlost_noise()
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._thread.start()
        self._ready.wait()
        if self._ok:
            with _ACTIVE_STREAMERS_LOCK:
                _ACTIVE_STREAMERS.add(self)
        return self._ok

    @staticmethod
    def _loop_exc_handler(loop, context):
        # Drop the noise produced when probes are cancelled mid-navigation on a
        # force shutdown: Playwright rejects in-flight protocol futures with
        # TargetClosedError, and abandoned ones log "exception was never
        # retrieved" at GC (routed here via Future.__del__). Real errors pass on.
        exc = context.get('exception')
        if exc is not None and exc.__class__.__name__ == 'TargetClosedError':
            return
        if 'never retrieved' in context.get('message', ''):
            return
        loop.default_exception_handler(context)

    def _thread_main(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.set_exception_handler(self._loop_exc_handler)
        try:
            self._loop.run_until_complete(self._startup())
            self._ok = True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Deep tech browser failed to start: {e}")
            self._ok = False
            self._ready.set()
            try:
                self._loop.run_until_complete(self._nav.close_browser())
            except Exception:
                pass
            try:
                self._loop.close()
            except Exception:
                pass
            return
        self._ready.set()
        self._loop.run_forever()
        # Loop stopped -> tear the browser down. close_browser() (browser.close +
        # pw.stop) is the essential step that lets the Node driver exit cleanly.
        try:
            self._loop.run_until_complete(self._nav.close_browser())
        except Exception:
            pass
        # Briefly flush the proactor's pending connection-lost callbacks so
        # Playwright's pipe transports close cleanly (avoids "unclosed transport"
        # deallocator tracebacks at GC).
        try:
            self._loop.run_until_complete(asyncio.sleep(0.05 if self._force else 0.3))
        except Exception:
            pass
        # On a graceful close, join the default executor (in-flight detect_rich)
        # and async generators. The force path (Ctrl+C) SKIPS this — abandoning
        # that work is what makes the shutdown feel immediate.
        if not self._force:
            try:
                self._loop.run_until_complete(self._loop.shutdown_default_executor())
            except Exception:
                pass
            try:
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            except Exception:
                pass
        try:
            self._loop.close()
        except Exception:
            pass

    async def _startup(self):
        if __package__:
            from .detector import Detector
        else:
            from detector import Detector
        self._sem = asyncio.Semaphore(self.concurrency)
        if self.detect_tech:
            try:
                self._detector = Detector(logger=self.logger, enable_tls_check=False)
                self._js_paths = self._detector.js_probe_paths()
            except Exception:
                self._detector = None
                self._js_paths = None
        self._nav = Navigator(timeout=self.timeout, logger=self.logger)
        await self._nav.start_browser()

    def submit(self, host: str):
        """Queue a host for deep detection (thread-safe, non-blocking)."""
        if not self._ok or self._loop is None:
            return
        host = (host or '').strip().lower()
        if not host:
            return
        self._loop.call_soon_threadsafe(self._schedule, host)

    def _schedule(self, host: str):
        task = self._loop.create_task(self._probe(host))
        with self._lock:
            self._pending.add(task)
        task.add_done_callback(self._task_done)

    def _task_done(self, task):
        with self._lock:
            self._pending.discard(task)
        # Retrieve any exception so a cancelled/failed probe (e.g. the browser
        # closing mid-navigation on Ctrl+C) doesn't log "exception was never
        # retrieved" during shutdown.
        if not task.cancelled():
            try:
                task.exception()
            except Exception:
                pass

    async def _probe(self, host: str):
        async with self._sem:
            try:
                ev = await self._nav.browse_host(host, js_paths=self._js_paths)
            except Exception as e:
                ev = {'input': host, 'status': None, 'title': None,
                      'final_url': None, 'server': None,
                      'error': str(e).splitlines()[0] if str(e) else 'failed'}
        techs = None
        if self._detector is not None and ev.get('status') is not None:
            try:
                loop = asyncio.get_event_loop()
                techs = await loop.run_in_executor(
                    None, self._detector.detect_rich, host, ev)
            except Exception:
                techs = None
        # Scheme that actually responded (https tried first, then http), taken
        # from the final URL (or the requested one) so callers can show it.
        scheme_src = ev.get('final_url') or ev.get('url') or ''
        protocol = scheme_src.split('://', 1)[0].lower() if '://' in scheme_src else None
        entry = {
            'input': host,
            'status': ev.get('status'),
            'protocol': protocol,
            'title': ev.get('title'),
            'final_url': ev.get('final_url'),
            'server': ev.get('server'),
            'technologies': techs or None,
            'error': ev.get('error'),
        }
        if self.on_result:
            try:
                self.on_result(entry)
            except Exception:
                pass

    def close(self, drain: bool = True):
        """
        Stop the streamer and tear the browser down, then join the background
        thread so the Playwright browser/driver is fully closed BEFORE this
        returns (an abrupt process exit while the browser is open yields an EPIPE
        crash from the Node driver).

        ``drain`` (default) waits for in-flight probes to finish. ``drain=False``
        is the Ctrl+C path: it cancels in-flight probes and stops the loop now,
        so ``_thread_main`` closes the browser immediately. It is safe to call
        after an interrupted graceful close — a force call always re-stops the
        loop and re-joins the thread, never a silent no-op.
        """
        if self._loop is None or not self._ok:
            return
        if self._thread is None or not self._thread.is_alive():
            with _ACTIVE_STREAMERS_LOCK:
                _ACTIVE_STREAMERS.discard(self)
            return  # already fully torn down

        if not drain:
            self._force = True

        # Schedule the shutdown coroutine once. Graceful: drain in-flight probes,
        # then close the browser, then stop. Force (Ctrl+C): cancel the probes
        # (abandoning any in-flight tech detection so we don't wait on it), close
        # the browser, stop — fast but still a clean Playwright shutdown.
        if not self._closed:
            self._closed = True
            force = not drain

            async def _shutdown():
                try:
                    if force:
                        with self._lock:
                            for t in list(self._pending):
                                t.cancel()
                        await self._nav.close_browser()
                    else:
                        while True:
                            with self._lock:
                                pend = list(self._pending)
                            if not pend:
                                break
                            await asyncio.gather(*pend, return_exceptions=True)
                        await self._nav.close_browser()
                finally:
                    self._loop.stop()

            try:
                self._loop.call_soon_threadsafe(
                    lambda: self._loop.create_task(_shutdown()))
            except RuntimeError:
                return  # loop already gone
        elif not drain:
            # A graceful drain was already running and got interrupted (Ctrl+C):
            # cancel its probes and close the browser now so it stops promptly.
            def _escalate():
                with self._lock:
                    for t in list(self._pending):
                        t.cancel()
                self._loop.create_task(self._nav.close_browser())
            try:
                self._loop.call_soon_threadsafe(_escalate)
            except RuntimeError:
                pass

        # Wait for the browser/driver to actually close. This join keeps the
        # process alive long enough for a clean Playwright shutdown.
        self._thread.join(timeout=30 if drain else 6)
        with _ACTIVE_STREAMERS_LOCK:
            _ACTIVE_STREAMERS.discard(self)
