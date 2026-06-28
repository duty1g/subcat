"""
Report server for subcat screenshots.

Serves a gowitness-style gallery from the screenshot base directory
(``~/.subcat/screenshots``) using only the Python standard library (no Flask).
Scans live as one sub-directory per scan id; the single-page React UI is served
at ``/`` and consumes a small JSON API from this backend:

    GET /api/scans            -> list of scans (id, domain, created, counts)
    GET /api/scan/<id>        -> the scan's result rows
    GET /scan/<id>/screenshots/<file>  -> a screenshot PNG
    GET /icons/<file>         -> a Wappalyzer technology icon

No static HTML is written to disk — everything is served live from here.

The look is a faithful port of the gowitness v3 web UI (shadcn/ui dark theme,
zinc/240-hue tokens): card screenshot, status badge top-right, footer with
title/URL + relative time and a row of technology icons, a toolbar with a
technologies filter, per-status-code toggles and a "show failed" switch, and a
page-size + numbered pager.
"""
import json
import os
import posixpath
import threading
import webbrowser
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, unquote

if __package__:
    from .display import ANSI
    from .screenshot import (INDEX_FILENAME, IMAGES_SUBDIR,
                             load_index, list_scans, is_scan_dir)
else:
    from display import ANSI
    from screenshot import (INDEX_FILENAME, IMAGES_SUBDIR,
                           load_index, list_scans, is_scan_dir)


# ---------------------------------------------------------------------------
# Front-end: a vendored single-file React/Vite/shadcn bundle (built from web/).
# The same artifact powers the live server (it fetches /api/scans + /api/scan/<id>)
# and the standalone report (data injected inline as window.__SUBCAT__).
# ---------------------------------------------------------------------------

_UI_PATH = os.path.join(os.path.dirname(__file__), 'assets', 'report_ui.html')


def _load_ui() -> str:
    """Load the built report UI, or a helpful placeholder if it isn't built."""
    try:
        with open(_UI_PATH, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return ("<!doctype html><meta charset=utf-8>"
                "<body style=\"font-family:system-ui,sans-serif;background:#0a0a0a;"
                "color:#e6edf3;padding:48px;line-height:1.6\">"
                "<h2>subcat report UI is not built</h2>"
                "<p>Build it once: <code>cd subcat/ui &amp;&amp; npm install &amp;&amp; "
                "npm run build</code>, then copy <code>subcat/ui/dist/index.html</code> to "
                "<code>subcat/assets/report_ui.html</code>.</p></body>")


# Served verbatim by the live server; reused as the template for the static report.
GALLERY_HTML = _load_ui()

# Vendored Wappalyzer icon set (same icons gowitness uses), aligned 1:1 with the
# 'icon' field in fingerprints.json (see subcat/ui/sync_icons.py). Served by the
# report server at /icons/<file>.
_ICONS_DIR = os.path.join(os.path.dirname(__file__), 'assets', 'icons')


def _build_scan_map(path: str):
    """
    Return (scans_map, metas).

    scans_map: {scan_id -> absolute scan directory}
    metas:     list of metadata dicts (for /api/scans)

    Works whether ``path`` is a base directory holding many scans or a single
    scan directory (served as a one-entry map).
    """
    path = os.path.abspath(path)
    if is_scan_dir(path):
        sid = os.path.basename(os.path.normpath(path)) or 'scan'
        metas = list_scans(os.path.dirname(path))
        meta = next((m for m in metas if m['id'] == sid), None)
        if meta is None:
            results = load_index(path)
            meta = {'id': sid, 'domain': sid, 'created': None,
                    'total': len(results),
                    'alive': sum(1 for r in results if r.get('status') is not None)}
        return {sid: path}, [meta]

    metas = list_scans(path)
    scans_map = {m['id']: os.path.join(path, m['id']) for m in metas}
    return scans_map, metas


def _make_handler(scans_map: dict, metas: list):

    class ReportHandler(SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, body: bytes, content_type: str, status: int = 200):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            # Never let a browser serve a stale gallery after the code changes.
            self.send_header('Cache-Control', 'no-store, must-revalidate')
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)

        def do_GET(self):
            path = unquote(urlparse(self.path).path)

            if path in ('/', '/index.html'):
                return self._send(GALLERY_HTML.encode('utf-8'), 'text/html; charset=utf-8')

            if path == '/api/scans':
                return self._send(json.dumps(metas).encode('utf-8'),
                                  'application/json; charset=utf-8')

            if path.startswith('/api/scan/'):
                sid = path[len('/api/scan/'):]
                if sid not in scans_map:
                    return self._send(b'[]', 'application/json; charset=utf-8', 404)
                body = json.dumps(load_index(scans_map[sid])).encode('utf-8')
                return self._send(body, 'application/json; charset=utf-8')

            # Image: /scan/<id>/screenshots/<file>
            if path.startswith('/scan/'):
                rest = path[len('/scan/'):]
                sid, _, sub = rest.partition('/')
                if sid not in scans_map or not sub.startswith(IMAGES_SUBDIR + '/'):
                    return self._send(b'not found', 'text/plain', 404)
                scan_dir = scans_map[sid]
                images_root = os.path.abspath(os.path.join(scan_dir, IMAGES_SUBDIR))
                rel = posixpath.normpath(sub)
                full = os.path.abspath(os.path.join(scan_dir, *rel.split('/')))
                if os.path.commonpath([full, images_root]) != images_root or not os.path.isfile(full):
                    return self._send(b'not found', 'text/plain', 404)
                with open(full, 'rb') as f:
                    return self._send(f.read(), 'image/png')

            # Technology icon: /icons/<filename> (served from the vendored set)
            if path.startswith('/icons/'):
                name = posixpath.basename(path[len('/icons/'):])
                icons_root = os.path.abspath(_ICONS_DIR)
                full = os.path.abspath(os.path.join(_ICONS_DIR, name))
                if os.path.commonpath([full, icons_root]) == icons_root and os.path.isfile(full):
                    ct = 'image/svg+xml' if full.lower().endswith('.svg') else 'image/png'
                    with open(full, 'rb') as f:
                        return self._send(f.read(), ct)
                return self._send(b'not found', 'text/plain', 404)

            return self._send(b'not found', 'text/plain', 404)

    return ReportHandler


def serve(path: str, host: str = '127.0.0.1', port: int = 7171, logger=None,
          open_browser: bool = False, open_path: str = '/', only_scan: str = None) -> None:
    """
    Serve the screenshot gallery for ``path`` (a base dir or a single scan).

    If ``only_scan`` is given, only that scan id is served (the others are
    hidden) and the page opens straight to it.
    """
    path = os.path.abspath(path)

    if not os.path.isdir(path):
        if logger:
            logger.critical(f"Report directory not found: {ANSI.RED}{path}{ANSI.RESET}")
        return

    scans_map, metas = _build_scan_map(path)
    if not scans_map:
        if logger:
            logger.critical(
                f"No scans found in {ANSI.RED}{path}{ANSI.RESET} "
                f"— run a scan with {ANSI.YELLOW}--screenshot{ANSI.RESET} first")
        return

    # Restrict to a single scan id when requested.
    if only_scan:
        if only_scan not in scans_map:
            if logger:
                logger.critical(f"Scan id not found: {ANSI.RED}{only_scan}{ANSI.RESET} in {path}")
            return
        scans_map = {only_scan: scans_map[only_scan]}
        metas = [m for m in metas if m['id'] == only_scan]
        open_path = f"/?scan={only_scan}"

    handler = _make_handler(scans_map, metas)
    try:
        httpd = ThreadingHTTPServer((host, port), handler)
    except OSError as e:
        if logger:
            logger.critical(f"Could not bind {host}:{port} — {e}")
        return

    if logger:
        logger.info(f"Report server running at {ANSI.GREEN}http://{host}:{port}{ANSI.RESET} "
                    f"{ANSI.BRIGHT_BLACK}(Ctrl+C to stop){ANSI.RESET}")

    if open_browser:
        url = f"http://{host}:{port}{open_path}"
        # Open shortly after the server starts listening.
        threading.Timer(0.6, lambda: _try_open(url, logger)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if logger:
            logger.info("Shutting down report server...")
    finally:
        httpd.server_close()


def _try_open(url: str, logger=None) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        if logger:
            logger.debug(f"Could not open browser for {url}")
