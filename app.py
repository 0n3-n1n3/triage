#!/usr/bin/env python3
"""A dependency-free, localhost-only dashboard. Start with: python app.py"""
from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import json
import secrets
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from core import __version__, config
from core.analysis import analyze
from demo import sample_emails

ROOT = Path(__file__).resolve().parent
MAX_FILES = 25
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_BATCH_BYTES = 20 * 1024 * 1024
MAX_REQUEST_BYTES = 29 * 1024 * 1024
STATIC = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/static/styles.css': ('styles.css', 'text/css; charset=utf-8'),
    '/static/app.js': ('app.js', 'text/javascript; charset=utf-8'),
    '/static/favicon.svg': ('favicon.svg', 'image/svg+xml'),
}


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address):
        super().__init__(address, DashboardHandler)
        self.token = secrets.token_urlsafe(32)
        self.workers = threading.BoundedSemaphore(2)
        port = self.server_address[1]
        self.hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
        self.origins = {f'http://{host}' for host in self.hosts}


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = 'PhishTriage'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, fmt, *args):
        # Never log email bodies, filenames, authentication tokens, or query strings.
        pass

    def send_data(self, status, body, content_type='application/json; charset=utf-8'):
        try:
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            self.send_header('Content-Security-Policy',
                             "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "img-src 'self'; connect-src 'self'; font-src 'self'; "
                             "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    def json_response(self, status, data):
        self.send_data(status, json.dumps(data, ensure_ascii=True, allow_nan=False).encode('utf-8'))

    def check_origin(self, *, token=False):
        # Host allowlisting blocks DNS rebinding; the token protects state-changing
        # requests even when a client sends no Origin header. Never enable CORS.
        if self.headers.get('Host', '').lower() not in self.server.hosts:
            self.json_response(403, {'error': 'Open this dashboard using localhost or 127.0.0.1.'})
            return False
        origin = self.headers.get('Origin')
        if origin is not None and origin not in self.server.origins:
            self.json_response(403, {'error': 'Cross-origin requests are not allowed.'})
            return False
        if self.headers.get('Sec-Fetch-Site') not in (None, 'none', 'same-origin'):
            self.json_response(403, {'error': 'Cross-origin requests are not allowed.'})
            return False
        if token and not hmac.compare_digest(self.headers.get('X-Workspace-Token', '').encode('utf-8'), self.server.token.encode('ascii')):
            self.json_response(403, {'error': 'Workspace session expired. Refresh the page.'})
            return False
        return True

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.check_origin():
            return
        try:
            path = urlsplit(self.path).path
            if path in STATIC:
                filename, content_type = STATIC[path]
                self.send_data(200, (ROOT / 'static' / filename).read_bytes(), content_type)
            elif path == '/api/session':
                self.json_response(200, {
                    'token': self.server.token, 'version': __version__,
                    'limits': {'files': MAX_FILES, 'file_bytes': MAX_FILE_BYTES, 'batch_bytes': MAX_BATCH_BYTES},
                })
            elif path == '/api/demo':
                if not self.check_origin(token=True):
                    return
                if not self.server.workers.acquire(blocking=False):
                    self.json_response(503, {'error': 'The analyzer is busy. Please try again.'})
                    return
                try:
                    self.json_response(200, analyze(sample_emails(), demo=True))
                finally:
                    self.server.workers.release()
            else:
                self.json_response(404, {'error': 'This page does not exist.'})
        except Exception:
            self.json_response(500, {'error': 'Unable to load the workspace. Check your config files and restart.'})

    def do_POST(self):
        if not self.check_origin(token=True):
            return
        if urlsplit(self.path).path != '/api/analyze':
            self.json_response(404, {'error': 'This endpoint does not exist.'})
            return
        if self.headers.get_content_type() != 'application/json':
            self.json_response(415, {'error': 'Send email files as a JSON request.'})
            return
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
            self.json_response(400, {'error': 'A single Content-Length header is required.'})
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_REQUEST_BYTES:
            self.json_response(413, {'error': 'This batch is too large. Limit uploads to 20 MiB total.'})
            return
        if not self.server.workers.acquire(blocking=False):
            self.json_response(503, {'error': 'The analyzer is busy. Please try again.'})
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError('The upload was interrupted. Please try again.')
            payload = json.loads(body)
            if not isinstance(payload, dict) or set(payload) != {'files'}:
                raise ValueError('The request must contain only a files array.')
            uploaded = payload['files']
            if not isinstance(uploaded, list) or not 1 <= len(uploaded) <= MAX_FILES:
                raise ValueError(f'Choose between 1 and {MAX_FILES} email files.')
            files, total = [], 0
            for item in uploaded:
                if not isinstance(item, dict) or not isinstance(item.get('name'), str) or not isinstance(item.get('data'), str):
                    raise ValueError('Each file needs a name and base64-encoded content.')
                name = item['name'].replace('\\', '/').rsplit('/', 1)[-1]
                if len(name) > 180 or any(ord(c) < 32 for c in name) or not name.lower().endswith('.eml'):
                    raise ValueError('Use .eml filenames of 180 characters or fewer.')
                if len(item['data']) > ((MAX_FILE_BYTES + 2) // 3) * 4:
                    raise ValueError(f'{name}: each email must be 10 MiB or smaller.')
                try:
                    raw = base64.b64decode(item['data'], validate=True)
                except (ValueError, binascii.Error):
                    raise ValueError(f'{name}: the file could not be decoded.') from None
                if not raw or len(raw) > MAX_FILE_BYTES:
                    raise ValueError(f'{name}: use a nonempty email no larger than 10 MiB.')
                total += len(raw)
                if total > MAX_BATCH_BYTES:
                    raise ValueError('The combined batch must be 20 MiB or smaller.')
                files.append((name, raw))
            # The client cannot opt into demo trust or provide its own analysis.
            self.json_response(200, analyze(files, demo=False))
        except (ValueError, UnicodeError) as exc:
            self.json_response(400, {'error': str(exc)[:300]})
        except socket.timeout:
            self.json_response(408, {'error': 'The upload timed out. Please try a smaller batch.'})
        except Exception:
            self.json_response(500, {'error': 'Analysis could not finish. Check your configuration and try again.'})
        finally:
            self.server.workers.release()


def main():
    parser = argparse.ArgumentParser(description='Start the local Phish Triage dashboard (Python 3.10+).')
    parser.add_argument('--port', type=int, default=8000, help='Local port (default: 8000).')
    parser.add_argument('--open', action='store_true', help='Open the dashboard in your default browser.')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('--port must be between 1 and 65535')
    try:
        for name in sorted(config.NAMES):
            config.load(name)
        server = DashboardServer(('127.0.0.1', args.port))
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Could not start: {exc}\nTry another port with --port 8001.\n')
    url = f'http://127.0.0.1:{args.port}'
    print(f'\n  PHISH TRIAGE  /  {__version__}\n\n  Open {url}\n'
          '  Local rules only. No external services.\n  Press Ctrl+C to stop.\n', flush=True)
    if args.open:
        timer = threading.Timer(0.5, webbrowser.open, args=(url,))
        timer.daemon = True
        timer.start()
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print('\nWorkspace stopped.')
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
