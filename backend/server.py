import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
try:
    from backend.auth_service import AuthService
except ModuleNotFoundError:
    from auth_service import AuthService

PORT = int(os.getenv('PORT', '4000'))
DB_PATH = os.getenv('SQLITE_DB_PATH', './backend/data/auth.db')
JWT_SECRET = os.getenv('JWT_SECRET', 'dev-secret')

service = AuthService(DB_PATH, JWT_SECRET)


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        if self.path == '/health':
            return self._json(200, {'ok': True})
        self._json(404, {'error': 'Not found'})

    def do_POST(self):
        parsed = urlparse(self.path)
        content_len = int(self.headers.get('Content-Length', '0'))
        body = json.loads(self.rfile.read(content_len) or '{}')

        routes = {
            '/auth/register/start': lambda: service.register_start(body.get('name'), body.get('mobileNo'), body.get('password')),
            '/auth/register/verify-otp': lambda: service.verify_otp(body.get('mobileNo', ''), body.get('otp', '')),
            '/auth/register/resend-otp': lambda: service.resend_otp(body.get('mobileNo', '')),
            '/auth/login': lambda: service.login(body.get('mobileNo', ''), body.get('password')),
        }

        if parsed.path not in routes:
            return self._json(404, {'error': 'Not found'})

        status, payload = routes[parsed.path]()
        self._json(status, payload)


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), Handler)
    print(f'Backend listening on http://localhost:{PORT}')
    server.serve_forever()
