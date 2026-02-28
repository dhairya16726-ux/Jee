import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import crypt
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque


def utc_now():
    return datetime.now(timezone.utc)


def to_iso(dt):
    return dt.isoformat()


def from_iso(value):
    return datetime.fromisoformat(value)


class AuthService:
    def __init__(self, db_path: str, jwt_secret: str, otp_ttl_minutes: int = 5):
        os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.jwt_secret = jwt_secret
        self.otp_ttl_minutes = otp_ttl_minutes
        self.rate_buckets = defaultdict(deque)
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              mobileNo TEXT NOT NULL UNIQUE,
              passwordHash TEXT NOT NULL,
              isVerified INTEGER NOT NULL DEFAULT 0,
              createdAt TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS otp_codes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              mobileNo TEXT NOT NULL,
              otpHash TEXT NOT NULL,
              expiresAt TEXT NOT NULL,
              createdAt TEXT NOT NULL,
              consumedAt TEXT,
              attemptCount INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS otp_resend_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              mobileNo TEXT NOT NULL,
              requestedAt TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def sanitize(self, value):
        if not isinstance(value, str):
            return ''
        return value.strip().replace('<', '').replace('>', '')

    def valid_mobile(self, mobile):
        return mobile.isdigit() and len(mobile) == 10

    def password_errors(self, password):
        if not isinstance(password, str):
            return ['Password is required.']
        errors = []
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if not any(c.isupper() for c in password):
            errors.append('Password must include an uppercase letter.')
        if not any(c.islower() for c in password):
            errors.append('Password must include a lowercase letter.')
        if not any(c.isdigit() for c in password):
            errors.append('Password must include a number.')
        if not any(c in "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?" for c in password):
            errors.append('Password must include a special character.')
        return errors

    def _hash_password(self, password):
        salt = crypt.mksalt(crypt.METHOD_BLOWFISH)
        return crypt.crypt(password, salt)

    def _verify_password(self, password, hashed):
        return crypt.crypt(password, hashed) == hashed

    def _hash_otp(self, otp):
        return hashlib.sha256(otp.encode()).hexdigest()

    def _rate_limit(self, key, max_attempts, window_seconds):
        now = time.time()
        bucket = self.rate_buckets[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= max_attempts:
            return False
        bucket.append(now)
        return True

    def _generate_token(self, payload):
        header = {'alg': 'HS256', 'typ': 'JWT'}
        import base64

        def b64url(data):
            return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

        p = payload.copy()
        p['exp'] = int(time.time()) + 3600
        head = b64url(header)
        body = b64url(p)
        signature = hmac.new(self.jwt_secret.encode(), f'{head}.{body}'.encode(), hashlib.sha256).digest()
        sig = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        return f'{head}.{body}.{sig}'

    def _record_otp(self, mobile_no):
        otp = f"{secrets.randbelow(1000000):06d}"
        now = utc_now()
        expiry = now + timedelta(minutes=self.otp_ttl_minutes)
        self.conn.execute(
            'INSERT INTO otp_codes (mobileNo, otpHash, expiresAt, createdAt, consumedAt, attemptCount) VALUES (?, ?, ?, ?, NULL, 0)',
            (mobile_no, self._hash_otp(otp), to_iso(expiry), to_iso(now)),
        )
        self.conn.execute(
            'INSERT INTO otp_resend_log (mobileNo, requestedAt) VALUES (?, ?)',
            (mobile_no, to_iso(now)),
        )
        self.conn.commit()
        return otp

    def register_start(self, name, mobile_no, password):
        name = self.sanitize(name)
        mobile_no = self.sanitize(mobile_no)

        if not name:
            return 400, {'error': 'Invalid input.'}
        if not self.valid_mobile(mobile_no):
            return 400, {'error': 'Invalid input.'}
        errors = self.password_errors(password)
        if errors:
            return 400, {'error': 'Invalid input.', 'details': errors}

        if self.conn.execute('SELECT id FROM users WHERE mobileNo = ?', (mobile_no,)).fetchone():
            return 409, {'error': 'Unable to process registration.'}

        self.conn.execute(
            'INSERT INTO users (name, mobileNo, passwordHash, isVerified, createdAt) VALUES (?, ?, ?, 0, ?)',
            (name, mobile_no, self._hash_password(password), to_iso(utc_now())),
        )
        self.conn.commit()
        otp = self._record_otp(mobile_no)
        return 201, {'message': 'Registration started. Verify OTP to activate account.', 'mockOtp': otp}

    def resend_otp(self, mobile_no):
        mobile_no = self.sanitize(mobile_no)
        if not self.valid_mobile(mobile_no):
            return 400, {'error': 'Invalid input.'}

        user = self.conn.execute('SELECT isVerified FROM users WHERE mobileNo = ?', (mobile_no,)).fetchone()
        if not user or user['isVerified'] == 1:
            return 400, {'error': 'Unable to process request.'}

        window_start = to_iso(utc_now() - timedelta(minutes=15))
        count = self.conn.execute(
            'SELECT COUNT(*) as c FROM otp_resend_log WHERE mobileNo = ? AND requestedAt >= ?',
            (mobile_no, window_start),
        ).fetchone()['c']
        if count >= 3:
            return 429, {'error': 'Too many OTP resend requests. Try later.'}

        otp = self._record_otp(mobile_no)
        return 200, {'message': 'OTP resent.', 'mockOtp': otp}

    def verify_otp(self, mobile_no, otp):
        if not self._rate_limit(f'otp:{mobile_no}', 10, 15 * 60):
            return 429, {'error': 'Too many attempts. Please try again later.'}

        mobile_no = self.sanitize(mobile_no)
        otp = self.sanitize(otp)
        if not self.valid_mobile(mobile_no) or not (otp.isdigit() and len(otp) == 6):
            return 400, {'error': 'Invalid input.'}

        user = self.conn.execute('SELECT id, isVerified FROM users WHERE mobileNo = ?', (mobile_no,)).fetchone()
        if not user or user['isVerified'] == 1:
            return 400, {'error': 'Unable to verify OTP.'}

        otp_row = self.conn.execute(
            'SELECT * FROM otp_codes WHERE mobileNo = ? AND consumedAt IS NULL ORDER BY createdAt DESC LIMIT 1',
            (mobile_no,),
        ).fetchone()
        if not otp_row or from_iso(otp_row['expiresAt']) < utc_now():
            return 400, {'error': 'Unable to verify OTP.'}

        if self._hash_otp(otp) != otp_row['otpHash']:
            self.conn.execute('UPDATE otp_codes SET attemptCount = attemptCount + 1 WHERE id = ?', (otp_row['id'],))
            self.conn.commit()
            return 400, {'error': 'Unable to verify OTP.'}

        now = to_iso(utc_now())
        self.conn.execute('UPDATE otp_codes SET consumedAt = ? WHERE id = ?', (now, otp_row['id']))
        self.conn.execute('UPDATE users SET isVerified = 1 WHERE id = ?', (user['id'],))
        self.conn.commit()
        return 200, {'message': 'Account verified successfully.'}

    def login(self, mobile_no, password):
        if not self._rate_limit(f'login:{mobile_no}', 10, 15 * 60):
            return 429, {'error': 'Too many attempts. Please try again later.'}

        mobile_no = self.sanitize(mobile_no)
        if not self.valid_mobile(mobile_no) or not isinstance(password, str):
            return 400, {'error': 'Invalid credentials.'}

        user = self.conn.execute('SELECT * FROM users WHERE mobileNo = ?', (mobile_no,)).fetchone()
        if not user or user['isVerified'] != 1:
            return 401, {'error': 'Invalid credentials.'}

        if not self._verify_password(password, user['passwordHash']):
            return 401, {'error': 'Invalid credentials.'}

        token = self._generate_token({'sub': user['id'], 'mobileNo': user['mobileNo']})
        return 200, {'token': token}
