import os
import tempfile
import time
from backend.auth_service import AuthService


def make_service(ttl=5):
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    service = AuthService(tmp.name, 'test-secret', otp_ttl_minutes=ttl)
    return service, tmp.name


def cleanup(service, path):
    service.conn.close()
    os.unlink(path)


def test_duplicate_mobile_registration_rejected():
    service, path = make_service()
    try:
      s1, _ = service.register_start('Alice', '9999999999', 'Test@1234')
      s2, _ = service.register_start('Alice', '9999999999', 'Test@1234')
      assert s1 == 201
      assert s2 == 409
    finally:
      cleanup(service, path)


def test_login_blocked_before_otp_verification():
    service, path = make_service()
    try:
      service.register_start('Alice', '8888888888', 'Test@1234')
      status, payload = service.login('8888888888', 'Test@1234')
      assert status == 401
      assert payload['error'] == 'Invalid credentials.'
    finally:
      cleanup(service, path)


def test_wrong_otp_and_expiry_behavior():
    service, path = make_service(ttl=0.0005)
    try:
      _, reg = service.register_start('Alice', '7777777777', 'Test@1234')
      status_wrong, _ = service.verify_otp('7777777777', '000000')
      assert status_wrong == 400
      time.sleep(0.08)
      status_expired, _ = service.verify_otp('7777777777', reg['mockOtp'])
      assert status_expired == 400
    finally:
      cleanup(service, path)


def test_successful_login_after_verification():
    service, path = make_service()
    try:
      _, reg = service.register_start('Alice', '6666666666', 'Test@1234')
      verify_status, _ = service.verify_otp('6666666666', reg['mockOtp'])
      login_status, payload = service.login('6666666666', 'Test@1234')
      assert verify_status == 200
      assert login_status == 200
      assert isinstance(payload['token'], str)
    finally:
      cleanup(service, path)
