"""
test_integration.py
Integration test ของเว็บ uncle-auth — ทดสอบผ่าน Flask test client
(เหมือนเปิดเบราว์เซอร์จริง แต่ทำอัตโนมัติ)

สถานะตั้งต้น (หลังจบ EP.7): ต้องเขียวครบ 10 ตัว
รัน:  pytest -v
"""

import importlib
import os
import re
import sys

import pytest

# ให้ test มองเห็น module ในโฟลเดอร์โปรเจกต์ (ขึ้นไป 1 ระดับ)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import storage  # noqa: E402
import accounts  # noqa: E402
import app as app_module  # noqa: E402


@pytest.fixture
def client(tmp_path):
    """
    สร้าง test client ใหม่ทุกเทสต์ พร้อมไฟล์ข้อมูลชั่วคราว
    (แต่ละเทสต์เริ่มจากฐานข้อมูลว่าง ไม่ปนกัน)
    """
    test_db = tmp_path / "users.json"
    storage.DB_PATH = str(test_db)

    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def _register(client, username, password):
    res = client.get("/register")
    csrf_token = _extract_csrf_token(res.get_data(as_text=True))
    return client.post(
        "/register",
        data={"username": username, "password": password, "csrf_token": csrf_token},
        follow_redirects=True,
    )


def _login(client, username, password):
    res = client.get("/login")
    csrf_token = _extract_csrf_token(res.get_data(as_text=True))
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf_token},
        follow_redirects=True,
    )


def _extract_csrf_token(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF token not found in form"
    return match.group(1)


# ---------- register ----------

def test_register_new_user_succeeds(client):
    res = _register(client, "somchai", "pass1234")
    assert res.status_code == 200
    assert "สมัครสมาชิกสำเร็จ" in res.get_data(as_text=True)


def test_register_duplicate_username_fails(client):
    _register(client, "somchai", "pass1234")
    res = _register(client, "somchai", "other999")
    assert "ถูกใช้แล้ว" in res.get_data(as_text=True)


def test_register_empty_username_fails(client):
    res = _register(client, "", "pass1234")
    assert "กรุณากรอกชื่อผู้ใช้" in res.get_data(as_text=True)


def test_password_is_hashed_not_plaintext(client):
    _register(client, "somchai", "pass1234")
    users = storage.load_users()
    assert users["somchai"]["password_hash"] != "pass1234"
    assert len(users["somchai"]["password_hash"]) > 20


# ---------- login ----------

def test_login_with_correct_password_succeeds(client):
    _register(client, "somchai", "pass1234")
    res = _login(client, "somchai", "pass1234")
    assert "สวัสดี somchai" in res.get_data(as_text=True)


def test_login_with_wrong_password_fails(client):
    _register(client, "somchai", "pass1234")
    res = _login(client, "somchai", "wrongpass")
    assert "ไม่ถูกต้อง" in res.get_data(as_text=True)


def test_login_nonexistent_user_fails(client):
    res = _login(client, "ghost", "whatever1")
    assert "ไม่ถูกต้อง" in res.get_data(as_text=True)


def test_login_without_csrf_token_is_rejected(client):
    _register(client, "somchai", "pass1234")
    res = client.post(
        "/login",
        data={"username": "somchai", "password": "pass1234"},
        follow_redirects=True,
    )
    assert "คำขอไม่ถูกต้อง" in res.get_data(as_text=True)


# ---------- protected page ----------

def test_dashboard_requires_login(client):
    res = client.get("/dashboard", follow_redirects=True)
    assert "เข้าสู่ระบบ" in res.get_data(as_text=True)
    assert "สวัสดี" not in res.get_data(as_text=True)


# ---------- change password ----------

def test_change_password_with_correct_old_succeeds(client):
    _register(client, "somchai", "pass1234")
    _login(client, "somchai", "pass1234")
    dashboard = client.get("/dashboard")
    csrf_token = _extract_csrf_token(dashboard.get_data(as_text=True))
    res = client.post(
        "/change-password",
        data={
            "old_password": "pass1234",
            "new_password": "newpass99",
            "csrf_token": csrf_token,
        },
        follow_redirects=True,
    )
    assert "เปลี่ยนรหัสผ่านสำเร็จ" in res.get_data(as_text=True)
    # login ด้วยรหัสใหม่ได้
    client.get("/logout")
    res2 = _login(client, "somchai", "newpass99")
    assert "สวัสดี somchai" in res2.get_data(as_text=True)


def test_change_password_with_wrong_old_fails(client):
    _register(client, "somchai", "pass1234")
    _login(client, "somchai", "pass1234")
    dashboard = client.get("/dashboard")
    csrf_token = _extract_csrf_token(dashboard.get_data(as_text=True))
    res = client.post(
        "/change-password",
        data={
            "old_password": "WRONG",
            "new_password": "newpass99",
            "csrf_token": csrf_token,
        },
        follow_redirects=True,
    )
    assert "รหัสผ่านเดิมไม่ถูกต้อง" in res.get_data(as_text=True)
