"""
app.py
ชั้น routes ของเว็บ (slim) — รับ request จากเบราว์เซอร์ แล้วเรียก accounts.py
หลังจาก refactor ใน EP.7 ไฟล์นี้ "บาง" ลงมาก เหลือแค่เรื่อง web เท่านั้น
logic ทั้งหมดย้ายไปอยู่ใน accounts.py / security.py / storage.py
"""

import os
import secrets

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import accounts

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32)


def _get_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _validate_csrf_token() -> bool:
    session_token = session.get("csrf_token")
    form_token = request.form.get("csrf_token", "")
    return bool(
        session_token
        and form_token
        and secrets.compare_digest(session_token, form_token)
    )


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": _get_csrf_token}


@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not _validate_csrf_token():
            flash("คำขอไม่ถูกต้อง", "error")
            return redirect(url_for("register"))
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        try:
            accounts.register_user(username, password)
            flash("สมัครสมาชิกสำเร็จ เข้าสู่ระบบได้เลย", "success")
            return redirect(url_for("login"))
        except accounts.AccountError as e:
            flash(str(e), "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not _validate_csrf_token():
            flash("คำขอไม่ถูกต้อง", "error")
            return redirect(url_for("login"))
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if accounts.authenticate(username, password):
            session["username"] = username.strip()
            return redirect(url_for("dashboard"))
        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", "error")
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])


@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))
    if not _validate_csrf_token():
        flash("คำขอไม่ถูกต้อง", "error")
        return redirect(url_for("dashboard"))
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    try:
        accounts.change_password(session["username"], old_password, new_password)
        flash("เปลี่ยนรหัสผ่านสำเร็จ", "success")
    except accounts.AccountError as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
