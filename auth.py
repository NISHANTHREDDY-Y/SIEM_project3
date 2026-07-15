from functools import wraps

from flask import g, redirect, request, session, url_for
from werkzeug.security import check_password_hash

from database import get_user_account, insert_audit_log, touch_last_login

ROLE_ORDER = {
    "Viewer": 1,
    "SOC Analyst": 2,
    "Administrator": 3,
}


def load_current_user():
    username = session.get("username")
    if not username:
        g.current_user = None
        return None

    user = get_user_account(username)
    if user is None:
        session.clear()
        g.current_user = None
        return None

    g.current_user = dict(user)
    return g.current_user


def authenticate_user(username, password):
    user = get_user_account(username)
    if user is None:
        return None
    if not user["active"]:
        return None
    if not check_password_hash(user["password_hash"], password or ""):
        return None
    return dict(user)


def login_user(user, ip_address=""):
    session["username"] = user["username"]
    session["role"] = user["role"]
    touch_last_login(user["username"])
    insert_audit_log(user["username"], "Login", "Authentication", f"Role={user['role']}", ip_address, "SUCCESS")


def logout_user():
    user = g.get("current_user") or {}
    username = user.get("username", "Unknown")
    insert_audit_log(username, "Logout", "Authentication", "User logged out", request.remote_addr or "", "SUCCESS")
    session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("current_user") is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = g.get("current_user")
            if user is None:
                return redirect(url_for("login", next=request.path))
            if user["role"] not in roles:
                insert_audit_log(user["username"], "Denied", "Authorization", f"Required={','.join(roles)}", request.remote_addr or "", "DENIED")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def can_manage():
    user = g.get("current_user") or {}
    return user.get("role") in {"Administrator", "SOC Analyst"}


def can_admin():
    user = g.get("current_user") or {}
    return user.get("role") == "Administrator"
