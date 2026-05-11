"""
Module 2A — Role-Based Access Control
Roles: viewer < analyst < dev < admin
"""
from functools import wraps
from flask import session, jsonify, request, redirect

# ── Permission matrix ─────────────────────────────────────────────────────────
ROLES = ["viewer", "user", "analyst", "dev", "admin"]

PERMISSIONS = {
    # "user" is the default role assigned on account approval — same capabilities as analyst
    "view_dashboard":   {"viewer", "user", "analyst", "dev", "admin"},
    "run_scan":         {"user", "analyst", "dev", "admin"},
    "download_patch":   {"user", "analyst", "dev", "admin"},
    "manage_projects":  {"user", "dev", "admin"},
    "manage_users":     {"admin"},
    "view_audit":       {"admin"},
    "export_report":    {"user", "analyst", "dev", "admin"},
    "false_positive":   {"user", "analyst", "dev", "admin"},
    "assign_vuln":      {"dev", "admin"},
    "comment_vuln":     {"viewer", "user", "analyst", "dev", "admin"},
    "view_ciso":        {"admin"},
    "manage_settings":  {"admin"},
}


def role_level(role: str) -> int:
    """Returns numeric level for role comparisons (higher = more privileged)."""
    try:
        return ROLES.index(role)
    except ValueError:
        return -1


def has_permission(role: str, perm: str) -> bool:
    return role in PERMISSIONS.get(perm, set())


def require_role(*allowed_roles):
    """
    Decorator: allows access only if session role is in allowed_roles.
    Must be applied AFTER @login_required.

    Usage:
        @app.route('/admin')
        @login_required
        @require_role('admin')
        def admin_page(): ...

        @app.route('/scan')
        @login_required
        @require_role('analyst', 'dev', 'admin')
        def scan(): ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_role = session.get("role", "viewer")
            if user_role not in allowed_roles:
                if request.is_json or request.method != "GET":
                    return jsonify({"error": "Accès refusé", "required": list(allowed_roles), "your_role": user_role}), 403
                return redirect("/dashboard")
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_permission(perm: str):
    """
    Decorator: allows access only if the user's role has the given permission.

    Usage:
        @app.route('/scan')
        @login_required
        @require_permission('run_scan')
        def scan(): ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_role = session.get("role", "viewer")
            if not has_permission(user_role, perm):
                if request.is_json or request.method != "GET":
                    return jsonify({"error": "Permission refusée", "permission": perm, "your_role": user_role}), 403
                return redirect("/dashboard")
            return f(*args, **kwargs)
        return wrapper
    return decorator
