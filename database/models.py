"""
database/models.py
SQLAlchemy ORM models replacing the runtime JSON files.

Persisted here        →  Was stored in
─────────────────────────────────────────
User                  →  data/users.json
Project               →  data/projects.json
ProjectMember         →  (new — project collaborators)
ProjectInvitation     →  (new — email-based invite tokens)
AccessRequest         →  data/requests.json
Metric (session hist) →  data/users/<u>/metrics.json
AuditLog              →  data/audit_log.json
Comment               →  data/comments.json
VulnAssignment        →  data/assignments.json
FalsePositive         →  data/false_positives.json
ToolExecution         →  (new — tool run results + cache)

Knowledge-base JSON files (cve_database.json, cwe_list.json,
rag_examples.json) are intentionally NOT migrated.
"""
import json as _json
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, Float,
    DateTime, Text, ForeignKey, JSON, Index,
)
from sqlalchemy.orm import relationship
from database.db import Base


# ══════════════════════════════════════════════════════════════════
# User
# ══════════════════════════════════════════════════════════════════

class User(Base):
    __tablename__ = "users"

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    username            = Column(String(50), unique=True, nullable=False, index=True)
    password            = Column(String(256), nullable=False)
    role                = Column(String(20), default="analyst", nullable=False)
    full_name           = Column(String(100), default="")
    email               = Column(String(200), default="")
    lang                = Column(String(5),   default="fr")
    active              = Column(Boolean, default=True)
    blocked             = Column(Boolean, default=False)
    must_change_password= Column(Boolean, default=False)
    totp_secret         = Column(String(64))
    totp_enabled        = Column(Boolean, default=False)
    created_at          = Column(DateTime, default=datetime.now)
    # optional extra fields stored as JSON dict (department, avatar, etc.)
    extra               = Column(JSON, default=dict)

    # relationships
    metrics  = relationship("Metric",         back_populates="user", cascade="all, delete-orphan")
    tool_runs= relationship("ToolExecution",  back_populates="user", cascade="all, delete-orphan")

    # ── dict conversion helpers ───────────────────────────────────

    def to_dict(self) -> dict:
        d = {
            "password":            self.password,
            "role":                self.role,
            "full_name":           self.full_name or "",
            "email":               self.email or "",
            "lang":                self.lang or "fr",
            "active":              self.active,
            "blocked":             self.blocked,
            "must_change_password":self.must_change_password,
            "totp_secret":         self.totp_secret,
            "totp_enabled":        self.totp_enabled,
            "created_at":          self.created_at.isoformat() if self.created_at else "",
        }
        if self.extra:
            d.update(self.extra)
        return d

    @classmethod
    def from_dict(cls, username: str, data: dict) -> "User":
        known = {"password","role","full_name","email","lang","active","blocked",
                 "must_change_password","totp_secret","totp_enabled","created_at"}
        extra = {k: v for k, v in data.items() if k not in known}
        created = data.get("created_at")
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created)
            except ValueError:
                created = datetime.now()
        return cls(
            username             = username,
            password             = data.get("password", ""),
            role                 = data.get("role", "analyst"),
            full_name            = data.get("full_name", ""),
            email                = data.get("email", ""),
            lang                 = data.get("lang", "fr"),
            active               = data.get("active", True),
            blocked              = data.get("blocked", False),
            must_change_password = data.get("must_change_password", False),
            totp_secret          = data.get("totp_secret"),
            totp_enabled         = data.get("totp_enabled", False),
            created_at           = created or datetime.now(),
            extra                = extra or {},
        )

    def update_from_dict(self, data: dict) -> None:
        known = {"password","role","full_name","email","lang","active","blocked",
                 "must_change_password","totp_secret","totp_enabled"}
        for k in known:
            if k in data:
                setattr(self, k, data[k])
        extra = {k: v for k, v in data.items() if k not in known | {"created_at"}}
        if extra:
            current = dict(self.extra or {})
            current.update(extra)
            self.extra = current


# ══════════════════════════════════════════════════════════════════
# Project
# ══════════════════════════════════════════════════════════════════

class Project(Base):
    __tablename__ = "projects"

    id          = Column(String(30), primary_key=True)          # 'proj_<hex>'
    name        = Column(String(200), nullable=False)
    description = Column(Text, default="")
    owner       = Column(String(50), ForeignKey("users.username", ondelete="CASCADE"), nullable=False, index=True)
    department  = Column(String(100), default="")
    status      = Column(String(20),  default="active")
    created_at  = Column(DateTime, default=datetime.now)
    tags        = Column(JSON, default=list)    # list[str]
    members     = Column(JSON, default=list)    # list[str] (usernames)

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "name":        self.name,
            "description": self.description or "",
            "owner":       self.owner,
            "department":  self.department or "",
            "status":      self.status or "active",
            "created_at":  self.created_at.isoformat() if self.created_at else "",
            "tags":        self.tags or [],
            "members":     self.members or [],
        }

    @classmethod
    def from_dict(cls, pid: str, data: dict) -> "Project":
        created = data.get("created_at")
        if isinstance(created, str):
            try:   created = datetime.fromisoformat(created)
            except ValueError: created = datetime.now()
        return cls(
            id          = pid,
            name        = data.get("name", ""),
            description = data.get("description", ""),
            owner       = data.get("owner", ""),
            department  = data.get("department", ""),
            status      = data.get("status", "active"),
            created_at  = created or datetime.now(),
            tags        = data.get("tags", []),
            members     = data.get("members", []),
        )


# ══════════════════════════════════════════════════════════════════
# ProjectMember
# ══════════════════════════════════════════════════════════════════

class ProjectMember(Base):
    __tablename__ = "project_members"
    __table_args__ = (
        Index("ix_pm_project_user", "project_id", "username", unique=True),
    )

    id         = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String(30), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    username   = Column(String(50), ForeignKey("users.username", ondelete="CASCADE"), nullable=False, index=True)
    role       = Column(String(20), default="member")   # "owner" | "member" | "viewer"
    joined_at  = Column(DateTime, default=datetime.now)

    def to_dict(self) -> dict:
        return {
            "project_id": self.project_id,
            "username":   self.username,
            "role":       self.role or "member",
            "joined_at":  self.joined_at.isoformat() if self.joined_at else "",
        }


# ══════════════════════════════════════════════════════════════════
# ProjectInvitation
# ══════════════════════════════════════════════════════════════════

class ProjectInvitation(Base):
    __tablename__ = "project_invitations"
    # status values: pending | approved | rejected | cancelled | accepted | expired

    id                    = Column(Integer, primary_key=True, autoincrement=True)
    project_id            = Column(String(30), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    invited_by            = Column(String(50), ForeignKey("users.username", ondelete="SET NULL"), nullable=True)
    email                 = Column(String(200), nullable=False, index=True)
    token                 = Column(String(64), unique=True, nullable=False, index=True)
    role                  = Column(String(20), default="member")
    status                = Column(String(20), default="pending", index=True)
    expires_at            = Column(DateTime, nullable=False)
    created_at            = Column(DateTime, default=datetime.now)
    responded_at          = Column(DateTime)
    # Approval workflow fields
    approved_by           = Column(String(50), nullable=True)
    approved_at           = Column(DateTime, nullable=True)
    rejected_at           = Column(DateTime, nullable=True)
    rejection_reason      = Column(Text, default="")
    cancelled_at          = Column(DateTime, nullable=True)
    cancelled_by          = Column(String(50), nullable=True)
    # Provisioning metadata
    invited_existing_user = Column(Boolean, nullable=True)   # True=existing, False=new account created
    credentials_sent      = Column(Boolean, default=False)
    provisioned_username  = Column(String(50), nullable=True)  # username created for new-user case

    def to_dict(self) -> dict:
        return {
            "id":                    self.id,
            "project_id":            self.project_id,
            "invited_by":            self.invited_by or "",
            "email":                 self.email,
            "role":                  self.role or "member",
            "status":                self.status or "pending",
            "expires_at":            self.expires_at.isoformat() if self.expires_at else "",
            "created_at":            self.created_at.isoformat() if self.created_at else "",
            "responded_at":          self.responded_at.isoformat() if self.responded_at else "",
            "approved_by":           self.approved_by or "",
            "approved_at":           self.approved_at.isoformat() if self.approved_at else "",
            "rejected_at":           self.rejected_at.isoformat() if self.rejected_at else "",
            "rejection_reason":      self.rejection_reason or "",
            "cancelled_at":          self.cancelled_at.isoformat() if self.cancelled_at else "",
            "cancelled_by":          self.cancelled_by or "",
            "invited_existing_user": self.invited_existing_user,
            "credentials_sent":      bool(self.credentials_sent),
            "provisioned_username":  self.provisioned_username or "",
        }


# ══════════════════════════════════════════════════════════════════
# AccessRequest
# ══════════════════════════════════════════════════════════════════

class AccessRequest(Base):
    __tablename__ = "access_requests"

    id             = Column(String(30), primary_key=True)
    email          = Column(String(200), nullable=False, index=True)
    full_name      = Column(String(100), default="")
    reason         = Column(Text, default="")
    status         = Column(String(20), default="pending", index=True)
    role_requested = Column(String(20), default="analyst")
    created_at     = Column(DateTime, default=datetime.now)
    reviewed_by    = Column(String(50))
    reviewed_at    = Column(DateTime)
    username       = Column(String(50))     # assigned on approval

    def to_dict(self) -> dict:
        # reason field may be JSON-encoded (stores company + use_case + plain reason)
        company = ""
        use_case = ""
        reason_text = self.reason or ""
        if reason_text.startswith("{"):
            try:
                parsed = _json.loads(reason_text)
                company     = parsed.get("company", "")
                use_case    = parsed.get("use_case", "")
                reason_text = parsed.get("reason", "")
            except (_json.JSONDecodeError, AttributeError):
                pass
        return {
            "id":             self.id,
            "email":          self.email,
            "full_name":      self.full_name or "",
            "reason":         reason_text,
            "company":        company,
            "use_case":       use_case,
            "status":         self.status,
            "role_requested": self.role_requested,
            "created_at":     self.created_at.isoformat() if self.created_at else "",
            "reviewed_by":    self.reviewed_by or "",
            "reviewed_at":    self.reviewed_at.isoformat() if self.reviewed_at else "",
            "username":       self.username or "",
        }


# ══════════════════════════════════════════════════════════════════
# Metric  (per-user session history)
# ══════════════════════════════════════════════════════════════════

class Metric(Base):
    __tablename__ = "metrics"
    __table_args__ = (
        Index("ix_metrics_username_ts", "username", "timestamp"),
    )

    id           = Column(Integer, primary_key=True, autoincrement=True)
    username     = Column(String(50), ForeignKey("users.username", ondelete="CASCADE"), nullable=False)
    timestamp    = Column(DateTime, default=datetime.now)
    session_data = Column(JSON)    # full session metrics snapshot

    user = relationship("User", back_populates="metrics")

    def to_dict(self) -> dict:
        d = dict(self.session_data or {})
        d.setdefault("timestamp", self.timestamp.isoformat() if self.timestamp else "")
        return d


# ══════════════════════════════════════════════════════════════════
# AuditLog
# ══════════════════════════════════════════════════════════════════

class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_ts_event", "ts", "event"),
    )

    id      = Column(Integer, primary_key=True, autoincrement=True)
    ts      = Column(DateTime, default=datetime.now, index=True, nullable=False)
    event   = Column(String(100), index=True)
    user    = Column(String(50),  index=True)
    ip      = Column(String(50))
    details = Column(JSON)

    def to_dict(self) -> dict:
        return {
            "ts":      self.ts.isoformat() if self.ts else "",
            "event":   self.event or "",
            "user":    self.user or "",
            "ip":      self.ip or "",
            "details": self.details or {},
        }


# ══════════════════════════════════════════════════════════════════
# Comment
# ══════════════════════════════════════════════════════════════════

class Comment(Base):
    __tablename__ = "comments"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    hex_id     = Column(String(20), unique=True, index=True)  # external identifier
    vuln_key   = Column(String(300), index=True)
    username   = Column(String(50))
    text       = Column(Text)
    mentions   = Column(Text, default="[]")  # JSON-encoded list of @mentioned users
    created_at = Column(DateTime, default=datetime.now)

    def to_dict(self) -> dict:
        import json as _json
        try:
            mentions = _json.loads(self.mentions or "[]")
        except Exception:
            mentions = []
        return {
            "id":         self.hex_id or str(self.id),
            "vuln_id":    self.vuln_key,
            "vuln_key":   self.vuln_key,
            "author":     self.username or "",
            "text":       self.text or "",
            "mentions":   mentions,
            "created_at": self.created_at.isoformat() if self.created_at else "",
        }


# ══════════════════════════════════════════════════════════════════
# VulnAssignment
# ══════════════════════════════════════════════════════════════════

class VulnAssignment(Base):
    __tablename__ = "vuln_assignments"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    vuln_key    = Column(String(300), index=True)   # same as vuln_id in app routes
    cwe         = Column(String(50), default="")
    message     = Column(String(200), default="")
    assignee    = Column(String(50))
    assigned_by = Column(String(50), default="")
    deadline    = Column(String(30), default="")
    status      = Column(String(30), default="open")
    note        = Column(Text, default="")
    created_at  = Column(DateTime, default=datetime.now)
    updated_at  = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self) -> dict:
        return {
            "vuln_id":     self.vuln_key,
            "vuln_key":    self.vuln_key,
            "cwe":         self.cwe or "",
            "message":     self.message or "",
            "assignee":    self.assignee or "",
            "assigned_by": self.assigned_by or "",
            "deadline":    self.deadline or "",
            "status":      self.status or "open",
            "note":        self.note or "",
            "created_at":  self.created_at.isoformat() if self.created_at else "",
            "updated_at":  self.updated_at.isoformat() if self.updated_at else "",
        }


# ══════════════════════════════════════════════════════════════════
# FalsePositive
# ══════════════════════════════════════════════════════════════════

class FalsePositive(Base):
    __tablename__ = "false_positives"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    vuln_key        = Column(String(300), unique=True, index=True)
    cwe             = Column(String(50), default="")
    message_snippet = Column(String(200), default="")
    reporters       = Column(Text, default="[]")   # JSON list of usernames
    confirmed_count = Column(Integer, default=0)
    reason          = Column(Text, default="")
    reported_by     = Column(String(50))           # first reporter
    created_at      = Column(DateTime, default=datetime.now)
    last_seen       = Column(DateTime)

    def to_dict(self) -> dict:
        import json as _json
        try:
            reporters = _json.loads(self.reporters or "[]")
        except Exception:
            reporters = []
        return {
            "vuln_key":        self.vuln_key,
            "cwe":             self.cwe or "",
            "message_snippet": self.message_snippet or "",
            "reporters":       reporters,
            "confirmed_count": self.confirmed_count or 0,
            "reason":          self.reason or "",
            "reported_by":     self.reported_by or "",
            "created_at":      self.created_at.isoformat() if self.created_at else "",
            "last_seen":       self.last_seen.isoformat() if self.last_seen else "",
        }


# ══════════════════════════════════════════════════════════════════
# ToolExecution  (tool run cache + audit)
# ══════════════════════════════════════════════════════════════════

class ToolExecution(Base):
    __tablename__ = "tool_executions"
    __table_args__ = (
        Index("ix_tool_exec_cache", "cache_key"),
    )

    id             = Column(Integer, primary_key=True, autoincrement=True)
    username       = Column(String(50), ForeignKey("users.username", ondelete="SET NULL"), nullable=True)
    tool_name      = Column(String(50), nullable=False)
    target_path    = Column(String(500))
    status         = Column(String(20))   # "success" | "failed" | "timeout" | "unavailable"
    findings_count = Column(Integer, default=0)
    findings_json  = Column(JSON)         # list of normalized finding dicts
    cache_key      = Column(String(32), index=True)
    executed_at    = Column(DateTime, default=datetime.now)
    duration_ms    = Column(Integer, default=0)
    error_message  = Column(Text)

    user = relationship("User", back_populates="tool_runs")

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "tool_name":      self.tool_name,
            "target_path":    self.target_path or "",
            "status":         self.status,
            "findings_count": self.findings_count,
            "findings":       self.findings_json or [],
            "executed_at":    self.executed_at.isoformat() if self.executed_at else "",
            "duration_ms":    self.duration_ms,
            "error":          self.error_message or "",
        }
