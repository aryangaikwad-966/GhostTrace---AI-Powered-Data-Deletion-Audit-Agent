#!/usr/bin/env python3
"""GhostTrace - minimal, high-accuracy deletion-audit agent.

Reads deletion requests + participant-facing evidence, reconstructs each
case's state at audit_at, applies deletion_rules.csv exactly, and emits
output.csv with case_id, deletion_status, steps_json.
"""
import csv
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATASET = REPO / "dataset"
EVIDENCE = DATASET / "evidence"
OUTPUT = REPO / "output.csv"

# ---------------------------------------------------------------------------
# Operation ordering (from specification / sample outputs)
# ---------------------------------------------------------------------------
FIND_OP_ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]
REMED_OP_ORDER = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]
VERIFY_OP_ORDER = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]

# Loaded from the participant-facing policy CSV before prediction.
TREATMENT = {}


def load_treatments():
    with open(DATASET / "deletion_rules.csv", newline="") as f:
        return {row["data_category"].strip(): row["required_action"].strip().upper() for row in csv.DictReader(f)}


def treatment_for(category, rec, audit_at):
    if not TREATMENT:
        TREATMENT.update(load_treatments())
    action = TREATMENT.get(category, "DELETE")
    if category == "SECURITY_AUDIT_LOG":
        until = parse_ts((rec or {}).get("retention_until"))
        cutoff = parse_ts(audit_at)
        if until and cutoff and until <= cutoff:
            return "DELETE"
    if category == "LEGAL_HOLD_RECORD":
        active = str((rec or {}).get("hold_active", (rec or {}).get("active", "true"))).lower() in ("true", "1", "yes")
        until = parse_ts((rec or {}).get("hold_until") or (rec or {}).get("retention_until"))
        cutoff = parse_ts(audit_at)
        if not active or (until and cutoff and until <= cutoff):
            return "DELETE"
    return action

# category -> verification op when in compliant final state
VERIFY_OP = {
    "DELETE": "VERIFY_RECORD_ABSENT",
    "REDACT": "VERIFY_RECORD_REDACTED",
    "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED",
    "RETAIN": "VERIFY_RECORD_PRESENT",
}

# finding op for a record that still violates its treatment
FIND_OP = {
    "DELETE": "REPORT_REMAINING_RECORD",
    "REDACT": "REPORT_EXPOSED_PII",
    "ANONYMIZE": "REPORT_EXPOSED_PII",
    "DATA_FLOW": "REPORT_ACTIVE_DATA_FLOW",
    "BACKUP": "REPORT_RESTORE_RISK",
}

# remediation op
REMED_OP = {
    "DELETE": "DELETE_RECORD",
    "REDACT": "REDACT_RECORD",
    "ANONYMIZE": "ANONYMIZE_RECORD",
    "DATA_FLOW": "DISABLE_DATA_FLOW",
    "BACKUP": "BLOCK_RESTORE",
}

OP_INDEX = {op: i for i, op in enumerate(FIND_OP_ORDER + REMED_OP_ORDER + VERIFY_OP_ORDER)}

# ---------------------------------------------------------------------------
# Deletion authorization keywords (multilingual)
# ---------------------------------------------------------------------------
DELETION_PHRASES = [
    # english - present / imperative
    "delete my account", "delete my data", "delete my profile", "delete my record",
    "delete all my", "delete everything", "delete this account", "delete the account",
    "delete my information", "delete my personal details", "erase my data",
    "erase my account", "remove my account", "remove my data", "remove my profile",
    "remove my information", "remove my personal details", "remove my name and contact details",
    "remove my records", "remove records", "remove the profile", "remove the account",
    "remove this account", "remove all my", "remove me from", "remove it", "remove them",
    "can you remove", "take down my", "wipe my data", "wipe my account",
    "cleanse my data", "expunge my data", "purge my data",
    # english - past / passive / status
    "deleted my account", "deleted my data", "deleted my profile", "deleted this account",
    "deleted the account", "my account deleted", "my data deleted",
    "account was deleted", "data was deleted", "account itself is gone",
    "account is gone", "page is gone", "deletion complete", "deletion was complete",
    "deletion request", "request for deletion", "permanent account deletion",
    "request for permanent account deletion", "right to be forgotten",
    "right to erasure", "article 17", "gdpr deletion", "gdpr erasure",
    "personal data deletion", "personal data removed", "confirm deletion",
    "confirm my deletion", "verify that my account was deleted",
    "confirm when the review", "handle any copies", "apply the correct treatment",
    "still appears", "still exists", "still existed", "still shows", "can still find",
    "no longer using", "no longer need this account",
    "deletion", "erasure", "deleting my account", "deleting my data",
    "deleting it", "before deleting", "request failed",
    "inspect the actual systems", "tell me the outcome", "tell me the result",
    "confirm deletion is complete", "deletion confirmed",
    "close my account", "close the account", "close this account",
    "close my account permanently", "close this account permanently",
    "closed my account", "closed the account", "want it closed",
    "would like it closed", "treat this message as a request",
    # audit / verification requests for a prior deletion (authorized)
    "verify that my account was deleted", "verify my account was deleted",
    "confirm that the profile is gone", "profile is gone",
    "account was fully removed", "account fully removed",
    "audit the deletion", "audit my deletion", "confirm deletion status",
    "confirm the account was deleted", "check the latest state",
    "confirm that my account", "remaining records cannot identify",
    "cannot identify me",
    # standalone deletion verbs (guarded by negation window above)
    r"\bdelete\b", r"\berase\b", r"\bremove\b", r"\bpurge\b", r"\bwipe\b",
    r"\bdeleted\b", r"\bdeletion\b", r"\berasure\b", r"\bremoved\b",
    r"\bclosing\b", r"\bclosed\b",
    # multilingual
    "eliminar", "eliminar mi cuenta", "borrar", "suprimir", "suppression",
    "supprimer", "supprimer mon compte", "supprimez", "loeschung", "loschen",
    "konto loschen", "account loschen", "cancella", "eliminare", "rimuovi",
    "apagar", "apagar minha conta", "удалить", "удалить аккаунт", "verwijder",
    "verwijder mijn", "smazat", "vymazat", "torles", "izbrisi", "fjern", "slett",
    "poista", "מחק", "حذف", "احذف حسابي", "削除", "削除して", "계정 삭제",
    "계정을 삭제", "xoa", "xoa tai khoan", "magpalit", "burahan", "hapus",
    "hapus akun", "padam", "padam akaun", "alem",
]
DELETION_RE = re.compile("|".join(re.escape(w) for w in DELETION_PHRASES), re.IGNORECASE)

NON_DELETION_PHRASES = [
    "access my data", "access my account", "right to access", "data access",
    "copy of my data", "data portability", "export my data", "download my data",
    "correct my", "rectify my", "update my email", "change my email",
    "unsubscribe", "opt out", "opt-out", "marketing", "newsletter",
    "do not sell my", "do not track",
]
NON_DELETION_RE = re.compile("|".join(re.escape(w) for w in NON_DELETION_PHRASES), re.IGNORECASE)

NEGATION_PHRASES = [
    "do not delete", "don't delete", "dont delete", "never delete",
    "not delete my", "do not want to delete", "do not wish to delete",
    "prevent deletion", "cancel deletion", "stop deletion",
    "i do not want to delete", "i dont want to delete", "do not delete my data",
    "i do not want my data deleted",
]

NEG_WINDOW = 80


def is_deletion_authorized(request_text):
    """Return True if the request actually authorizes deletion."""
    tl = (request_text or "").lower()
    has_del = bool(DELETION_RE.search(tl))
    if not has_del:
        return False
    # Explicit negation of a deletion phrase nearby means not authorized.
    for m in DELETION_RE.finditer(tl):
        s = max(0, m.start() - NEG_WINDOW)
        e = min(len(tl), m.end() + NEG_WINDOW)
        window = tl[s:e]
        if any(neg in window for neg in NEGATION_PHRASES):
            continue
        return True
    return False


# ---------------------------------------------------------------------------
# Identity resolution
# ---------------------------------------------------------------------------
def load_identities():
    by_email = {}
    by_id = {}
    with open(DATASET / "user_identities.csv", newline="") as f:
        for row in csv.DictReader(f):
            email = (row.get("email") or "").strip().lower()
            uid = (row.get("user_id") or "").strip()
            by_email[email] = row
            if uid:
                by_id[uid] = row
    return by_email, by_id


def load_audit_history():
    """Return time-stamped historical identity values by stable user id."""
    hist = defaultdict(set)
    with open(DATASET / "user_audit_log.csv", newline="") as f:
        for row in csv.DictReader(f):
            uid = (row.get("user_id") or "").strip()
            for val in (row.get("old_value"), row.get("new_value")):
                if val:
                    hist[uid].add((row.get("field_name", "").strip().lower(), val.strip().lower(), row.get("event_time", "")))
    return hist


def resolve_identities(email, by_email, by_id, audit_hist, audit_at=None):
    """Return stable id and all current/historical identifier strings known by cutoff."""
    import hashlib
    emails = set()
    identifiers = set()
    email_l = (email or "").strip().lower()
    if email_l:
        emails.add(email_l)
        identifiers.add(email_l)
    identifiers.add(hashlib.sha256(email_l.encode()).hexdigest())
    user_id = None
    row = by_email.get(email_l)
    cutoff = parse_ts(audit_at)
    snap_time = parse_ts(row.get("updated_at")) if row else None
    if row and (not cutoff or not snap_time or snap_time <= cutoff):
        user_id = (row.get("user_id") or "").strip()
    # Reverse lookup: historical email in audit log -> user_id
    if not user_id and audit_hist:
        for uid, hist_values in audit_hist.items():
            if any(field == "email" and value == email_l and (not cutoff or not parse_ts(event) or parse_ts(event) <= cutoff) for field, value, event in hist_values):
                user_id = uid
                break
    if user_id and user_id in by_id:
        row = by_id[user_id]
        updated = parse_ts(row.get("updated_at"))
        if not cutoff or not updated or updated <= cutoff:
            for key in ("email", "name", "phone", "email_hash"):
                val = (row.get(key) or "").strip().lower()
                if val:
                    identifiers.add(val)
                    if key == "email":
                        emails.add(val)
                        identifiers.add(hashlib.sha256(val.encode()).hexdigest())
    if user_id:
        for field, val, event_time in audit_hist.get(user_id, set()):
            event = parse_ts(event_time)
            if cutoff and event and event > cutoff:
                continue
            identifiers.add(val)
            if field == "email":
                emails.add(val)
                identifiers.add(hashlib.sha256(val.encode()).hexdigest())
    return user_id, emails, identifiers


# ---------------------------------------------------------------------------
# Evidence parsing -> observations
# ---------------------------------------------------------------------------
def system_for_store(store):
    store = (store or "").strip().lower()
    # Snapshot and replica names often describe an origin rather than a service.
    for suffix in ("_read_replica", "_regional_replica", "_failover_replica", "_replica"):
        if store.endswith(suffix):
            store = store[:-len(suffix)]
    mapping = {
        "account": "account_service",
        "account_service": "account_service",
        "customer_profiles": "account_service",
        "customer_profiles_primary": "account_service",
        "identity": "identity_service",
        "identity_service": "identity_service",
        "security": "security_service",
        "security_service": "security_service",
        "analytics": "analytics_platform",
        "analytics_platform": "analytics_platform",
        "search": "search_service",
        "search_service": "search_service",
        "search_documents_primary": "search_service",
        "customer_search_documents": "search_service",
        "support": "support_platform",
        "support_platform": "support_platform",
        "support_records": "support_platform",
        "support_tickets": "support_platform",
        "support_attachments": "support_platform",
        "export": "export_service",
        "export_service": "export_service",
        "customer_exports": "export_service",
        "integration": "integration_service",
        "integration_service": "integration_service",
        "connector_subscriptions": "integration_service",
        "connector_configurations": "integration_service",
        "backup": "backup_service",
        "backup_service": "backup_service",
        "backup_restore_entries": "backup_service",
        "cache": "cache_service",
        "cache_service": "cache_service",
        "marketing": "marketing_platform",
        "marketing_platform": "marketing_platform",
        "object": "object_storage",
        "object_storage": "object_storage",
        "data_flow": "integration_service",
        "user_export_store": "export_service",
        "customer_export_store": "export_service",
        "user_data_store": "integration_service",
        "data_store": "integration_service",
        "customer_data_store": "integration_service",
        "analytics_identity_store": "analytics_platform",
        "customer_analytics_warehouse": "analytics_platform",
        "customer_export_service": "export_service",
        "customer_export_store": "export_service",
        "customer_download_center": "export_service",
        "legal": "legal_service",
        "legal_service": "legal_service",
        "audit": "security_service",
        "audit_record": "security_service",
        "security_audit_records": "security_service",
        "security_audit_events": "security_service",
        "customer_analytics_profiles": "analytics_platform",
        "deleted_customer_references": "identity_service",
        "marketing_profiles": "marketing_platform",
    }
    if store.startswith("data_flow") or store == "data":
        return "integration_service"
    return mapping.get(store, store)


def system_for_resource(resource_id):
    rid = (resource_id or "").lower()
    for prefix, system in (
        ("audit_record_", "security_service"), ("tombstone_", "identity_service"),
        ("data_flow_", "integration_service"), ("analytics_", "analytics_platform"),
        ("search_", "search_service"), ("support_", "support_platform"),
        ("backup_", "backup_service"), ("export_", "export_service"),
        ("account_", "account_service"), ("marketing_", "marketing_platform"),
        ("legal_hold_", "legal_service"), ("cache_", "cache_service"),
    ):
        if rid.startswith(prefix):
            return system
    return ""


def category_for(store, collection, rec=None):
    c = (collection or "").lower()
    s = system_for_store(store)
    # Resource namespace is more reliable than a shortened/aliased store name.
    resource_category = {
        "account_service": "USER_PROFILE", "identity_service": "ACCOUNT_TOMBSTONE",
        "security_service": "SECURITY_AUDIT_LOG", "analytics_platform": "ANALYTICS_PROFILE",
        "search_service": "SEARCH_INDEX_ENTRY", "export_service": "USER_EXPORT",
        "integration_service": "DATA_FLOW", "backup_service": "BACKUP_ARCHIVE",
        "cache_service": "CACHE_ENTRY", "marketing_platform": "MARKETING_PROFILE",
        "legal_service": "LEGAL_HOLD_RECORD",
    }
    table_categories = {
        "customer_profiles": "USER_PROFILE", "user_profiles": "USER_PROFILE",
        "customer_search_documents": "SEARCH_INDEX_ENTRY", "search_documents_primary": "SEARCH_INDEX_ENTRY",
        "customer_analytics_profiles": "ANALYTICS_PROFILE", "customer_analytics_reports": "ANALYTICS_PROFILE",
        "support_records": "SUPPORT_MESSAGE", "support_tickets": "SUPPORT_MESSAGE",
        "support_attachments": "SUPPORT_ATTACHMENT", "customer_exports": "USER_EXPORT",
        "customer_export_jobs": "USER_EXPORT", "exports": "USER_EXPORT",
        "connector_subscriptions": "DATA_FLOW", "connector_configurations": "DATA_FLOW",
        "backup_restore_entries": "BACKUP_ARCHIVE", "backup_catalog": "BACKUP_ARCHIVE",
        "security_audit_records": "SECURITY_AUDIT_LOG", "security_audit_events": "SECURITY_AUDIT_LOG",
        "deleted_customer_references": "ACCOUNT_TOMBSTONE", "marketing_profiles": "MARKETING_PROFILE",
        "email_delivery_logs": "EMAIL_DELIVERY_LOG",
    }
    if c in table_categories:
        return table_categories[c]
    if rec:
        rid = rec.get("resource_id") or ""
        by_resource = system_for_resource(rid)
        if by_resource:
            return {
                "account_service": "USER_PROFILE", "identity_service": "ACCOUNT_TOMBSTONE",
                "security_service": "SECURITY_AUDIT_LOG", "analytics_platform": "ANALYTICS_PROFILE",
                "search_service": "SEARCH_INDEX_ENTRY", "export_service": "USER_EXPORT",
                "integration_service": "DATA_FLOW", "backup_service": "BACKUP_ARCHIVE",
                "cache_service": "CACHE_ENTRY", "marketing_platform": "MARKETING_PROFILE",
            }.get(by_resource, "USER_PROFILE")
    if s == "account_service" or c in ("customer_profiles", "user_profiles"):
        return "USER_PROFILE"
    if s == "identity_service":
        return "ACCOUNT_TOMBSTONE"
    if s == "security_service":
        return "SECURITY_AUDIT_LOG"
    if s == "analytics_platform":
        return "ANALYTICS_PROFILE"
    if s == "search_service":
        return "SEARCH_INDEX_ENTRY"
    if s == "support_platform":
        if "attachment" in c or "object" in c:
            return "SUPPORT_ATTACHMENT"
        return "SUPPORT_MESSAGE"
    if s == "export_service":
        return "USER_EXPORT"
    if s == "integration_service":
        return "DATA_FLOW"
    if s == "backup_service":
        return "BACKUP_ARCHIVE"
    if s == "cache_service":
        return "CACHE_ENTRY"
    if s == "marketing_platform":
        return "MARKETING_PROFILE"
    if s == "object_storage":
        return "SUPPORT_ATTACHMENT"
    if rec:
        rid = (rec.get("resource_id") or "").lower()
        if rid.startswith("account_"):
            return "USER_PROFILE"
        if rid.startswith("audit_record"):
            return "SECURITY_AUDIT_LOG"
        if rid.startswith("analytics_"):
            return "ANALYTICS_PROFILE"
        if rid.startswith("search_"):
            return "SEARCH_INDEX_ENTRY"
        if rid.startswith("support_"):
            return "SUPPORT_MESSAGE"
        if rid.startswith("backup_"):
            return "BACKUP_ARCHIVE"
        if rid.startswith("data_flow"):
            return "DATA_FLOW"
        if rid.startswith("export_"):
            return "USER_EXPORT"
        if rid.startswith("tombstone_"):
            return "ACCOUNT_TOMBSTONE"
    return "USER_PROFILE"


def identifiers_of(rec):
    # Keep the existing two-value interface: the first set contains direct
    # identifiers (including historical names, phones, and email hashes).
    emails, uids = set(), set()
    email_keys = {"email", "owner_email", "requester_email", "subject_selector", "customer_email", "lookup_key", "query", "matched_value", "correlation_key", "match_key", "subject_key"}
    uid_keys = {"user_id", "customer_reference", "subject_reference", "subject_ref"}
    other_keys = {"name", "full_name", "requester_name", "owner_name", "phone", "requester_phone", "owner_phone", "email_hash", "correlation_key", "match_key"}
    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                key = str(key).lower()
                if item not in (None, "") and isinstance(item, (str, int)):
                    v = str(item).strip()
                    low = v.lower()
                    if (key in uid_keys and re.fullmatch(r"user_[A-Za-z0-9]+", v, re.I)) or (key in {"lookup_key", "subject_key", "correlation_key", "match_key", "matched_value"} and re.fullmatch(r"user_[A-Za-z0-9]+", v, re.I)):
                        uids.add(v)
                    elif key in email_keys or (key in {"correlation_key", "match_key"} and ("@" in v or re.fullmatch(r"[0-9a-f]{64}", v, re.I))):
                        emails.add(low)
                    elif key in other_keys:
                        emails.add(low)
                if isinstance(item, (dict, list)):
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(rec or {})
    return emails, uids


def normalize_state(category, state_hint, rec=None, fields=None):
    """Map evidence hints to a canonical state."""
    hint = (state_hint or "").strip().lower()
    fields = fields or {}
    if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
        return "PRESENT"
    if category == "DATA_FLOW":
        return "ACTIVE" if fields.get("enabled") is True or str(fields.get("enabled")).lower() in ("1", "true", "yes") else "DISABLED"
    if category == "BACKUP_ARCHIVE":
        return "ACTIVE" if fields.get("restore_allowed") is True or str(fields.get("restore_allowed")).lower() in ("1", "true", "yes") else "BLOCKED"
    if category == "ACCOUNT_TOMBSTONE":
        has_id = any(rec.get(k) not in (None, "") for k in ("name", "full_name", "email", "phone", "email_hash", "display_name"))
        return "PRESENT" if has_id else "REDACTED"
    if category == "ANALYTICS_PROFILE":
        has_id = any(rec.get(k) not in (None, "", "null") for k in ("email", "phone", "email_hash", "user_id", "customer_reference", "name", "full_name"))
        return "ANONYMIZED" if not has_id else "PRESENT"
    if category == "USER_PROFILE":
        hint_status = (rec or {}).get("account_status", "").upper()
        if hint_status == "DELETED" and not any((rec or {}).get(k) for k in ("email", "phone", "email_hash", "full_name", "name")):
            return "ABSENT"
    if hint in ("not_found", "404", "absent", "deleted"):
        return "ABSENT"
    if hint in ("found", "present", "hit", "active", "identifiable", "anonymous"):
        if hint == "anonymous":
            return "ANONYMIZED"
        return "PRESENT"
    if hint == "redacted":
        return "REDACTED"
    if hint == "disabled":
        return "DISABLED"
    if hint == "blocked":
        return "BLOCKED"
    # default: inspect record content for direct identifiers
    if rec:
        has_id = any(rec.get(k) not in (None, "") for k in ("email", "phone", "requester_email", "owner_email"))
        doc = rec.get("document")
        if isinstance(doc, dict):
            has_id = has_id or doc.get("email") not in (None, "")
        return "PRESENT" if has_id else "ABSENT"
    return "PRESENT"


def obs_from_record(evidence_id, captured_at, system_id, category, resource_id, state, rec, identifiers):
    system_id = system_for_store(system_id) or system_for_resource(resource_id) or system_id
    return {
        "evidence_id": evidence_id,
        "captured_at": captured_at,
        "system_id": system_id,
        "category": category,
        "resource_id": resource_id,
        "state": state,
        "observed_at": (rec or {}).get("observed_at") or captured_at,
        "identifiers": identifiers,
        "rec": rec,
    }


def parse_json_bundle(obj, evidence_id, captured_at):
    out = []
    snaps = obj.get("snapshots")
    if not snaps:
        # top-level records: treat whole object as one snapshot
        snaps = [obj]
    for snap in snaps:
        store = snap.get("data_store") or obj.get("source")
        collection = snap.get("collection") or obj.get("collection")
        system_id = system_for_store(store)
        for rec in snap.get("records", []) or []:
            category = category_for(store, collection, rec)
            emails, uids = identifiers_of(rec)
            state = normalize_state(category, rec.get("account_status") or rec.get("status"), rec)
            rid = rec.get("resource_id")
            out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, state, rec, (emails, uids)))
    return out


def parse_service_export(obj, evidence_id, captured_at):
    out = []
    exports = obj.get("service_exports", {}) or {}
    for system_id, blocks in exports.items():
        for btype, items in (blocks or {}).items():
            for item in items or []:
                rid = item.get("resource_id")
                rec = dict(item)
                system_id = system_for_store(system_id)
                if system_id == "account_service":
                    category = "USER_PROFILE"
                    code = str(item.get("status_code") or "")
                    profile = item.get("profile") or {}
                    if code == "404" or profile in (None, {}) or profile.get("email") is None:
                        state = "ABSENT"
                    else:
                        state = "PRESENT"
                    if isinstance(profile, dict) and profile.get("email"):
                        rec["email"] = profile.get("email")
                elif system_id == "analytics_platform":
                    category = "ANALYTICS_PROFILE"
                    state = "ANONYMIZED" if not item.get("email") and not item.get("customer_reference") else "PRESENT"
                elif system_id == "backup_service":
                    category = "BACKUP_ARCHIVE"
                    state = "ACTIVE" if item.get("restore_allowed") is True else "BLOCKED"
                elif system_id == "export_service":
                    category = "USER_EXPORT"
                    state = "PRESENT"
                elif system_id == "integration_service":
                    category = "DATA_FLOW"
                    state = "ACTIVE" if item.get("enabled") is True else "DISABLED"
                elif system_id == "search_service":
                    category = "SEARCH_INDEX_ENTRY"
                    state = "PRESENT" if (item.get("hits") or {}).get("total", 0) > 0 else "ABSENT"
                elif system_id == "security_service":
                    category = "SECURITY_AUDIT_LOG"
                    state = "PRESENT"
                elif system_id == "support_platform":
                    category = "SUPPORT_MESSAGE"
                    has_direct_id = any(item.get(k) not in (None, "") for k in ("email", "phone", "requester_email", "owner_email"))
                    state = "REDACTED" if not has_direct_id else "PRESENT"
                else:
                    category = category_for(system_id, btype, item)
                    state = normalize_state(category, None, item)
                emails, uids = identifiers_of(rec)
                out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, state, rec, (emails, uids)))
    return out


def parse_sql(path, evidence_id, captured_at):
    out = []
    text = path.read_text(errors="replace")
    # direct-column table schemas known
    direct_schemas = {
        "customer_profiles": ("USER_PROFILE", ["resource_id", "user_id", "full_name", "email", "phone", "account_status", "updated_at"]),
        "customer_profiles_primary": ("USER_PROFILE", ["resource_id", "user_id", "full_name", "email", "phone", "account_status", "updated_at"]),
        "customer_profiles_failover_replica": ("USER_PROFILE", ["resource_id", "user_id", "full_name", "email", "phone", "account_status", "updated_at"]),
        "customer_profiles_read_replica": ("USER_PROFILE", ["resource_id", "user_id", "full_name", "email", "phone", "account_status", "updated_at"]),
        "search_documents_primary": ("SEARCH_INDEX_ENTRY", ["resource_id", "display_name", "email", "source_resource_id", "indexed_at"]),
        "customer_search_documents": ("SEARCH_INDEX_ENTRY", ["resource_id", "customer_reference", "display_name", "email", "phone", "email_hash", "index_name", "updated_at"]),
        "customer_analytics_profiles": ("ANALYTICS_PROFILE", ["resource_id", "customer_reference", "email", "phone", "email_hash", "audience_cohort", "updated_at"]),
        "support_records": ("SUPPORT_MESSAGE", ["resource_id", "customer_reference", "requester_name", "requester_email", "requester_phone", "message_excerpt", "updated_at"]),
        "customer_exports": ("USER_EXPORT", ["resource_id", "customer_reference", "owner_email", "owner_phone", "object_key", "updated_at"]),
        "connector_subscriptions": ("DATA_FLOW", ["resource_id", "customer_reference", "customer_email", "connector_name", "enabled", "last_delivery_status", "updated_at"]),
        "backup_restore_entries": ("BACKUP_ARCHIVE", ["resource_id", "customer_reference", "customer_email", "archive_key", "restore_allowed", "updated_at"]),
        "security_audit_records": ("SECURITY_AUDIT_LOG", ["resource_id", "subject_reference", "event_code", "retention_until", "updated_at"]),
    }
    for m in re.finditer(r'INSERT INTO\s+"?([\w]+)"?\s+VALUES\s*\((.*?)\);', text, re.S):
        table = m.group(1)
        vals_text = m.group(2)
        # split top-level commas respecting quotes
        parts = []
        cur = []
        in_q = False
        esc = False
        for ch in vals_text:
            if esc:
                cur.append(ch); esc = False; continue
            if ch == "\\":
                cur.append(ch); esc = True; continue
            if ch == "'" and not in_q:
                in_q = True; cur.append(ch); continue
            if ch == "'" and in_q:
                in_q = False; cur.append(ch); continue
            if ch == "," and not in_q:
                parts.append("".join(cur).strip()); cur = []; continue
            cur.append(ch)
        if cur:
            parts.append("".join(cur).strip())
        def unwrap(p):
            p = p.strip()
            if p.startswith("'") and p.endswith("'"):
                return p[1:-1].replace("''", "'")
            return p
        vals = [unwrap(p) for p in parts]
        if table in direct_schemas:
            category, cols = direct_schemas[table]
            rec = dict(zip(cols, vals))
            rid = rec.get(cols[0])
            system_id = system_for_store(table.split("_")[0])
            # parse json string fields if present
            for ck in ("record_json",):
                if ck in rec:
                    try:
                        jrec = json.loads(rec[ck])
                        emails, uids = identifiers_of(jrec)
                        rec.update(jrec)
                    except Exception:
                        emails, uids = identifiers_of(rec)
            else:
                emails, uids = identifiers_of(rec)
            # state
            if category == "USER_PROFILE":
                state = "ABSENT" if rec.get("account_status") in ("DELETED", "DELETION_PENDING", None, "") and not rec.get("email") else "PRESENT"
                if rec.get("account_status") == "DELETION_PENDING":
                    state = "PRESENT"
            elif category == "DATA_FLOW":
                state = "ACTIVE" if rec.get("enabled") == "1" else "DISABLED"
            elif category == "BACKUP_ARCHIVE":
                state = "ACTIVE" if rec.get("restore_allowed") == "1" else "BLOCKED"
            elif category == "ANALYTICS_PROFILE":
                has_id = any(rec.get(k) not in (None, "") for k in ("email", "phone", "email_hash"))
                state = "ANONYMIZED" if not has_id else "PRESENT"
            else:
                state = normalize_state(category, None, rec)
            out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, state, rec, (emails, uids)))
        elif table == "customer_data_primary" or table == "customer_data_read_replica":
            # record_json column
            if len(vals) >= 5:
                rid = unwrap(vals[0])
                origin_system = unwrap(vals[1])
                collection = unwrap(vals[2])
                json_text = unwrap(vals[3])
                try:
                    jrec = json.loads(json_text)
                except Exception:
                    jrec = {}
                category = category_for(origin_system, collection, jrec)
                system_id = system_for_store(origin_system)
                emails, uids = identifiers_of(jrec)
                state = normalize_state(category, None, jrec)
                rec = jrec
                rec["resource_id"] = rid
                out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, state, rec, (emails, uids)))
    return out


def parse_sql(path, evidence_id, captured_at):
    """Read every table from the SQLite-compatible snapshot without schema guesses."""
    out = []
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    try:
        db.executescript(path.read_text(errors="replace"))
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for table in tables:
            safe_table = table.replace('"', '""')
            for row in db.execute(f'SELECT * FROM "{safe_table}"'):
                rec = dict(row)
                if rec.get("record_json"):
                    try:
                        rec.update(json.loads(rec["record_json"]))
                    except (TypeError, json.JSONDecodeError):
                        pass
                rid = rec.get("resource_id")
                if not rid:
                    continue
                system = rec.get("origin_system") or rec.get("data_store") or rec.get("system_id") or table
                system_id = system_for_resource(rid) or system_for_store(system)
                collection = rec.get("collection_name") or rec.get("collection") or table
                category = category_for(system_id, collection, rec)
                emails, uids = identifiers_of(rec)
                if category == "DATA_FLOW":
                    state = "ACTIVE" if str(rec.get("enabled", "")).lower() in ("1", "true", "yes") else "DISABLED"
                elif category == "BACKUP_ARCHIVE":
                    state = "ACTIVE" if str(rec.get("restore_allowed", "")).lower() in ("1", "true", "yes") else "BLOCKED"
                elif category in ("ANALYTICS_PROFILE", "ACCOUNT_TOMBSTONE"):
                    state = normalize_state(category, None, rec)
                elif category == "USER_PROFILE":
                    state = "ABSENT" if str(rec.get("account_status", "")).upper() == "DELETED" and not any(rec.get(k) for k in ("email", "phone", "email_hash", "full_name", "name")) else "PRESENT"
                elif category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
                    state = "PRESENT"
                elif category == "SUPPORT_MESSAGE":
                    state = "PRESENT" if any(rec.get(k) for k in ("requester_name", "requester_email", "requester_phone", "email", "phone")) else "REDACTED"
                elif category == "EMAIL_DELIVERY_LOG":
                    state = "PRESENT" if any(rec.get(k) for k in ("email", "recipient_email")) else "REDACTED"
                else:
                    state = "PRESENT"
                out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, state, rec, (emails, uids)))
    finally:
        db.close()
    return out


FIELD_RE = re.compile(r'(\w+)="(?P<qv>[^"]*)"|(\w+)=(?P<uv>[^\s]+)')


def _fields(line):
    d = {}
    for m in FIELD_RE.finditer(line):
        key = m.group(1) or m.group(3)
        val = m.group("qv") if m.group("qv") is not None else m.group("uv")
        if key and val is not None:
            d[key] = val
    return d


def _log_identifier(fields, started_by_trace):
    """Return (emails, user_ids) for a log line, using the trace's started lookup."""
    emails, uids = [], []
    for k in ("lookup_key", "correlation_key", "subject_key", "match_key", "matched_value", "subject_reference"):
        v = fields.get(k)
        if v and v.lower() not in ("null", "none", ""):
            if re.fullmatch(r"user_[A-Za-z0-9]+", v, re.I):
                uids.append(v.strip())
            elif "@" in v or re.fullmatch(r"[0-9a-f]{64}", v, re.I):
                emails.append(v.strip().lower())
    for k in ("subject_reference", "subject_ref", "customer_reference", "subject_key"):
        v = fields.get(k)
        if v and v.lower() not in ("null", "none", ""):
            (uids if v.lower().startswith("user_") else emails).append(v.strip() if v.lower().startswith("user_") else v.strip().lower())
    v = fields.get("email")
    if v and v.lower() not in ("null", "none", ""):
        emails.append(v.strip().lower())
    v = fields.get("requester_email")
    if v and v.lower() not in ("null", "none", ""):
        emails.append(v.strip().lower())
    v = fields.get("owner_email")
    if v and v.lower() not in ("null", "none", ""):
        emails.append(v.strip().lower())
    tid = fields.get("trace_id")
    if tid and tid in started_by_trace:
        lk = started_by_trace[tid]
        if lk and lk.lower() not in ("null", "none", ""):
            emails.append(lk.strip().lower())
    return emails, uids


def _parse_log_fields(line):
    """Normalize key/value, bracketed, and pipe-delimited service log lines."""
    f = _fields(line)
    if "event" in f:
        return f
    bracketed = re.search(r"\[(?:DEBUG|INFO|WARN|ERROR)\]\s+\[([^]]+)\]\s+\[([^]]+)\]\s+([a-z][\w]+):", line, re.I)
    if bracketed:
        f.update(service=bracketed.group(1), trace_id=bracketed.group(2), event=bracketed.group(3))
        f.update(_fields(line[bracketed.end():]))
        return f
    parts = [p.strip() for p in line.split("|")]
    if len(parts) >= 5 and re.match(r"^\d{4}-\d\d-\d\dT", parts[0]):
        f.update(service=parts[2], trace_id=parts[3], event=parts[4])
        for part in parts[5:]:
            f.update(_fields(part))
    return f


def parse_log_lines(text, evidence_id, captured_at):
    out = []
    lines = text.splitlines()
    # First pass: capture started lookups keyed by trace_id so completed reads
    # can be attributed to the queried identity.
    started_by_trace = {}
    parsed = []
    for line in lines:
        f = _parse_log_fields(line)
        if not f or "event" not in f:
            continue
        parsed.append((line, f))
        if f["event"].endswith("_started") or f["event"].endswith("_start"):
            tid = f.get("trace_id")
            lk = f.get("lookup_key") or f.get("subject_key") or f.get("correlation_key")
            if tid and lk and lk.lower() not in ("null", "none", ""):
                started_by_trace[tid] = lk.strip().lower()
    for line, f in parsed:
        event = f["event"]
        rid = f.get("resource_id")
        system_id = system_for_store(f.get("service"))
        rec = dict(f)
        stamp = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)", line)
        if stamp:
            rec["observed_at"] = stamp.group(1)
        emails, uids = _log_identifier(f, started_by_trace)
        if event == "profile_lookup_completed":
            system_id = "account_service"
            category = "USER_PROFILE"
            rows = f.get("rows")
            state = "ABSENT" if (rows == "0" or f.get("http_status") == "404") else "PRESENT"
        elif event == "index_query_completed":
            system_id = "search_service"
            category = "SEARCH_INDEX_ENTRY"
            state = "PRESENT" if f.get("result") == "hit" else "ABSENT"
        elif event in ("analytics_profile_read_completed", "analytics_profile_read", "analytics_identity_scan"):
            system_id = "analytics_platform"
            category = "ANALYTICS_PROFILE"
            has_pii = any(f.get(k) not in (None, "", "null", "None") for k in ("email", "phone", "email_hash", "matched_value"))
            state = "PRESENT" if has_pii else ("ANONYMIZED" if event != "analytics_identity_scan" else "PRESENT")
        elif event in ("connector_config_read_completed", "connector_config_loaded"):
            system_id = "integration_service"
            category = "DATA_FLOW"
            state = "ACTIVE" if f.get("enabled") == "true" or (f.get("enabled") is None and f.get("scheduler_registered") == "true") else "DISABLED"
        elif event in ("restore_policy_read_completed", "restore_candidate_evaluated"):
            system_id = "backup_service"
            category = "BACKUP_ARCHIVE"
            active = f.get("restore_allowed") == "true" or (f.get("eligible") == "true" and f.get("deletion_block") != "true")
            state = "ACTIVE" if active else "BLOCKED"
        elif event == "connector_heartbeat":
            system_id = "integration_service"
            category = "DATA_FLOW"
            state = "ACTIVE" if f.get("enabled") == "true" or f.get("scheduler_registered") == "true" else "DISABLED"
        elif event in ("support_ticket_read_completed", "message_pii_scan", "attachment_pii_scan", "contact_query_completed", "contact_lookup_completed"):
            system_id = "support_platform"
            category = "SUPPORT_ATTACHMENT" if event == "attachment_pii_scan" else "SUPPORT_MESSAGE"
            if event in ("contact_query_completed", "contact_lookup_completed"):
                system_id = system_for_store(f.get("service")) or "support_platform"
                category = "SECONDARY_IDENTIFIER"
                rows = f.get("rows")
                state = "ABSENT" if (rows == "0" or f.get("http_status") == "404") else "PRESENT"
            else:
                state = "PRESENT" if any(f.get(k) not in (None, "", "null") for k in ("requester_name", "requester_email", "requester_phone", "matched_value")) else "PRESENT"
        elif event == "record_lookup":
            system_id = system_for_store(f.get("system") or f.get("service"))
            category = category_for(system_id, f.get("record_type"), {"resource_id": rid})
            state = "ABSENT" if f.get("result", "").upper() in ("NOT_FOUND", "ABSENT") else "PRESENT"
        elif event == "cache_lookup" and rid:
            system_id = system_for_store(f.get("service"))
            category = "CACHE_ENTRY"
            state = "PRESENT" if f.get("result", "").lower() in ("hit", "found") else "ABSENT"
        elif event == "audit_record_read_completed":
            system_id = "security_service"
            category = "SECURITY_AUDIT_LOG"
            state = "PRESENT"
        else:
            continue
        out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, state, rec, (emails, uids)))
    return out


def parse_structured_log(path, evidence_id, captured_at):
    # Some exports prefix JSON with an ISO timestamp; normalize the JSON object
    # to the same event parser used for key/value service logs.
    lines = []
    with open(path, errors="replace") as f:
        for line in f:
            brace = line.find("{")
            if brace < 0:
                continue
            try:
                obj = json.loads(line[brace:])
            except json.JSONDecodeError:
                continue
            hits = obj.get("hits") or {}
            if isinstance(hits, dict) and hits.get("total", 0):
                obj["result"] = "hit"
            fields = []
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    continue
                fields.append(f'{key}={json.dumps(value, ensure_ascii=False)}')
            lines.append(line[:brace].strip() + " " + " ".join(fields))
    return parse_log_lines("\n".join(lines), evidence_id, captured_at)


def parse_handover_txt(text, evidence_id, captured_at):
    out = []
    status_map = {
        "not_found": "ABSENT", "found": "PRESENT", "identifiable": "PRESENT",
        "anonymized": "ANONYMIZED", "redacted": "REDACTED", "active": "ACTIVE",
        "blocked": "BLOCKED", "disabled": "DISABLED",
    }
    cat_map = {
        "user_profile": "USER_PROFILE", "analytics_profile": "ANALYTICS_PROFILE",
        "search_index_entry": "SEARCH_INDEX_ENTRY", "backup_archive": "BACKUP_ARCHIVE",
        "user_export": "USER_EXPORT", "data_flow": "DATA_FLOW",
        "support_message": "SUPPORT_MESSAGE", "support_attachment": "SUPPORT_ATTACHMENT",
        "security_audit_log": "SECURITY_AUDIT_LOG", "account_tombstone": "ACCOUNT_TOMBSTONE",
    }
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        _ts, system, rid, category, status = parts[:5]
        identifier = parts[5] if len(parts) > 5 else ""
        system_id = system_for_store(system)
        category = cat_map.get(category.lower(), category_for(system, category, None))
        state = status_map.get(status.lower(), "PRESENT")
        emails = [identifier] if "@" in identifier else []
        uids = [identifier] if identifier.startswith("user_") else []
        rec = {"identifier": identifier}
        out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, state, rec, (emails, uids)))
    return out


def parse_pdf(path, evidence_id, captured_at):
    try:
        import fitz
    except Exception:
        return []
    out = []
    try:
        doc = fitz.open(str(path))
    except Exception:
        return []
    text = "\n".join(p.get_text() for p in doc)
    lines = text.splitlines()
    all_emails = {e.lower() for e in re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', text)}
    all_uids = set(re.findall(r'\buser_[A-Za-z0-9]+\b', text, re.I))
    seen = set()
    is_attachment = ("attachment" in path.stem.lower()) or ("attachment" in text.lower())
    prefix_re = re.compile(r'\b(account_[A-Za-z0-9]+|search_[A-Za-z0-9]+|support_[A-Za-z0-9]+|backup_[A-Za-z0-9]+|data_flow_[A-Za-z0-9]+|analytics_[A-Za-z0-9]+|export_[A-Za-z0-9]+|audit_record_[A-Za-z0-9]+|tombstone_[A-Za-z0-9]+)\b')
    for i, line in enumerate(lines):
        for rid in prefix_re.findall(line):
            if rid in seen:
                continue
            seen.add(rid)
            near = " ".join(lines[max(0, i - 1):min(len(lines), i + 2)])
            emails = {e.lower() for e in re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', near)}
            uids = set(re.findall(r'\buser_[A-Za-z0-9]+\b', near, re.I))
            if not emails and len(all_emails) == 1:
                emails = set(all_emails)
            if not uids and len(all_uids) == 1:
                uids = set(all_uids)
            system_id = system_for_resource(rid)
            category = "SUPPORT_ATTACHMENT" if (is_attachment and system_id == "support_platform") else category_for(system_id, "", {"resource_id": rid})
            out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, "PRESENT", {"ocr_text": text}, (emails, uids)))
    if not seen and len(all_emails) == 1:
        category = "SUPPORT_ATTACHMENT" if is_attachment else "SUPPORT_MESSAGE"
        out.append(obs_from_record(evidence_id, captured_at, "support_platform", category, "pdf_" + path.stem, "PRESENT", {}, (all_emails, set())))
    return out


def parse_image(path, evidence_id, captured_at):
    try:
        import pytesseract
        from PIL import Image
    except Exception:
        return []
    try:
        text = pytesseract.image_to_string(Image.open(str(path)))
    except Exception:
        return []
    def resources(s):
        found = set()
        patterns = {
            "audit_record": r"\baudit[ _.-]*records?[ _.-]*(\d[A-Za-z0-9]*)\b",
            "data_flow": r"\bdata[ _.-]*flow[ _.-]*(\d[A-Za-z0-9]*)\b",
            "tombstone": r"\btombstone[ _.-]*(\d[A-Za-z0-9]*)\b",
            "account": r"\baccount[ _.-]*(\d[A-Za-z0-9]*)\b",
            "analytics": r"\banalytics[ _.-]*(\d[A-Za-z0-9]*)\b",
            "search": r"\bsearch[ _.-]*(\d[A-Za-z0-9]*)\b",
            "support": r"\bsupport[ _.-]*(\d[A-Za-z0-9]*)\b",
            "backup": r"\bbackup[ _.-]*(\d[A-Za-z0-9]*)\b",
            "export": r"\bexport[ _.-]*(\d[A-Za-z0-9]*)\b",
            "marketing": r"\bmarketing[ _.-]*(\d[A-Za-z0-9]*)\b",
            "cache": r"\bcache[ _.-]*(\d[A-Za-z0-9]*)\b",
        }
        for prefix, pattern in patterns.items():
            found.update(f"{prefix}_{m.group(1)}" for m in re.finditer(pattern, s, re.I))
        return found

    # OCR is grouped by screen row so a decoy email in another row cannot be
    # attached to every resource visible in the same screenshot.
    from pytesseract import Output
    data = pytesseract.image_to_data(Image.open(str(path)), output_type=Output.DICT, config="--psm 11")
    words = []
    for i, token in enumerate(data["text"]):
        token = token.strip()
        if token and token != "|" and int(data["conf"][i] or -1) >= 15:
            words.append((int(data["top"][i]), int(data["left"][i]), token))
    rows = []
    for top, left, token in sorted(words):
        if not rows or top - rows[-1][0] > 8:
            rows.append([top, []])
        rows[-1][1].append((left, token))
    row_items = []
    for top, parts in rows:
        row_text = " ".join(v for _, v in sorted(parts))
        ids = resources(row_text)
        emails = {e.lower() for e in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", row_text)}
        if ids:
            row_items.append((ids, emails))
    all_emails = {e.lower() for e in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)}
    all_ids = resources(text)
    out, seen = [], set()
    for ids, row_emails in row_items:
        linked = row_emails or (all_emails if len(all_emails) == 1 else set())
        for rid in ids:
            key = rid
            if key in seen:
                continue
            seen.add(key)
            system_id = system_for_resource(rid)
            category = category_for(system_id, "", {"resource_id": rid})
            rec = {"ocr_text": text}
            if linked:
                rec["email"] = next(iter(linked)) if len(linked) == 1 else None
            out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, "PRESENT", rec, (linked, set())))
    # Some UI detail views put one focused subject email away from its resource row.
    if not out and all_ids:
        linked = all_emails if len(all_emails) == 1 else set()
        for rid in all_ids:
            system_id = system_for_resource(rid)
            category = category_for(system_id, "", {"resource_id": rid})
            rec = {"ocr_text": text, "email": next(iter(linked)) if len(linked) == 1 else None}
            out.append(obs_from_record(evidence_id, captured_at, system_id, category, rid, "PRESENT", rec, (linked, set())))
    return out


def list_evidence_files():
    """Return list of (evidence_id, path, captured_at, kind)."""
    files = []
    manifest = {}
    with open(DATASET / "evidence_files.csv", newline="") as f:
        for row in csv.DictReader(f):
            manifest[row["file_id"]] = row
    for root, _dirs, fnames in os.walk(EVIDENCE):
        for fn in fnames:
            p = Path(root) / fn
            rel = p.relative_to(EVIDENCE)
            # evidence id from filename stem or manifest
            eid = None
            cap = None
            for mid, mrow in manifest.items():
                mpath = mrow.get("file_path", "")
                if mpath == fn or mpath == str(rel) or mpath.endswith("/" + fn) or mrow.get("file_id") == p.stem:
                    eid = mid
                    cap = mrow.get("captured_at")
                    break
            if not eid:
                eid = p.stem
            kind = p.suffix.lower()
            files.append((eid, p, cap, kind))
    return files


def parse_evidence_file(eid, path, cap):
    kind = path.suffix.lower()
    try:
        if kind == ".json":
            obj = json.load(open(path, errors="replace"))
            if "snapshots" in obj:
                return parse_json_bundle(obj, eid, cap or obj.get("exported_at"))
            if "service_exports" in obj:
                return parse_service_export(obj, eid, cap or obj.get("exported_at"))
            if "records" in obj and "captured_at" in obj:
                return parse_json_bundle(obj, eid, cap or obj.get("captured_at"))
            return []
        if kind == ".sql":
            return parse_sql(path, eid, cap)
        if kind in (".log", ".txt"):
            text = path.read_text(errors="replace")
            # structured json-lines?
            if kind == ".log" and re.search(r"^\s*(?:\d{4}-\d\d-\d\dT[^ ]+\s+)?\{", text, re.M):
                return parse_structured_log(path, eid, cap)
            if re.search(r'\|\s*(?:USER_PROFILE|ANALYTICS_PROFILE|BACKUP_ARCHIVE|SUPPORT_MESSAGE|SUPPORT_ATTACHMENT|USER_EXPORT|DATA_FLOW|SECURITY_AUDIT_LOG|ACCOUNT_TOMBSTONE)\s*\|', text):
                return parse_handover_txt(text, eid, cap)
            return parse_log_lines(text, eid, cap)
        if kind == ".pdf":
            return parse_pdf(path, eid, cap)
        if kind in (".png", ".jpg", ".jpeg", ".tiff", ".bmp"):
            return parse_image(path, eid, cap)
    except Exception:
        return []
    return []


# ---------------------------------------------------------------------------
# Case analysis
# ---------------------------------------------------------------------------
def parse_ts(ts):
    if not ts:
        return None
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def find_account_resource(user_id, emails, observations, activities, requested_at, audit_at):
    """Determine the account resource_id for a user."""
    candidates = []
    for o in observations:
        if o["system_id"] == "account_service" and o["category"] == "USER_PROFILE":
            oemails, ouids = o["identifiers"]
            if (any(e in emails for e in oemails) or (user_id and user_id in ouids)) and o.get("resource_id"):
                candidates.append(o)
    if not candidates:
        return None
    candidates.sort(key=lambda o: parse_ts(o.get("observed_at")) or parse_ts(o.get("captured_at")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return candidates[0]["resource_id"]


def find_audit_resource(user_id, observations):
    for o in observations:
        if o["system_id"] == "security_service" and o["category"] == "SECURITY_AUDIT_LOG":
            oemails, ouids = o["identifiers"]
            if user_id in ouids:
                return o["resource_id"]
    return None


def analyze_case(case, by_email, by_id, audit_hist, evidence_obs_by_id, activities):
    case_id = case["case_id"]
    email = (case.get("email") or "").strip()
    audit_at = parse_ts(case.get("audit_at"))
    requested_at = parse_ts(case.get("requested_at"))
    request_text = case.get("request_text", "")

    steps = []

    # 1. authorization
    authorized = is_deletion_authorized(request_text)
    if not authorized:
        return "NOT_APPLICABLE", []

    # 2. identities
    user_id, emails, identifiers = resolve_identities(email, by_email, by_id, audit_hist, case.get("audit_at"))
    emails |= identifiers

    # 3. gather evidence captured <= audit_at
    obs = []
    used_evidence = set()
    for eid, obslst in evidence_obs_by_id.items():
        cap = obslst.get("_captured_at")
        cap_dt = parse_ts(cap) if cap else None
        if audit_at and cap_dt and cap_dt > audit_at:
            continue
        for o in obslst["obs"]:
            observed_dt = parse_ts(o.get("observed_at"))
            if audit_at and observed_dt and observed_dt > audit_at:
                continue
            oemails, ouids = o["identifiers"]
            match = any(e in emails for e in oemails) or (user_id and user_id in ouids)
            # also match by resource email present in record content
            if not match:
                rec = o.get("rec") or {}
                r_email = (rec.get("email") or rec.get("owner_email") or "").lower()
                if r_email in emails:
                    match = True
                doc = rec.get("document")
                if isinstance(doc, dict) and doc.get("email", "").lower() in emails:
                    match = True
            if match:
                obs.append(o)
                used_evidence.add(eid)

    # 4. account resource id
    account_id = find_account_resource(user_id, emails, obs, activities, requested_at, audit_at)
    audit_id = find_audit_resource(user_id, obs) if user_id else None

    # 5. build per-resource best state
    # group by resource_id
    by_resource = defaultdict(list)
    for o in obs:
        if o.get("resource_id"):
            by_resource[o["resource_id"]].append(o)

    records = []  # (resource, category, system, state, identifiers)
    for rid, obslist in by_resource.items():
        def observation_time(o):
            return parse_ts(o.get("observed_at")) or parse_ts(o.get("captured_at")) or datetime.min.replace(tzinfo=timezone.utc)
        obslist.sort(key=lambda o: (observation_time(o), o.get("evidence_id", "")))
        latest_time = observation_time(obslist[-1])
        newest = [o for o in obslist if observation_time(o) == latest_time]
        # At equal timestamps, preserve a conservative state if sources conflict.
        risky = [o for o in newest if o["state"] in ("PRESENT", "ACTIVE")]
        selected = risky[-1] if risky else newest[-1]
        state = selected["state"]
        o0 = selected
        records.append({
            "resource_id": rid,
            "category": o0["category"],
            "system_id": o0["system_id"],
            "state": state,
            "evidence_id": o0["evidence_id"],
            "observations": obslist,
            "rec": o0.get("rec") or {},
        })

    # 6. determine findings & remediation
    findings = []   # (op_order, system, resource, find_op, state, evidence_id)
    remediation = []  # (op_order, system, resource, remedy_op, final_state)
    verification = [] # (op_order, system, resource, verify_op, final_state, evidence_id or "")

    # account handling
    account_state = "ABSENT"
    account_obs = [r for r in records if r["resource_id"] == account_id]
    if account_obs:
        account_state = account_obs[0]["state"]

    # treatment per record
    for r in records:
        category = r["category"]
        treatment = treatment_for(category, r.get("rec"), case.get("audit_at"))
        if category == "DATA_FLOW":
            continue  # handled separately via data flow obs
        if r["resource_id"] == account_id:
            continue  # handled separately
        if r["resource_id"] == audit_id:
            continue  # audit is RETAIN; verify present only if complete
        if treatment == "DELETE":
            if r["state"] == "PRESENT":
                findings.append((FIND_OP_ORDER.index("REPORT_REMAINING_RECORD"), r["system_id"], r["resource_id"], "REPORT_REMAINING_RECORD", r["state"], r["evidence_id"]))
                remediation.append((REMED_OP_ORDER.index("DELETE_RECORD"), r["system_id"], r["resource_id"], "DELETE_RECORD", "ABSENT"))
                verification.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_ABSENT"), r["system_id"], r["resource_id"], "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        elif treatment == "REDACT":
            if r["state"] in ("PRESENT",):
                findings.append((FIND_OP_ORDER.index("REPORT_EXPOSED_PII"), r["system_id"], r["resource_id"], "REPORT_EXPOSED_PII", r["state"], r["evidence_id"]))
                remediation.append((REMED_OP_ORDER.index("REDACT_RECORD"), r["system_id"], r["resource_id"], "REDACT_RECORD", "REDACTED"))
                verification.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_REDACTED"), r["system_id"], r["resource_id"], "VERIFY_RECORD_REDACTED", "REDACTED", ""))
        elif treatment == "ANONYMIZE":
            if r["state"] == "PRESENT":
                findings.append((FIND_OP_ORDER.index("REPORT_EXPOSED_PII"), r["system_id"], r["resource_id"], "REPORT_EXPOSED_PII", r["state"], r["evidence_id"]))
                remediation.append((REMED_OP_ORDER.index("ANONYMIZE_RECORD"), r["system_id"], r["resource_id"], "ANONYMIZE_RECORD", "ANONYMIZED"))
                verification.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_ANONYMIZED"), r["system_id"], r["resource_id"], "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
        elif treatment == "RETAIN" and r["state"] == "PRESENT":
            verification.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_PRESENT"), r["system_id"], r["resource_id"], "VERIFY_RECORD_PRESENT", "PRESENT", ""))

    # data flows
    for r in records:
        if r["category"] == "DATA_FLOW" and r["state"] == "ACTIVE":
            findings.append((FIND_OP_ORDER.index("REPORT_ACTIVE_DATA_FLOW"), r["system_id"], r["resource_id"], "REPORT_ACTIVE_DATA_FLOW", r["state"], r["evidence_id"]))
            remediation.append((REMED_OP_ORDER.index("DISABLE_DATA_FLOW"), r["system_id"], r["resource_id"], "DISABLE_DATA_FLOW", "DISABLED"))
            verification.append((VERIFY_OP_ORDER.index("VERIFY_DATA_FLOW_DISABLED"), r["system_id"], r["resource_id"], "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
    # backups
    for r in records:
        if r["category"] == "BACKUP_ARCHIVE" and r["state"] == "ACTIVE":
            findings.append((FIND_OP_ORDER.index("REPORT_RESTORE_RISK"), r["system_id"], r["resource_id"], "REPORT_RESTORE_RISK", r["state"], r["evidence_id"]))
            remediation.append((REMED_OP_ORDER.index("BLOCK_RESTORE"), r["system_id"], r["resource_id"], "BLOCK_RESTORE", "BLOCKED"))
            verification.append((VERIFY_OP_ORDER.index("VERIFY_RESTORE_BLOCKED"), r["system_id"], r["resource_id"], "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))

    # account finding if present
    if account_state == "PRESENT":
        findings.append((FIND_OP_ORDER.index("REPORT_REMAINING_RECORD"), "account_service", account_id, "REPORT_REMAINING_RECORD", account_state, account_obs[0]["evidence_id"] if account_obs else ""))
        remediation.append((REMED_OP_ORDER.index("DELETE_RECORD"), "account_service", account_id, "DELETE_RECORD", "ABSENT"))
        verification.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_ABSENT"), "account_service", account_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    has_findings = bool(findings)

    # 7. status
    if not authorized:
        status = "NOT_APPLICABLE"
    elif not has_findings:
        status = "COMPLETE"
    else:
        status = "INCOMPLETE"

    # 8. build steps
    def step(n, phase, system, resource, op, state, evidence_id):
        return {
            "step_no": n,
            "phase": phase,
            "system_id": system,
            "resource_id": resource,
            "operation": op,
            "state": state,
            "evidence_id": evidence_id,
        }

    if status == "NOT_APPLICABLE":
        return status, []

    if status == "INCOMPLETE":
        # findings
        findings.sort(key=lambda x: (x[0], x[1], x[2]))
        # remediation
        remediation.sort(key=lambda x: (x[0], x[1], x[2]))
        # verification: account first (absent), then audit present, then per-resource
        # always include account absent verify + audit present verify
        verifies = []
        if account_id:
            verifies.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_ABSENT"), "account_service", account_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        if audit_id:
            verifies.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_PRESENT"), "security_service", audit_id, "VERIFY_RECORD_PRESENT", "PRESENT", ""))
        for v in verification:
            verifies.append((v[0], v[1], v[2], v[3], v[4], v[5]))
        # dedupe verification by (system, resource, op)
        seen_v = set()
        dedup_v = []
        for v in sorted(verifies, key=lambda x: (x[0], x[1], x[2])):
            key = (v[1], v[2], v[3])
            if key in seen_v:
                continue
            seen_v.add(key)
            dedup_v.append(v)
        all_steps = []
        n = 1
        for _, sys, rid, op, st, eid in findings:
            all_steps.append(step(n, "FINDING", sys, rid, op, st, eid)); n += 1
        for _, sys, rid, op, st in remediation:
            all_steps.append(step(n, "REMEDIATION", sys, rid, op, st, "")); n += 1
        for _, sys, rid, op, st, eid in dedup_v:
            all_steps.append(step(n, "VERIFICATION", sys, rid, op, st, eid)); n += 1
        return status, all_steps

    # COMPLETE: verification only, citing evidence
    verifies = []
    # Account absence can only be verified when an identity-linked resource was observed.
    acct_evid = ""
    if account_obs:
        acct_evid = account_obs[0]["evidence_id"]
    if account_id:
        verifies.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_ABSENT"), "account_service", account_id, "VERIFY_RECORD_ABSENT", "ABSENT", acct_evid))
    if audit_id:
        au = [r for r in records if r["resource_id"] == audit_id]
        verifies.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_PRESENT"), "security_service", audit_id, "VERIFY_RECORD_PRESENT", "PRESENT", au[0]["evidence_id"] if au else ""))
    for r in records:
        if r["resource_id"] in (account_id, audit_id):
            continue
        treatment = TREATMENT.get(r["category"], "DELETE")
        if r["state"] == "ABSENT" and treatment == "DELETE":
            verifies.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_ABSENT"), r["system_id"], r["resource_id"], "VERIFY_RECORD_ABSENT", "ABSENT", r["evidence_id"]))
        elif r["state"] == "REDACTED" and treatment == "REDACT":
            verifies.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_REDACTED"), r["system_id"], r["resource_id"], "VERIFY_RECORD_REDACTED", "REDACTED", r["evidence_id"]))
        elif r["state"] == "ANONYMIZED" and treatment == "ANONYMIZE":
            verifies.append((VERIFY_OP_ORDER.index("VERIFY_RECORD_ANONYMIZED"), r["system_id"], r["resource_id"], "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", r["evidence_id"]))
        elif r["category"] == "DATA_FLOW" and r["state"] == "DISABLED":
            verifies.append((VERIFY_OP_ORDER.index("VERIFY_DATA_FLOW_DISABLED"), r["system_id"], r["resource_id"], "VERIFY_DATA_FLOW_DISABLED", "DISABLED", r["evidence_id"]))
        elif r["category"] == "BACKUP_ARCHIVE" and r["state"] == "BLOCKED":
            verifies.append((VERIFY_OP_ORDER.index("VERIFY_RESTORE_BLOCKED"), r["system_id"], r["resource_id"], "VERIFY_RESTORE_BLOCKED", "BLOCKED", r["evidence_id"]))
    verifies.sort(key=lambda x: (x[0], x[1], x[2]))
    seen_v = set(); dedup_v = []
    for v in verifies:
        key = (v[1], v[2], v[3])
        if key in seen_v:
            continue
        seen_v.add(key)
        dedup_v.append(v)
    all_steps = []
    n = 1
    for _, sys, rid, op, st, eid in dedup_v:
        all_steps.append(step(n, "VERIFICATION", sys, rid, op, st, eid)); n += 1
    return status, all_steps


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    by_email, by_id = load_identities()
    audit_hist = load_audit_history()

    # pre-parse all evidence
    evidence_obs_by_id = {}
    for eid, p, cap, kind in list_evidence_files():
        obslist = parse_evidence_file(eid, p, cap)
        evidence_obs_by_id[eid] = {"obs": obslist, "_captured_at": cap}

    # load activities (for account fallback)
    activities = []
    act_path = DATASET / "system_activity.csv"
    if act_path.exists():
        with open(act_path, newline="") as f:
            activities = list(csv.DictReader(f))

    cases = []
    with open(DATASET / "deletion_requests.csv", newline="") as f:
        cases = list(csv.DictReader(f))

    rows = []
    for case in cases:
        status, steps = analyze_case(case, by_email, by_id, audit_hist, evidence_obs_by_id, activities)
        rows.append({
            "case_id": case["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(",", ":")),
        })

    rows.sort(key=lambda r: r["case_id"])
    with open(OUTPUT, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for r in rows:
            w.writerow([r["case_id"], r["deletion_status"], r["steps_json"]])

    print(f"Wrote {OUTPUT} with {len(rows)} rows")
    from collections import Counter
    print(Counter(r["deletion_status"] for r in rows))


if __name__ == "__main__":
    main()
