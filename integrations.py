"""
integrations.py — Intégrations externes : Slack, Teams, Jira
Place à la racine : patchmind/integrations.py
"""
import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Config depuis .env ───────────────────────────────────────────────────────
SLACK_WEBHOOK_URL  = os.getenv("SLACK_WEBHOOK_URL", "")
TEAMS_WEBHOOK_URL  = os.getenv("TEAMS_WEBHOOK_URL", "")
JIRA_BASE_URL      = os.getenv("JIRA_BASE_URL", "")       # ex: https://mycompany.atlassian.net
JIRA_EMAIL         = os.getenv("JIRA_EMAIL", "")
JIRA_API_TOKEN     = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY   = os.getenv("JIRA_PROJECT_KEY", "PM")  # ex: PM, SEC, DEV

SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
    "LOW": "🟢", "ERROR": "🔴", "WARNING": "🟡"
}


# ── 1. SLACK ─────────────────────────────────────────────────────────────────

def notify_slack(metrics, results, username="unknown"):
    """Envoie un résumé d'analyse sur Slack."""
    if not SLACK_WEBHOOK_URL:
        print("⚠️  SLACK_WEBHOOK_URL non configuré")
        return False

    total     = metrics.get("total", 0)
    validated = metrics.get("validated", 0)
    rejected  = metrics.get("rejected", 0)
    rate      = metrics.get("success_rate", 0)
    mttr      = metrics.get("mttr", 0)

    # Top CWE
    cwe_counts = {}
    for r in results:
        cwe_counts[r.get("cwe","?")] = cwe_counts.get(r.get("cwe","?"), 0) + 1
    top_cwe = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:3]

    # Couleur barre latérale
    color = "#00ff88" if rate >= 80 else "#ffaa00" if rate >= 50 else "#ff4757"

    payload = {
        "username":   "PatchMind Bot",
        "icon_emoji": ":shield:",
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "🛡️ PatchMind — Analyse terminée"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Utilisateur*\n@{username}"},
                        {"type": "mrkdwn", "text": f"*Date*\n{datetime.now().strftime('%Y-%m-%d %H:%M')}"},
                        {"type": "mrkdwn", "text": f"*Vulnérabilités*\n{total} détectées"},
                        {"type": "mrkdwn", "text": f"*Patches*\n✅ {validated} validés · ❌ {rejected} rejetés"},
                        {"type": "mrkdwn", "text": f"*Success rate*\n{rate}%"},
                        {"type": "mrkdwn", "text": f"*MTTR moyen*\n{mttr}s"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Top CWE détectés :*\n" + "\n".join([f"• `{cwe}` — {count} occurrence(s)" for cwe, count in top_cwe]) if top_cwe else "Aucune vulnérabilité"}
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{'🏆 Excellent résultat !' if rate>=90 else '⚠️ Des vulnérabilités nécessitent une correction manuelle.' if rejected>0 else '✅ Toutes les vulnérabilités ont été corrigées.'}"
                    }
                }
            ]
        }]
    }

    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code == 200:
            print("✅ Notification Slack envoyée")
            return True
        else:
            print(f"❌ Slack erreur : {resp.status_code}")
            return False
    except Exception as e:
        print(f"❌ Slack exception : {e}")
        return False


# ── 2. MICROSOFT TEAMS ───────────────────────────────────────────────────────

def notify_teams(metrics, results, username="unknown"):
    """Envoie un résumé sur Microsoft Teams via Incoming Webhook."""
    if not TEAMS_WEBHOOK_URL:
        print("⚠️  TEAMS_WEBHOOK_URL non configuré")
        return False

    total     = metrics.get("total", 0)
    validated = metrics.get("validated", 0)
    rejected  = metrics.get("rejected", 0)
    rate      = metrics.get("success_rate", 0)
    mttr      = metrics.get("mttr", 0)

    color = "00ff88" if rate >= 80 else "ffaa00" if rate >= 50 else "ff4757"

    payload = {
        "@type":      "MessageCard",
        "@context":   "https://schema.org/extensions",
        "themeColor": color,
        "summary":    "PatchMind — Analyse terminée",
        "sections": [
            {
                "activityTitle":    "🛡️ PatchMind — Analyse de sécurité terminée",
                "activitySubtitle": f"Utilisateur : @{username} · {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "facts": [
                    {"name": "Vulnérabilités détectées", "value": str(total)},
                    {"name": "Patches validés",           "value": f"✅ {validated}"},
                    {"name": "Patches rejetés",           "value": f"❌ {rejected}"},
                    {"name": "Success rate",              "value": f"{rate}%"},
                    {"name": "MTTR moyen",                "value": f"{mttr}s"},
                ],
                "markdown": True
            }
        ],
        "potentialAction": [
            {
                "@type":   "OpenUri",
                "name":    "Voir le dashboard",
                "targets": [{"os": "default", "uri": "http://localhost:5000/dashboard"}]
            }
        ]
    }

    try:
        resp = requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code in [200, 202]:
            print("✅ Notification Teams envoyée")
            return True
        else:
            print(f"❌ Teams erreur : {resp.status_code}")
            return False
    except Exception as e:
        print(f"❌ Teams exception : {e}")
        return False


# ── 3. JIRA ──────────────────────────────────────────────────────────────────

def create_jira_tickets(results, username="unknown"):
    """Crée des tickets Jira pour chaque vulnérabilité rejetée."""
    if not all([JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN]):
        print("⚠️  Jira non configuré (JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN requis)")
        return []

    import base64
    auth = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type":  "application/json",
        "Accept":        "application/json"
    }

    # Créer un ticket par vulnérabilité non corrigée
    rejected = [r for r in results if not r.get("success")]
    created_tickets = []

    for vuln in rejected:
        cwe      = vuln.get("cwe", "CWE-?")
        severity = vuln.get("severity", "MEDIUM")
        sev_emoji = SEVERITY_EMOJI.get(severity.split("(")[0].strip(), "🟡")

        # Priorité Jira selon sévérité
        priority_map = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "ERROR": "High", "WARNING": "Medium"}
        priority = priority_map.get(severity.split("(")[0].strip(), "Medium")

        payload = {
            "fields": {
                "project":     {"key": JIRA_PROJECT_KEY},
                "summary":     f"{sev_emoji} [{cwe}] Vulnérabilité dans {vuln.get('file','?')} (ligne {vuln.get('line','?')})",
                "description": {
                    "type":    "doc",
                    "version": 1,
                    "content": [{
                        "type":    "paragraph",
                        "content": [{
                            "type": "text",
                            "text": f"Vulnérabilité détectée par PatchMind et non corrigée automatiquement.\n\n"
                                    f"• CWE : {cwe}\n"
                                    f"• Fichier : {vuln.get('file','?')}\n"
                                    f"• Ligne : {vuln.get('line','?')}\n"
                                    f"• Sévérité : {severity}\n"
                                    f"• Message : {vuln.get('message','')}\n"
                                    f"• Analysé par : @{username}\n"
                                    f"• Date : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
                                    f"Une correction manuelle est requise."
                        }]
                    }]
                },
                "issuetype": {"name": "Bug"},
                "priority":  {"name": priority},
                "labels":    ["security", "patchmind", cwe.lower().replace("-", "")],
            }
        }

        try:
            resp = requests.post(
                f"{JIRA_BASE_URL}/rest/api/3/issue",
                json=payload, headers=headers, timeout=15
            )
            if resp.status_code == 201:
                ticket = resp.json()
                ticket_key = ticket.get("key", "?")
                created_tickets.append({
                    "key":  ticket_key,
                    "url":  f"{JIRA_BASE_URL}/browse/{ticket_key}",
                    "cwe":  cwe,
                    "file": vuln.get("file","?"),
                })
                print(f"✅ Ticket Jira créé : {ticket_key} ({cwe})")
            else:
                print(f"❌ Jira erreur {resp.status_code} : {resp.text[:200]}")
        except Exception as e:
            print(f"❌ Jira exception : {e}")

    return created_tickets


# ── 4. NOTIFICATIONS GROUPÉES ────────────────────────────────────────────────

def send_all_notifications(metrics, results, username="unknown"):
    """Envoie toutes les notifications configurées."""
    sent = {}
    if SLACK_WEBHOOK_URL:
        sent["slack"] = notify_slack(metrics, results, username)
    if TEAMS_WEBHOOK_URL:
        sent["teams"] = notify_teams(metrics, results, username)
    if JIRA_BASE_URL:
        tickets = create_jira_tickets(results, username)
        sent["jira"] = {"created": len(tickets), "tickets": tickets}
    return sent