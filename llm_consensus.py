"""
Module 1 — Multi-LLM Consensus
Calls Groq + Gemini + DeepSeek in parallel, picks a majority patch via
difflib.SequenceMatcher (threshold 0.80). Falls back to Groq alone.
"""
import os
import re
import json
import time
import difflib
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.json_io import locked_update as _locked_update

load_dotenv()

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
CONSENSUS_LOG  = os.path.join(BASE_DIR, "data", "consensus_log.json")
ERRORS_LOG     = os.path.join(BASE_DIR, "data", "llm_errors.json")

CONSENSUS_THRESHOLD = 0.80

# ── Groq ──────────────────────────────────────────────────────────────────────
try:
    from groq import Groq as _GroqClient
    _groq = _GroqClient(api_key=os.getenv("GROQ_API_KEY", ""))
    GROQ_OK = True
except Exception:
    GROQ_OK = False

# ── Gemini ────────────────────────────────────────────────────────────────────
try:
    import google.generativeai as genai
    _gemini_key = os.getenv("GEMINI_API_KEY", "")
    if _gemini_key:
        genai.configure(api_key=_gemini_key)
    GEMINI_OK = bool(_gemini_key)
except ImportError:
    GEMINI_OK = False

# ── DeepSeek (OpenAI-compat) ──────────────────────────────────────────────────
try:
    from openai import OpenAI as _OpenAIClient
    _deepseek_key = os.getenv("DEEPSEEK_API_KEY", "")
    _deepseek = _OpenAIClient(
        api_key=_deepseek_key or "no-key",
        base_url="https://api.deepseek.com/v1"
    ) if _deepseek_key else None
    DEEPSEEK_OK = bool(_deepseek_key)
except ImportError:
    DEEPSEEK_OK = False
    _deepseek = None


def _strip_markdown(text: str) -> str:
    text = re.sub(r"^```[a-zA-Z0-9+#]*\n?", "", text.strip())
    text = re.sub(r"\n?```$", "", text).strip()
    return text


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a.strip(), b.strip()).ratio()


def _append_json_log(path: str, entry: dict):
    """Atomically append *entry* to the JSON log at *path*, capped at 500 entries."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)

        def _do_append(data):
            data.append(entry)
            if len(data) > 500:
                return data[-500:]
            return data

        _locked_update(path, _do_append, [])
    except Exception:
        pass


class LLMConsensus:
    """
    Orchestrates parallel LLM calls and consensus voting.
    Usage:
        result = LLMConsensus().get_patch(vuln, code_context, rag_context)
        # result["fixed_code"]  — the winning patch
        # result["consensus"]   — dict with model votes, agreement, badge
    """

    def get_patch(self, vuln: dict, code_context: str = "", rag_context: str = "") -> dict:
        prompt = self._build_prompt(vuln, code_context, rag_context)
        patches = {}
        errors  = {}

        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {}
            futures[ex.submit(self._call_groq, prompt)]    = "groq"
            futures[ex.submit(self._call_gemini, prompt)]  = "gemini"
            futures[ex.submit(self._call_deepseek, prompt)]= "deepseek"

            for fut in as_completed(futures):
                model = futures[fut]
                try:
                    result = fut.result(timeout=90)
                    if result:
                        patches[model] = result
                except Exception as e:
                    errors[model] = str(e)

        consensus = self._vote(patches)
        consensus["errors"] = errors
        consensus["vuln_cwe"] = vuln.get("cwe", "")

        # Log
        ts = datetime.now().isoformat()
        _append_json_log(CONSENSUS_LOG, {
            "ts": ts,
            "cwe": vuln.get("cwe", ""),
            "file": os.path.basename(vuln.get("file", "")),
            "line": vuln.get("line", 0),
            "agreement": consensus["agreement"],
            "winner": consensus["winner"],
            "models_ok": list(patches.keys()),
            "models_failed": list(errors.keys()),
        })
        if errors:
            for m, err in errors.items():
                _append_json_log(ERRORS_LOG, {"ts": ts, "model": m, "error": err[:300]})

        fixed = consensus.get("fixed_code", "")
        return {"fixed_code": fixed, "consensus": consensus}

    # ── Voting ────────────────────────────────────────────────────────────────

    def _vote(self, patches: dict) -> dict:
        models = list(patches.keys())
        if not patches:
            return {"fixed_code": "", "winner": "none", "agreement": "0/0",
                    "badge": "⚠ No model responded", "votes": {}}

        # Single model — no consensus possible
        if len(patches) == 1:
            m = models[0]
            return {"fixed_code": patches[m], "winner": m,
                    "agreement": "1/1", "badge": f"⚠ Solo {m}",
                    "votes": {m: "sole"}}

        # Count pairwise agreements
        votes = {m: [] for m in models}
        for i in range(len(models)):
            for j in range(i + 1, len(models)):
                ma, mb = models[i], models[j]
                sim = _similarity(patches[ma], patches[mb])
                if sim >= CONSENSUS_THRESHOLD:
                    votes[ma].append(mb)
                    votes[mb].append(ma)

        # Find the patch agreed upon by most others
        best_model = max(models, key=lambda m: len(votes[m]))
        best_count = len(votes[best_model]) + 1  # self + agreeing others

        if best_count >= 2 and len(patches) >= 2:
            # Consensus reached
            badge = f"✓ Consensus {best_count}/{len(patches)}"
            return {
                "fixed_code":  patches[best_model],
                "winner":      best_model,
                "agreement":   f"{best_count}/{len(patches)}",
                "badge":       badge,
                "votes":       {m: votes[m] for m in models},
                "similarities": {
                    f"{models[i]}/{models[j]}": round(
                        _similarity(patches[models[i]], patches[models[j]]), 3)
                    for i in range(len(models)) for j in range(i+1, len(models))
                }
            }

        # No consensus — fall back to Groq
        fallback = patches.get("groq") or patches[models[0]]
        fallback_model = "groq" if "groq" in patches else models[0]
        return {
            "fixed_code":  fallback,
            "winner":      fallback_model,
            "agreement":   f"1/{len(patches)}",
            "badge":       f"⚠ Fallback {fallback_model}",
            "votes":       {m: votes[m] for m in models},
        }

    # ── Model Calls ───────────────────────────────────────────────────────────

    def _call_groq(self, prompt: str) -> str:
        if not GROQ_OK:
            return ""
        models = [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "meta-llama/llama-4-scout-17b-16e-instruct",
        ]
        for model in models:
            try:
                resp = _groq.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=2048,
                )
                return _strip_markdown(resp.choices[0].message.content)
            except Exception as e:
                if "429" in str(e) or "rate_limit" in str(e).lower():
                    time.sleep(3)
                    continue
                raise
        return ""

    def _call_gemini(self, prompt: str) -> str:
        if not GEMINI_OK:
            return ""
        try:
            model = genai.GenerativeModel("gemini-1.5-flash")
            resp  = model.generate_content(prompt)
            return _strip_markdown(resp.text)
        except Exception:
            try:
                model = genai.GenerativeModel("gemini-1.5-pro")
                resp  = model.generate_content(prompt)
                return _strip_markdown(resp.text)
            except Exception:
                return ""

    def _call_deepseek(self, prompt: str) -> str:
        if not DEEPSEEK_OK or _deepseek is None:
            return ""
        try:
            resp = _deepseek.chat.completions.create(
                model="deepseek-coder",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=2048,
            )
            return _strip_markdown(resp.choices[0].message.content)
        except Exception:
            return ""

    # ── Prompt ────────────────────────────────────────────────────────────────

    def _build_prompt(self, vuln: dict, code_context: str, rag_context: str) -> str:
        lang = vuln.get("language", "python")
        cwe  = vuln.get("cwe", "CWE-?")
        return f"""You are a security expert in {lang}. Fix the vulnerability below.

Vulnerability:
- CWE      : {cwe}
- File     : {vuln.get('file', '')}
- Line     : {vuln.get('line', 0)}
- Severity : {vuln.get('severity', '')}
- Message  : {vuln.get('message', '')}

{rag_context}

Code to fix:
```{lang}
{code_context}
```

Rules:
1. Fix ONLY the vulnerability above.
2. Do NOT change anything else.
3. Return ONLY the complete fixed code, no explanation, no markdown fences.
"""


# ── Module-level convenience function ─────────────────────────────────────────

_consensus = LLMConsensus()

def consensus_patch(vuln: dict, code_context: str = "", rag_context: str = "") -> dict:
    """Convenience wrapper: returns same dict as LLMConsensus.get_patch()."""
    return _consensus.get_patch(vuln, code_context, rag_context)
