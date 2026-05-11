"""
Module 1 — Multi-LLM Consensus
Calls Groq + Gemini + Ollama in parallel, picks a majority patch via
difflib.SequenceMatcher (threshold 0.80). Falls back to Groq alone.
"""
import os
import re
import json
import time
import difflib
import sys
import requests
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
    _gemini_key = os.getenv("GEMINI_API_KEY")
    if _gemini_key:
        genai.configure(api_key=_gemini_key)
    GEMINI_OK = bool(_gemini_key)
except ImportError:
    GEMINI_OK = False

# ── Ollama (local) ────────────────────────────────────────────────────────────
OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "codellama")
OLLAMA_OK    = True  # optimistically true; checked at call time


def _strip_markdown(text: str) -> str:
    text = re.sub(r"^```[a-zA-Z0-9+#]*\n?", "", text.strip())
    text = re.sub(r"\n?```$", "", text).strip()
    return text


def normalize_patch_output(text: str) -> str:
    """Normalize LLM output before similarity comparison.

    Strips markdown fences, inline explanations/comments, and normalises
    whitespace so that semantically identical patches from different models
    are not penalised for cosmetic differences.
    """
    if not text:
        return ""
    # Remove markdown code fences
    text = re.sub(r"^```[a-zA-Z0-9+#]*\n?", "", text.strip())
    text = re.sub(r"\n?```$", "", text).strip()
    # Remove leading explanation lines (lines that contain no code-like tokens)
    lines = text.splitlines()
    code_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip blank lines and lines that look like natural-language prose
        if not stripped:
            continue
        if re.match(r'^(here|this|the|i |sure|of course|below|fixed|output|result)', stripped, re.IGNORECASE):
            code_start = i + 1
        else:
            break
    lines = lines[code_start:]
    # Normalise indentation: replace tabs with 4 spaces, collapse trailing spaces
    normalised = []
    for line in lines:
        line = line.replace("\t", "    ").rstrip()
        normalised.append(line)
    # Remove consecutive blank lines (keep at most one)
    result_lines = []
    prev_blank = False
    for line in normalised:
        is_blank = line.strip() == ""
        if is_blank and prev_blank:
            continue
        result_lines.append(line)
        prev_blank = is_blank
    return "\n".join(result_lines).strip()


def _similarity(a: str, b: str) -> float:
    na, nb = normalize_patch_output(a), normalize_patch_output(b)
    return difflib.SequenceMatcher(None, na, nb).ratio()


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
            futures[ex.submit(self._call_groq, prompt)]   = "groq"
            futures[ex.submit(self._call_gemini, prompt)] = "gemini"
            futures[ex.submit(self._call_ollama, prompt)] = "ollama"

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
            model = genai.GenerativeModel("gemini-2.0-flash")
            resp  = model.generate_content(prompt)
            return _strip_markdown(resp.text)
        except Exception:
            try:
                model = genai.GenerativeModel("gemini-2.0-flash")
                resp  = model.generate_content(prompt)
                return _strip_markdown(resp.text)
            except Exception:
                return ""

    def _call_ollama(self, prompt: str) -> str:
        try:
            resp = requests.post(
                OLLAMA_URL,
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                timeout=90,
            )
            resp.raise_for_status()
            return _strip_markdown(resp.json().get("response", ""))
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
