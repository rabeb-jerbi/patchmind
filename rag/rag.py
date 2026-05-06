import faiss
import numpy as np
import json
import os
import sys
import threading
from datetime import datetime
from sentence_transformers import SentenceTransformer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.json_io import read_json as _read_json, locked_update as _locked_update

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAG_FILE      = os.path.join(BASE_DIR, "data", "rag_examples.json")
CWE_LIST_FILE = os.path.join(BASE_DIR, "data", "cwe_list.json")

# ── Lazy model loading — avoids blocking Flask startup ────────────────────────
_model       = None
_model_lock  = threading.Lock()


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        with _model_lock:
            if _model is None:
                _model = SentenceTransformer('all-MiniLM-L6-v2')
    return _model


# ── CWE description cache — file is static, read once ─────────────────────────
_cwe_list_cache: dict = {}
_cwe_cache_loaded = False


def _load_cwe_list() -> dict:
    global _cwe_list_cache, _cwe_cache_loaded
    if not _cwe_cache_loaded:
        if os.path.exists(CWE_LIST_FILE):
            _cwe_list_cache = _read_json(CWE_LIST_FILE, {})
        _cwe_cache_loaded = True
    return _cwe_list_cache


def load_examples(cwe_id):
    """Charge les exemples depuis rag_examples.json."""
    cwe_clean = cwe_id.split(":")[0].strip()

    if not os.path.exists(RAG_FILE):
        print(f"⚠️  Fichier RAG introuvable : {RAG_FILE}")
        return []

    db = _read_json(RAG_FILE, {})
    examples = db.get(cwe_clean, [])

    if examples:
        local  = [e for e in examples if e.get("source") == "local"]
        real   = [e for e in examples if e.get("source") != "local"]
        print(f"✅ {len(real)} exemple(s) OSV+GitHub + {len(local)} exemple(s) locaux")
    else:
        print(f"⚠️  Aucun exemple trouvé pour {cwe_clean}")

    return examples


def save_new_example(cwe_id, vulnerable_code, fixed_code, source="validated"):
    """Sauvegarde un nouvel exemple validé dans rag_examples.json."""
    cwe_clean = cwe_id.split(":")[0].strip()
    new_example = {
        "cwe":         cwe_clean,
        "source":      source,
        "description": f"Auto-saved validated fix — {datetime.now().strftime('%Y-%m-%d')}",
        "vulnerable":  vulnerable_code[:500],
        "fixed":       fixed_code[:500],
    }

    def _do_save(db):
        if cwe_clean not in db:
            db[cwe_clean] = []
        for example in db[cwe_clean]:
            if example["vulnerable"].strip() == vulnerable_code.strip():
                return db  # already exists — no change
        db[cwe_clean].append(new_example)
        return db

    try:
        _locked_update(RAG_FILE, _do_save, {})
        print(f"💾 Nouvel exemple sauvegardé pour {cwe_clean}")
        return True
    except Exception as e:
        print(f"⚠️  save_new_example error: {e}")
        return False


def build_index(examples):
    """Construit l'index FAISS."""
    m = _get_model()
    texts = [f"{e['cwe']} {e.get('description', '')} {e['vulnerable']}" for e in examples]
    embeddings = m.encode(texts)
    embeddings = np.array(embeddings, dtype='float32')
    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(embeddings)
    return index


def search_similar_fixes(vulnerable_code, cwe_id, k=2):
    """Cherche les fixes les plus similaires."""
    examples = load_examples(cwe_id)

    if not examples:
        return []

    m     = _get_model()
    index = build_index(examples)

    query           = f"{cwe_id} {vulnerable_code}"
    query_embedding = np.array(m.encode([query]), dtype='float32')

    k = min(k, len(examples))
    distances, indices = index.search(query_embedding, k)

    results = []
    for i in indices[0]:
        if i < len(examples):
            results.append(examples[i])

    return results


def get_cwe_description(cwe_id):
    """Récupère la description officielle d'un CWE depuis le cache MITRE."""
    cwe_clean = cwe_id.split(":")[0].strip()
    cwe_list  = _load_cwe_list()

    cwe = cwe_list.get(cwe_clean)
    if cwe:
        return {
            "id":          cwe["id"],
            "name":        cwe["name"],
            "description": cwe["description"],
            "severity":    cwe["severity"],
        }
    return None


if __name__ == "__main__":
    fixes = search_similar_fixes(
        "query = 'SELECT * FROM users WHERE id = ' + user_id",
        "CWE-89"
    )

    print(f"\n✅ {len(fixes)} fix(es) trouvé(s) :\n")
    for i, fix in enumerate(fixes, 1):
        print(f"  📌 Fix {i} :")
        print(f"     Source     : {fix.get('source', 'unknown')}")
        print(f"     CWE        : {fix['cwe']}")
        print(f"     Description: {fix.get('description', '')[:80]}")
        print(f"     Vulnérable : {fix['vulnerable'][:80]}")
        print(f"     Corrigé    : {fix['fixed'][:80]}")
        print()
