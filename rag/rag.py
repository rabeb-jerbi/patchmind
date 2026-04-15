import faiss
import numpy as np
import json
import os
from datetime import datetime
from sentence_transformers import SentenceTransformer

model = SentenceTransformer('all-MiniLM-L6-v2')

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAG_FILE      = os.path.join(BASE_DIR, "data", "rag_examples.json")
CWE_LIST_FILE = os.path.join(BASE_DIR, "data", "cwe_list.json")


def load_examples(cwe_id):
    """Charge les exemples depuis rag_examples.json."""
    
    cwe_clean = cwe_id.split(":")[0].strip()
    
    if not os.path.exists(RAG_FILE):
        print(f"⚠️  Fichier RAG introuvable : {RAG_FILE}")
        return []
    
    with open(RAG_FILE, "r", encoding="utf-8") as f:
        db = json.load(f)
    
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
    
    # Charger la base existante
    if os.path.exists(RAG_FILE):
        with open(RAG_FILE, "r", encoding="utf-8") as f:
            db = json.load(f)
    else:
        db = {}
    
    # Créer la clé si elle n'existe pas
    if cwe_clean not in db:
        db[cwe_clean] = []
    
    # Vérifier si l'exemple existe déjà
    for example in db[cwe_clean]:
        if example["vulnerable"].strip() == vulnerable_code.strip():
            return False  # Déjà existant
    
    # Ajouter le nouvel exemple
    new_example = {
        "cwe":         cwe_clean,
        "source":      source,
        "description": f"Auto-saved validated fix — {datetime.now().strftime('%Y-%m-%d')}",
        "vulnerable":  vulnerable_code[:500],
        "fixed":       fixed_code[:500]
    }
    
    db[cwe_clean].append(new_example)
    
    # Sauvegarder
    with open(RAG_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    
    print(f"💾 Nouvel exemple sauvegardé pour {cwe_clean}")
    return True


def build_index(examples):
    """Construit l'index FAISS."""
    texts = [f"{e['cwe']} {e.get('description', '')} {e['vulnerable']}" for e in examples]
    embeddings = model.encode(texts)
    embeddings = np.array(embeddings, dtype='float32')
    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(embeddings)
    return index


def search_similar_fixes(vulnerable_code, cwe_id, k=2):
    """Cherche les fixes les plus similaires."""
    
    examples = load_examples(cwe_id)
    
    if not examples:
        return []
    
    index = build_index(examples)
    
    query = f"{cwe_id} {vulnerable_code}"
    query_embedding = model.encode([query])
    query_embedding = np.array(query_embedding, dtype='float32')
    
    k = min(k, len(examples))
    distances, indices = index.search(query_embedding, k)
    
    results = []
    for i in indices[0]:
        if i < len(examples):
            results.append(examples[i])
    
    return results


def get_cwe_description(cwe_id):
    """Récupère la description officielle d'un CWE depuis MITRE."""
    
    cwe_clean = cwe_id.split(":")[0].strip()
    
    if os.path.exists(CWE_LIST_FILE):
        with open(CWE_LIST_FILE, "r", encoding="utf-8") as f:
            cwe_list = json.load(f)
        
        if cwe_clean in cwe_list:
            cwe = cwe_list[cwe_clean]
            return {
                "id":          cwe["id"],
                "name":        cwe["name"],
                "description": cwe["description"],
                "severity":    cwe["severity"]
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