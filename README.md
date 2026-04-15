# 🔒 PatchMind — Automated Vulnerability Remediation System

> *De la détection passive à la remédiation automatique, intelligente et mesurable*

---

## 📋 Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Utilisation](#utilisation)
5. [Structure du projet](#structure-du-projet)
6. [Technologies](#technologies)
7. [Résultats](#résultats)

---

## 🎯 Vue d'ensemble

PatchMind est une plateforme open source qui **automatise l'ensemble du cycle de remédiation des vulnérabilités logicielles** :

- 🔍 **Détection** automatique avec Semgrep (SAST)
- 🌐 **Enrichissement** via standards CWE/CVE (NVD API)
- 🧠 **Génération** intelligente de patches (RAG + LLM)
- ✅ **Validation** stricte multi-couches
- 📊 **Métriques** temps réel

**Résultat :** MTTR moyen de **~15 secondes** vs 3 jours manuellement.

---

## 🏗️ Architecture
Git Repo → Semgrep → CWE → NVD API → RAG → LLM → Patch → Validation → Fichier corrigé
### Pipeline détaillé

| Étape | Module | Description |
|-------|--------|-------------|
| 1 | `scanner/` | Scan SAST avec Semgrep |
| 2 | `enricher/` | Enrichissement NVD API |
| 3 | `rag/` | Recherche sémantique FAISS |
| 4 | `generator/` | Génération patch (Groq LLM) |
| 5 | `validator/` | Validation multi-couches |
| 6 | `metrics/` | Collecte métriques |

---

## ⚙️ Installation

### Prérequis

- Python 3.9+
- Git

### Étapes
```bash
# 1. Cloner le projet
git clone https://github.com/username/patchmind.git
cd patchmind

# 2. Créer environnement virtuel
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer les clés API
cp .env.example .env
# Editer .env avec tes clés
```

### Configuration `.env`
GROQ_API_KEY=gsk_...
GITHUB_TOKEN=ghp_...
### Mettre à jour la base CVEfixes
```bash
python data/fetch_cvefixes.py
```

---

## 🚀 Utilisation

### Lancer le pipeline complet
```bash
python main.py
```

### Tester sur un fichier spécifique

Modifie dans `main.py` :
```python
file_path = "ton_fichier.py"
```

### Mettre à jour les exemples CVEfixes
```bash
python data/fetch_cvefixes.py
```

---

## 📁 Structure du projet
patchmind/
├── scanner/
│   └── scanner.py          # Détection Semgrep
├── enricher/
│   └── enricher.py         # NVD API
├── rag/
│   └── rag.py              # RAG FAISS
├── generator/
│   └── generator.py        # LLM Groq
├── validator/
│   └── validator.py        # Validation
├── metrics/
│   └── metrics.py          # Métriques
├── data/
│   ├── fetch_cvefixes.py   # Script mise à jour
│   ├── cvefixes_cache.json # Vrais exemples OSV+GitHub
│   ├── local_examples.json # Exemples locaux
│   └── metrics.json        # Historique métriques
├── main.py                 # Pipeline principal
├── requirements.txt
├── .env                    # Clés API (ne pas committer)
└── README.md

---

## 🛠️ Technologies

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| **Langage** | Python 3.9+ | Développement |
| **SAST** | Semgrep | Détection vulnérabilités |
| **Standards** | CWE, CVE, NVD API | Classification |
| **Données** | OSV API + GitHub API | Exemples réels |
| **LLM** | Groq (Llama 3.3) | Génération patches |
| **RAG** | FAISS + sentence-transformers | Recherche sémantique |
| **Métriques** | JSON | Observabilité |

---

## 📊 Résultats

### Sur `test_multi_vuln.py` (3 vulnérabilités)

| Vulnérabilité | CWE | Résultat | Temps |
|--------------|-----|----------|-------|
| SQL Injection | CWE-89 | ✅ VALIDÉ | 14.6s |
| XSS | CWE-79 | ✅ VALIDÉ | 14.6s |
| Path Traversal | CWE-22 | ✅ VALIDÉ | 14.7s |

### Métriques globales
✅ Success rate  : 100%
⏱️  MTTR moyen   : 14.65 secondes
⏱️  Durée totale : 50.38 secondes

---

## 📝 Limites

- Les métriques sont basées sur un MVP — pas encore testées en production
- Support actuel : Python uniquement
- Dépend de la qualité des règles Semgrep
- Nécessite une connexion internet pour NVD API et Groq

---
*PatchMind : De la détection passive à la remédiation automatique, intelligente et mesurable.*
