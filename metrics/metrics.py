import time
import json
import os
from datetime import datetime

METRICS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "metrics.json")

class PatchMindMetrics:
    """Collecte et sauvegarde les métriques de PatchMind."""
    
    def __init__(self):
        self.session = {
            "timestamp":       datetime.now().isoformat(),
            "total_vulns":     0,
            "patches_validated": 0,
            "patches_rejected":  0,
            "success_rate":    0.0,
            "mttr_seconds":    0.0,
            "vulns":           []
        }
        self.start_time = time.time()
    
    def start_vuln(self, vuln):
        """Démarre le chronomètre pour une vulnérabilité."""
        self._current_vuln = {
            "cwe":        vuln["cwe"].split(":")[0].strip(),
            "file":       vuln["file"],
            "line":       vuln["line"],
            "severity":   vuln["severity"],
            "start_time": time.time(),
            "stages":     {}
        }
    
    def record_stage(self, stage_name, duration):
        """Enregistre le temps d'une étape."""
        self._current_vuln["stages"][stage_name] = round(duration, 2)
    
    def end_vuln(self, success):
        """Termine le chronomètre pour une vulnérabilité."""
        duration = time.time() - self._current_vuln["start_time"]
        self._current_vuln["total_seconds"] = round(duration, 2)
        self._current_vuln["success"]       = success
        self.session["vulns"].append(self._current_vuln)
        self.session["total_vulns"] += 1
        
        if success:
            self.session["patches_validated"] += 1
        else:
            self.session["patches_rejected"] += 1
    
    def finalize(self):
        """Calcule les métriques finales."""
        total = self.session["total_vulns"]
        
        if total > 0:
            self.session["success_rate"] = round(
                self.session["patches_validated"] / total * 100, 1
            )
            
            # MTTR moyen
            durations = [v["total_seconds"] for v in self.session["vulns"] if v["success"]]
            if durations:
                self.session["mttr_seconds"] = round(sum(durations) / len(durations), 2)
        
        self.session["total_duration"] = round(time.time() - self.start_time, 2)
        
        # Sauvegarder
        self._save()
        
        # Afficher
        self._display()
    
    def _save(self):
        """Sauvegarde les métriques dans un fichier JSON."""
        history = []
        
        if os.path.exists(METRICS_FILE):
            with open(METRICS_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)

        history.append(self.session)

        with open(METRICS_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
        
        print(f"\n📊 Métriques sauvegardées dans : {METRICS_FILE}")
    
    def _display(self):
        """Affiche les métriques."""
        print(f"\n{'=' * 60}")
        print(f"📊 MÉTRIQUES PATCHMIND")
        print(f"{'=' * 60}")
        print(f"  📅 Session        : {self.session['timestamp'][:19]}")
        print(f"  🔢 Total vulns    : {self.session['total_vulns']}")
        print(f"  ✅ Validés        : {self.session['patches_validated']}")
        print(f"  ❌ Rejetés        : {self.session['patches_rejected']}")
        print(f"  📈 Success rate   : {self.session['success_rate']}%")
        print(f"  ⏱️  MTTR moyen     : {self.session['mttr_seconds']} sec")
        print(f"  ⏱️  Durée totale   : {self.session['total_duration']} sec")
        print(f"\n  Détail par vulnérabilité :")
        for v in self.session["vulns"]:
            status = "✅" if v["success"] else "❌"
            print(f"  {status} {v['cwe']} ({v['file']}:{v['line']}) → {v['total_seconds']}s")