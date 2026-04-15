import requests
import json
import zipfile
import io
import xml.etree.ElementTree as ET

OUTPUT_FILE = "data/cwe_list.json"

def fetch_cwe_list():
    """Télécharge la liste officielle CWE depuis MITRE."""
    
    print("📥 Téléchargement de la liste CWE officielle depuis MITRE...")
    
    # URL officielle MITRE - liste complète CWE en XML
    url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    
    try:
        response = requests.get(url, timeout=30)
        print(f"✅ Téléchargement terminé ({len(response.content) // 1024} KB)")
        
        # Extraire le ZIP
        z = zipfile.ZipFile(io.BytesIO(response.content))
        xml_content = z.read(z.namelist()[0])
        
        print("🔍 Parsing XML...")
        
        # Parser le XML
        root = ET.fromstring(xml_content)
        namespace = {"cwe": "http://cwe.mitre.org/cwe-7"}
        
        cwe_dict = {}
        
        # Extraire toutes les faiblesses
        for weakness in root.iter("{http://cwe.mitre.org/cwe-7}Weakness"):
            cwe_id   = "CWE-" + weakness.get("ID", "")
            name     = weakness.get("Name", "")
            severity = weakness.get("Likelihood_Of_Exploit", "UNKNOWN")
            
            # Description
            desc_elem = weakness.find(".//{http://cwe.mitre.org/cwe-7}Description")
            description = desc_elem.text if desc_elem is not None else ""
            
            # Extended description
            ext_elem = weakness.find(".//{http://cwe.mitre.org/cwe-7}Extended_Description")
            extended = ext_elem.text if ext_elem is not None else ""
            
            # Relations
            relations = []
            for rel in weakness.findall(".//{http://cwe.mitre.org/cwe-7}Related_Weakness"):
                relations.append({
                    "nature": rel.get("Nature", ""),
                    "cwe_id": "CWE-" + rel.get("CWE_ID", "")
                })
            
            cwe_dict[cwe_id] = {
                "id":          cwe_id,
                "name":        name,
                "severity":    severity,
                "description": description[:500] if description else "",
                "extended":    extended[:300] if extended else "",
                "relations":   relations[:5]
            }
        
        print(f"✅ {len(cwe_dict)} CWE extraits")
        
        # Sauvegarder
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(cwe_dict, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Liste CWE sauvegardée dans : {OUTPUT_FILE}")
        
        # Afficher quelques exemples
        print(f"\n📋 Exemples :")
        for cwe_id in ["CWE-89", "CWE-79", "CWE-22", "CWE-78", "CWE-95", "CWE-327"]:
            if cwe_id in cwe_dict:
                print(f"  {cwe_id} : {cwe_dict[cwe_id]['name']}")
        
        return cwe_dict
        
    except Exception as e:
        print(f"❌ Erreur : {e}")
        return {}


if __name__ == "__main__":
    fetch_cwe_list()