from pathlib import Path
import re

p = Path("dashboard/app.py")
text = p.read_text(encoding="utf-8")
p.with_suffix(".py.delete-project-api.bak").write_text(text, encoding="utf-8")

route = r'''
@app.route('/projects/api/<project_id>', methods=['DELETE'])
@login_required
def delete_project_api(project_id):
    """Supprimer un projet depuis project_detail.html."""
    username = current_user()
    projects = _load_projects()
    project = projects.get(project_id)

    if not project:
        return jsonify({"ok": False, "error": "Projet introuvable"}), 404

    if project.get("owner") != username and session.get("role") != "admin":
        return jsonify({"ok": False, "error": "Seul le propriétaire ou l’admin peut supprimer ce projet"}), 403

    # Supprimer le projet
    projects.pop(project_id, None)
    _save_projects(projects)

    # Supprimer les analyses du projet si elles existent
    try:
        import shutil
        analysis_dir = os.path.join(ANALYSES_DIR, project_id)
        if os.path.isdir(analysis_dir):
            shutil.rmtree(analysis_dir)
    except Exception as e:
        print("[project delete] analyses cleanup error:", e)

    # Annuler les invitations liées au projet
    try:
        db = get_db_session()
        for inv in db.query(DBProjectInvitation).filter(DBProjectInvitation.project_id == project_id).all():
            inv.status = "cancelled"
        db.commit()
    except Exception as e:
        print("[project delete] invitations cleanup error:", e)

    try:
        audit_log("project_deleted", {
            "project_id": project_id,
            "project_name": project.get("name"),
            "deleted_by": username
        })
    except Exception:
        pass

    return jsonify({"ok": True})
'''

# Supprimer une ancienne route DELETE si elle existe déjà
text = re.sub(
    r"\n@app\.route\('/projects/api/<project_id>'[^)]*methods=\['DELETE'\][\s\S]*?(?=\n@app\.route|\nif __name__|$)",
    "\n",
    text,
    flags=re.S
)

# Ajouter avant if __name__
if "if __name__" in text:
    text = text.replace("if __name__", route + "\n\nif __name__", 1)
else:
    text += "\n\n" + route

p.write_text(text, encoding="utf-8")

print("✅ API suppression projet ajoutée/corrigée.")
print("Backup: dashboard/app.py.delete-project-api.bak")