import os
import zipfile
import shutil
from werkzeug.utils import secure_filename

# Extensions autorisées dans le zip (pour la sécurité)
ALLOWED_EXTENSIONS = (".c", ".py", ".md", ".txt", ".json")

def import_challenge_zip(zip_file_storage, cases_dir: str):
    """
    Extrait un zip dans le dossier cases/ et cherche le fichier .c principal.
    """
    # Récupère le nom du fichier sans l'extension pour créer l'ID du challenge
    filename = secure_filename(zip_file_storage.filename or "challenge.zip")
    case_id = os.path.splitext(filename)[0]
    case_folder = os.path.join(cases_dir, case_id)
    
    os.makedirs(case_folder, exist_ok=True)
    tmp_zip = os.path.join(case_folder, "_upload.zip")
    zip_file_storage.save(tmp_zip)

    try:
        with zipfile.ZipFile(tmp_zip) as z:
            for member in z.infolist():
                if member.is_dir(): continue
                # Extraction à plat (sans les sous-dossiers du zip)
                name = os.path.basename(member.filename) 
                _, ext = os.path.splitext(name)
                
                if ext.lower() in ALLOWED_EXTENSIONS:
                    target_path = os.path.join(case_folder, name)
                    with z.open(member) as src, open(target_path, "wb") as out:
                        shutil.copyfileobj(src, out)
    finally:
        # On supprime le zip une fois extrait
        if os.path.exists(tmp_zip):
            os.remove(tmp_zip)

    # On cherche le fichier .c principal pour pouvoir le compiler ensuite
    main_c = None
    for f in os.listdir(case_folder):
        if f.endswith(".c"):
            main_c = os.path.join(case_folder, f)
            break

    if not main_c:
        raise ValueError("Le fichier ZIP ne contient aucun fichier .c")

    return case_id, case_folder, main_c
