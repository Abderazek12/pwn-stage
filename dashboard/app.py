# LIGNES MAGIQUES POUR LES WEBSOCKETS EN TEMPS RÉEL (DOIT ÊTRE TOUT EN HAUT)
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, abort
from flask_socketio import SocketIO
import sqlite3
import os
import json
import subprocess
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import pty
import select
import termios
import struct
import fcntl

# --- IMPORT DES MODULES CUSTOM ---
from analyzer import analyze, run_checksec, parse_checksec_raw
from challenge_manager import import_challenge_zip

app = Flask(__name__)
app.secret_key = "cyber_secret_pwn_stage"

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

DB_PATH = "users.db"
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CASES_DIR = os.path.join(BASE_DIR, "cases")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(CASES_DIR, exist_ok=True)

active_terminals = {}

# ---------------- DB / Auth / Gamification ----------------
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        score INTEGER DEFAULT 0
    )""")
    try:
        cur.execute("ALTER TABLE user ADD COLUMN score INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass 
        
    cur.execute("""CREATE TABLE IF NOT EXISTS solves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        case_id TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(username, case_id)
    )""")
    
    if not cur.execute("SELECT 1 FROM user WHERE username='admin'").fetchone():
        cur.execute(
            "INSERT INTO user(username, password, score) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin"), 0)
        )
    con.commit()
    con.close()

init_db()

def login_required():
    return session.get("username") is not None

# ---------------- Results helpers ----------------
def result_path(case_id: str):
    return os.path.join(RESULTS_DIR, f"{case_id}.json")

def read_result_json(case_id: str):
    path = result_path(case_id)
    if not os.path.isfile(path): return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def write_result_json(case_id: str, payload: dict):
    path = result_path(case_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path

def list_all_results():
    items = []
    if not os.path.isdir(RESULTS_DIR): return items
    for fname in os.listdir(RESULTS_DIR):
        if not fname.endswith(".json"): continue
        case_id = fname[:-5]
        data = read_result_json(case_id) or {}
        difficulty = (data.get("difficulty") or "medium").lower()
        if difficulty not in ("low", "medium", "hard"): difficulty = "medium"
        items.append({
            "case_id": case_id,
            "title": data.get("title", case_id),
            "vuln_type": data.get("vuln_type", "N/A"),
            "difficulty": difficulty,
            "status": data.get("status", "unknown"),
            "timestamp": data.get("timestamp", ""),
            "notes": data.get("notes", ""),
            "checksec": data.get("checksec", {}),
        })
    items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return items

def compile_c_to_binary(src_c_path: str, out_path: str):
    cmd = ["gcc", src_c_path, "-o", out_path, "-g", "-fno-omit-frame-pointer", "-no-pie", "-Wno-implicit-function-declaration"]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return proc.returncode, proc.stdout

def find_binary_in_folder(folder: str):
    ignore_ext = (".c", ".py", ".txt", ".md", ".json")
    if not os.path.isdir(folder): return None
    candidates = []
    for fname in os.listdir(folder):
        full = os.path.join(folder, fname)
        if not os.path.isfile(full) or fname.endswith(ignore_ext): continue
        candidates.append(fname)
    if not candidates: return None
    lab = [c for c in candidates if c.startswith("lab_")]
    return lab[0] if lab else sorted(candidates)[0]

def list_cases():
    challenges = []
    if not os.path.isdir(CASES_DIR): return challenges
    for case_id in sorted(os.listdir(CASES_DIR)):
        case_folder = os.path.join(CASES_DIR, case_id)
        if not os.path.isdir(case_folder): continue
        files = os.listdir(case_folder)
        cfiles = [f for f in files if f.endswith(".c")]
        pyfiles = [f for f in files if f.endswith(".py") and f.startswith("exploit")]
        binary = find_binary_in_folder(case_folder)
        r = read_result_json(case_id) or {}
        challenges.append({
            "id": case_id,
            "title": r.get("title") or case_id,
            "vuln_type": r.get("vuln_type") or "N/A",
            "difficulty": r.get("difficulty", "medium").lower(),
            "description": r.get("notes") or "Pas de résultat JSON.",
            "cfiles": cfiles,
            "pyfiles": pyfiles,
            "binary": binary,
            "status": r.get("status", "unknown"),
        })
    return challenges

def group_cases_by_difficulty(challenges):
    groups = {"low": [], "medium": [], "hard": []}
    for ch in challenges:
        diff = ch.get("difficulty")
        if diff in groups: groups[diff].append(ch)
        else: groups["medium"].append(ch)
    return groups

# ---------------- ROUTES PRINCIPALES ----------------
@app.route("/")
def index():
    return render_template("index.html")

# NOUVELLE ROUTE POUR LA PAGE ABOUT ME
@app.route("/aboutme")
def aboutme():
    return render_template("aboutme.html")

@app.route("/dashboard")
def dashboard():
    if not login_required(): return redirect(url_for("login"))
    challenges = list_cases()
    groups = group_cases_by_difficulty(challenges)
    return render_template("dashboard.html", groups=groups, total=len(challenges))

@app.route("/challenge/<case_id>")
def challenge(case_id):
    if not login_required(): return redirect(url_for("login"))

    case_folder = os.path.join(CASES_DIR, case_id)
    if not os.path.isdir(case_folder): return "Challenge introuvable.", 404

    files = os.listdir(case_folder)
    cfiles = [f for f in files if f.endswith(".c")]
    pyfiles = [f for f in files if f.endswith(".py") and f.startswith("exploit")]
    binary = find_binary_in_folder(case_folder)

    result_json = read_result_json(case_id) or {}
    checksec_parsed = {}
    if binary:
        bin_path = os.path.join(case_folder, binary)
        checksec_raw = run_checksec(bin_path)
        checksec_parsed = parse_checksec_raw(checksec_raw)

    file_contents = {}
    for f in cfiles + pyfiles:
        try:
            with open(os.path.join(case_folder, f), "r", encoding="utf-8", errors="replace") as file_obj:
                file_contents[f] = file_obj.read()
        except Exception:
            file_contents[f] = "[Erreur: Impossible de lire le fichier]"

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT 1 FROM solves WHERE username=? AND case_id=?", (session['username'], case_id))
    is_solved = bool(cur.fetchone())
    con.close()

    return render_template(
        "challenge.html",
        case_id=case_id,
        title=result_json.get("title") or case_id,
        vuln_type=result_json.get("vuln_type") or "N/A",
        notes=result_json.get("notes") or "",
        difficulty=result_json.get("difficulty", "medium").lower(),
        cfiles=cfiles,
        pyfiles=pyfiles,
        binary=binary,
        checksec_parsed=checksec_parsed,
        is_solved=is_solved,
        file_contents=file_contents,
        result_json=result_json
    )

@app.route("/download/<case_id>/<path:fname>")
def download(case_id, fname):
    if not login_required(): return redirect(url_for("login"))
    return send_from_directory(os.path.join(CASES_DIR, case_id), fname, as_attachment=True)

@app.route("/test", methods=["GET", "POST"])
def test():
    if not login_required(): return redirect(url_for("login"))
    msg, analysis = "", None
    if request.method == "POST" and "file" in request.files:
        file = request.files["file"]
        if not file.filename.endswith(".c"):
            msg = "Erreur : seuls les fichiers .c sont autorisés."
        else:
            safe_name = secure_filename(file.filename)
            upload_path = os.path.join(UPLOADS_DIR, safe_name)
            file.save(upload_path)
            case_id = os.path.splitext(safe_name)[0]
            out_bin = os.path.join(UPLOADS_DIR, case_id)

            rc, compiler_out = compile_c_to_binary(upload_path, out_bin)
            binaire_analyse = out_bin if (rc == 0 and os.path.isfile(out_bin)) else None
            report = analyze(upload_path, binaire_analyse)

            payload = {"case_id": case_id, "title": f"Upload: {case_id}", "status": "analyzed", **report}
            write_result_json(case_id, payload)
            msg = f"Fichier analysé avec succès !"
            analysis = {"case_id": case_id, "compile_rc": rc, "report": report}
    return render_template("test.html", msg=msg, analysis=analysis)

@app.route("/import", methods=["GET", "POST"])
def import_zip():
    if not login_required(): return redirect(url_for("login"))
    msg, imported = "", None
    if request.method == "POST" and "zipfile" in request.files:
        z = request.files["zipfile"]
        if z.filename == "":
            msg = "Erreur : Aucun fichier sélectionné."
        else:
            try:
                case_id, case_folder, main_c = import_challenge_zip(z, CASES_DIR)
                out_bin = os.path.join(case_folder, f"lab_{case_id}")
                rc, compiler_out = compile_c_to_binary(main_c, out_bin)
                binaire_analyse = out_bin if rc == 0 and os.path.isfile(out_bin) else None
                report = analyze(main_c, binaire_analyse)
                payload = {"case_id": case_id, "title": case_id.upper(), "status": "success", **report}
                write_result_json(case_id, payload)
                msg = f"Succès ! Le challenge '{case_id}' a été importé."
                imported = case_id
            except Exception as e:
                msg = f"Erreur lors de l'import : {e}"
    return render_template("import.html", msg=msg, imported=imported)

# --- GAMIFICATION ---
def get_challenge_flag(case_folder, case_id):
    flag_path = os.path.join(case_folder, "flag.txt")
    if os.path.isfile(flag_path):
        with open(flag_path, "r", encoding="utf-8") as f: return f.read().strip()
    return f"PWN_STAGE{{{case_id}}}"

@app.route("/submit_flag/<case_id>", methods=["POST"])
def submit_flag(case_id):
    if not login_required(): return redirect(url_for("login"))
    submitted_flag = request.form.get("flag", "").strip()
    case_folder = os.path.join(CASES_DIR, case_id)
    if not os.path.isdir(case_folder): return redirect(url_for("dashboard"))
        
    correct_flag = get_challenge_flag(case_folder, case_id)
    result_json = read_result_json(case_id) or {}
    difficulty = result_json.get("difficulty", "medium").lower()
    points_map = {"low": 10, "medium": 30, "hard": 50}
    points_earned = points_map.get(difficulty, 30)

    username = session["username"]
    
    if submitted_flag == correct_flag:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        try:
            cur.execute("INSERT INTO solves (username, case_id) VALUES (?, ?)", (username, case_id))
            cur.execute("UPDATE user SET score = score + ? WHERE username = ?", (points_earned, username))
            con.commit()
            session['flash_msg'] = f"success|Bravo ! Flag correct. Vous avez gagné {points_earned} points."
        except sqlite3.IntegrityError:
            session['flash_msg'] = "warning|Vous avez déjà résolu ce challenge ! Points déjà accordés."
        finally:
            con.close()
    else:
        session['flash_msg'] = "danger|Flag incorrect, essayez encore..."
        
    return redirect(url_for('challenge', case_id=case_id))

@app.route("/leaderboard")
def leaderboard():
    if not login_required(): return redirect(url_for("login"))
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT username, score FROM user ORDER BY score DESC, id ASC")
    users = cur.fetchall()
    con.close()
    return render_template("leaderboard.html", users=users)

# --- RESULTS & AUTH ---
@app.route("/results")
def results_index():
    if not login_required(): return redirect(url_for("login"))
    results = list_all_results()
    return render_template("results.html", results=results, results_dir=RESULTS_DIR, results_count=len(results))

@app.route("/results/<case_id>")
def results_view(case_id):
    if not login_required(): return redirect(url_for("login"))
    data = read_result_json(case_id)
    if data is None: abort(404)
    return render_template("result_view.html", case_id=case_id, data=data, results_dir=RESULTS_DIR)

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u, p = request.form["username"], request.form["password"]
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT password FROM user WHERE username=?", (u,))
        row = cur.fetchone()
        con.close()
        if row and check_password_hash(row[0], p):
            session["username"] = u
            return redirect(url_for("dashboard"))
        msg = "Identifiants invalides."
    return render_template("login.html", msg=msg)

@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""
    if request.method == "POST":
        u, p = request.form["username"], request.form["password"]
        try:
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            cur.execute("INSERT INTO user (username, password, score) VALUES (?, ?, 0)", (u, generate_password_hash(p)))
            con.commit()
            msg = "Compte créé avec succès. Vous pouvez vous connecter !"
        except sqlite3.IntegrityError:
            msg = "Ce nom d'utilisateur est déjà pris."
        finally:
            con.close()
    return render_template("register.html", msg=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# =====================================================================
#                      PARTIE : TERMINAL WEB (SOCKETS)
# =====================================================================

def read_and_forward_pty_output(fd, sid):
    max_read_bytes = 1024 * 20
    while True:
        socketio.sleep(0.01)
        if sid not in active_terminals:
            break
        timeout_sec = 0
        (data_ready, _, _) = select.select([fd], [], [], timeout_sec)
        if data_ready:
            try:
                output = os.read(fd, max_read_bytes).decode('utf-8', 'replace')
                if not output: # EOF
                    break
                socketio.emit("pty-output", {"output": output}, to=sid, namespace="/pty")
            except OSError:
                break
    
    socketio.emit("pty-output", {"output": "\r\n\x1b[31m[!] Processus terminé.\x1b[0m\r\n"}, to=sid, namespace="/pty")

@socketio.on("pty-input", namespace="/pty")
def pty_input(data):
    sid = request.sid
    if sid in active_terminals:
        fd = active_terminals[sid]["fd"]
        try:
            os.write(fd, data["input"].encode())
        except OSError:
            pass

@socketio.on("resize", namespace="/pty")
def resize(data):
    sid = request.sid
    if sid in active_terminals:
        fd = active_terminals[sid]["fd"]
        try:
            winsize = struct.pack("HHHH", data["rows"], data["cols"], 0, 0)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
        except OSError:
            pass

@socketio.on("start-exploit", namespace="/pty")
def start_exploit(data):
    if not login_required(): return
        
    sid = request.sid
    case_id = data.get("case_id")
    file_to_run = data.get("file")
    mode = data.get("mode", "normal") # <--- MODIFICATION ICI : On récupère le mode
    
    case_folder = os.path.join(CASES_DIR, case_id)
    target_path = os.path.join(case_folder, file_to_run)
    
    if not os.path.isfile(target_path):
        socketio.emit("pty-output", {"output": f"\r\n[!] Erreur: Fichier {file_to_run} introuvable.\r\n"}, to=sid, namespace="/pty")
        return

    try:
        os.chmod(target_path, 0o755)
    except:
        pass

    # <--- MODIFICATION ICI : On vérifie si c'est GDB ou Python ou Normal
    if mode == "gdb":
        cmd = ["gdb", "./" + file_to_run]
    elif file_to_run.endswith(".py"):
        cmd = ["python3", "-u", file_to_run]
    else:
        cmd = ["./" + file_to_run]

    (child_pid, fd) = pty.fork()

    if child_pid == 0:
        os.chdir(case_folder)
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        try:
            os.execvpe(cmd[0], cmd, env)
        except Exception as e:
            print(f"Exec failed: {e}")
            os._exit(1)
    else:
        active_terminals[sid] = {"fd": fd, "child_pid": child_pid}
        socketio.start_background_task(target=read_and_forward_pty_output, fd=fd, sid=sid)

@socketio.on("disconnect", namespace="/pty")
def disconnect():
    sid = request.sid
    if sid in active_terminals:
        fd = active_terminals[sid]["fd"]
        child_pid = active_terminals[sid]["child_pid"]
        try:
            os.system(f"kill -9 {child_pid}")
            os.close(fd)
        except Exception:
            pass
        finally:
            del active_terminals[sid]
if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
