import os
import re
import subprocess
from datetime import datetime

# --- PWNTOOLS ENGINE (Correction du bug de démarrage) ---
# On désactive l'interface terminal de pwntools pour le mode web
os.environ['PWNLIB_NOTERM'] = '1'
os.environ['PWNLIB_SILENT'] = '1'

from pwn import ELF, ROP, context
context.log_level = 'error'

def _run(cmd, cwd=None, timeout=10):
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except Exception as e:
        return -1, f"[error running {cmd}]: {e}"

def run_checksec(binary_path: str):
    rc, out = _run(["checksec", "--file", binary_path])
    if rc != 0 and "not found" in out: return "[!] checksec introuvable."
    return out

def parse_checksec_raw(raw: str):
    info = {}
    for key in ["RELRO", "Canary", "NX", "PIE"]:
        m = re.search(rf"{key}:\s*(.*)", raw)
        if m: info[key.lower()] = m.group(1).strip()
    return info

def file_type(path: str):
    rc, out = _run(["file", path])
    return out.strip()

def strings_scan(binary_path: str):
    rc, out = _run(["strings", "-a", binary_path], timeout=15)
    hits = [n for n in ["/bin/sh", "flag", "CTF", "win", "system", "admin"] if n in out]
    return {"hits": list(set(hits))}

def symbols_scan(binary_path: str):
    rc, out = _run(["nm", "-an", binary_path])
    found = [sym for sym in ["win", "system", "printf", "puts", "main", "execve", "malloc", "free"] if re.search(rf"\b{sym}\b", out)]
    return {"found_symbols": list(set(found))}

# ====================================================================
# MODULE : DEEP ELF AUTOSPY (NIVEAU INTERMÉDIAIRE/EXPERT)
# ====================================================================
def deep_elf_analysis(binary_path: str):
    analysis = {
        "arch": "unknown",
        "plt_imports": [],
        "got_entries": [],
        "rop_gadgets": [],
        "useful_strings_addrs": {},
        "memory_layout": {}
    }
    
    if not binary_path or not os.path.isfile(binary_path): return analysis

    try:
        exe = ELF(binary_path)
        analysis["arch"] = f"{exe.arch} ({exe.bits} bits) - {exe.endian}"
        
        # Sections Mémoire (Utile pour le Stack Pivoting ou stocker des données)
        if '.bss' in exe.sections:
            analysis["memory_layout"][".bss (Writeable)"] = hex(exe.get_section_by_name('.bss').header.sh_addr)
        if '.data' in exe.sections:
            analysis["memory_layout"][".data (Writeable)"] = hex(exe.get_section_by_name('.data').header.sh_addr)

        analysis["plt_imports"] = list(exe.plt.keys())[:15]
        analysis["got_entries"] = list(exe.got.keys())[:15]
        
        sh_addr = next(exe.search(b'/bin/sh'), None)
        if sh_addr: analysis["useful_strings_addrs"]["/bin/sh"] = hex(sh_addr)

        try:
            rop = ROP(exe)
            gadgets_found = []
            
            # Recherche de gadgets critiques
            for g in ['pop rdi', 'pop rsi', 'pop rdx', 'pop rax', 'pop rcx', 'pop rbx', 'leave', 'ret', 'syscall', 'int 0x80']:
                try:
                    res = rop.find_gadget([g, 'ret']) if g not in ['leave', 'ret', 'syscall', 'int 0x80'] else rop.find_gadget([g])
                    if res: gadgets_found.append(f"{g.ljust(10)} ->  {hex(res.address)}")
                except:
                    continue
            analysis["rop_gadgets"] = gadgets_found
        except:
            pass

    except Exception as e:
        analysis["error"] = str(e)

    return analysis

# ====================================================================
# MODULE : ANALYSE STATIQUE DU CODE SOURCE
# ====================================================================
def source_patterns(source_text: str):
    lowered = source_text.lower()
    evidence = []
    
    for f in ["gets(", "strcpy(", "strcat(", "sprintf("]:
        if f in lowered: evidence.append(f"Stack Overflow potentiel: {f})")
            
    if re.search(r"printf\s*\(\s*[a-zA-Z0-9_]+\s*\)\s*;", source_text):
        evidence.append("Format String: printf(variable) détecté.")
        
    if re.search(r"read\(\s*\d+,\s*\w+,\s*\d+\s*\)", lowered):
        evidence.append("read() détecté: risque de Off-By-One ou d'absence de Null-Byte.")
    if "strncat(" in lowered or "strncpy(" in lowered:
        evidence.append("strncat/strncpy: risque de Null-Byte Poisoning.")

    if "malloc(" in lowered or "calloc(" in lowered:
        evidence.append("Heap Usage: malloc() détecté. Cherchez des UAF ou Heap Overflows.")
    if "free(" in lowered:
        evidence.append("Heap Usage: free() détecté. Vérifiez les Use-After-Free ou Double Free.")

    if "atoi(" in lowered or "atol(" in lowered:
        evidence.append("Integer Logic: atoi() utilisé. Risque d'Integer Overflow/Type confusion.")
        
    if "system(" in lowered or "execve(" in lowered or "popen(" in lowered:
        evidence.append("Command Execution: Fonction system/execve présente.")

    return list(set(evidence))

# ====================================================================
# MODULE : GÉNÉRATEUR DE STRATÉGIE D'ATTAQUE (ATTACK PLANNER)
# ====================================================================
def generate_attack_plan(evidence: list, chk: dict):
    plan = []
    e = " ".join(evidence).lower()
    pie = (chk.get("pie") or "").lower()
    canary = (chk.get("canary") or "").lower()
    nx = (chk.get("nx") or "").lower()
    relro = (chk.get("relro") or "").lower()

    if "format string" in e:
        plan.append("[Étape 1] Utilisez '%p' ou '%x' pour lire la pile et trouver l'adresse de base (PIE/Libc) ou le Canary.")
        if "full" not in relro:
            plan.append("[Étape 2] Utilisez '%n' pour écraser une entrée dans la table GOT (ex: printf -> system).")
        else:
            plan.append("[Étape 2] RELRO est Full. Écrasez l'adresse de retour (Saved RIP) sur la pile ou un hook malloc.")

    elif "stack overflow" in e or "read()" in e:
        if "found" in canary:
            plan.append("[Étape 1] Canary détecté. Trouvez un moyen de le fuiter (leak) via un format string ou une lecture sans null-byte.")
        if "enabled" in pie:
            plan.append("[Étape 2] PIE activé. Obtenez un leak d'une adresse de code pour contourner l'ASLR du binaire.")
            
        if "enabled" in nx:
            plan.append("[Étape 3] NX activé (Pas de shellcode sur la stack). Préparez une chaîne ROP.")
            plan.append("[Étape 4] ROP: Utilisez 'puts(puts@got)' ou 'printf' pour fuiter une adresse de la libc.")
            plan.append("[Étape 5] ROP: Calculez la base de la libc, puis faites un ret2libc vers 'system(\"/bin/sh\")'.")
        else:
            plan.append("[Étape 3] NX désactivé ! Injectez un shellcode classique dans le buffer et sautez dessus.")

    elif "heap usage" in e:
        plan.append("[Étape 1] Cible orientée Heap (Tas). Cherchez un Use-After-Free (pointeur non mis à NULL après free).")
        plan.append("[Étape 2] Manipulez les chunks (Tcache, Fastbin) pour obtenir une primitive Arbitrary Write.")
        if "full" not in relro:
            plan.append("[Étape 3] Écrasez le pointeur free@got ou une fonction du heap (ex: __free_hook).")

    if not plan:
        plan.append("Stratégie inconnue : analysez manuellement le comportement binaire dans GDB.")

    return plan

def classify_vuln(evidence: list):
    e = " ".join(evidence).lower()
    if "heap usage" in e and "free(" in e: return "heap_exploitation"
    if "format string" in e: return "format_string"
    if "stack overflow" in e: return "stack_overflow"
    if "integer" in e: return "integer_bug"
    return "unknown/custom"

def estimate_difficulty(vuln_type: str, chk: dict):
    pie = (chk.get("pie") or "").lower()
    canary = (chk.get("canary") or "").lower()
    nx = (chk.get("nx") or "").lower()
    
    if vuln_type == "heap_exploitation": return "hard"
    if "enabled" in pie and "found" in canary: return "hard"
    if "enabled" in pie or "found" in canary: return "medium"
    if "enabled" in nx: return "medium"
    return "low"

def analyze(source_path: str, binary_path: str):
    src_text = ""
    if source_path and os.path.isfile(source_path):
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            src_text = f.read()

    evidence = source_patterns(src_text)

    chk_raw, chk_parsed, binfo, sym, sscan, deep_elf = "", {}, {}, {}, {}, {}

    if binary_path and os.path.isfile(binary_path):
        chk_raw = run_checksec(binary_path)
        chk_parsed = parse_checksec_raw(chk_raw)
        binfo["file"] = file_type(binary_path)
        sym = symbols_scan(binary_path)
        sscan = strings_scan(binary_path)
        deep_elf = deep_elf_analysis(binary_path)

    vuln_type = classify_vuln(evidence)
    difficulty = estimate_difficulty(vuln_type, chk_parsed)
    attack_plan = generate_attack_plan(evidence, chk_parsed)

    return {
        "vuln_type": vuln_type,
        "difficulty": difficulty,
        "evidence": evidence,
        "attack_plan": attack_plan,
        "checksec": chk_parsed,
        "checksec_raw": chk_raw,
        "binary_info": binfo,
        "symbols": sym,
        "strings": sscan,
        "deep_analysis": deep_elf,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }
