#!/usr/bin/env python3
"""
collector_telnet_v2.py
Versão estendida: locks por host com TTL, retries, WAIT e SUBSESSION (!SUBSESSION).
Telnet-based.
"""

import telnetlib, time, re, json, os, threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import traceback

# --- CONFIGURÁVEL ---
CONFIG_DIR = "."  # onde commands.txt, devices.json, schedule.conf ficam
LOG_DIR = "logs"
CHECK_INTERVAL_SEC = 60  # checa a cada minuto se há jobs
MAX_WORKERS = 6
TELNET_TIMEOUT = 10
COMMAND_DELAY = 0.4  # delay entre comandos normais
# ----------------------

# --- utilitários ---
def ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)

def load_commands(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = [l.rstrip() for l in f if l.strip() and not l.strip().startswith("#")]
    return lines

def load_devices(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_schedule(path):
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            ln = line.split("#",1)[0].strip()
            if not ln:
                continue
            parts = ln.split()
            if len(parts) < 5:
                continue
            cron = " ".join(parts[:5])
            ips = None
            if len(parts) > 5:
                ips = " ".join(parts[5:]).strip()
                ips = [ip.strip() for ip in ips.split(",") if ip.strip()]
            entries.append((cron, ips))
    return entries

# Cron helper (simples)
def parse_field(field, minv, maxv):
    vals = set()
    if field == "*":
        return set(range(minv, maxv+1))
    for part in field.split(","):
        part = part.strip()
        if part.startswith("*/"):
            step = int(part[2:])
            vals.update(range(minv, maxv+1, step))
        elif "-" in part:
            a,b = part.split("-",1)
            vals.update(range(int(a), int(b)+1))
        else:
            vals.add(int(part))
    return vals

def cron_matches(cron_expr, dt):
    fields = cron_expr.split()
    if len(fields) != 5:
        return False
    minute_field, hour_field, dom_field, month_field, dow_field = fields
    m = dt.minute; h = dt.hour; dom = dt.day; mon = dt.month
    dow = dt.isoweekday() % 7
    try:
        if m not in parse_field(minute_field, 0, 59): return False
        if h not in parse_field(hour_field, 0, 23): return False
        if dom not in parse_field(dom_field, 1, 31): return False
        if mon not in parse_field(month_field, 1, 12): return False
        if dow not in parse_field(dow_field, 0, 6): return False
    except Exception:
        return False
    return True

# --- VAR replacement ---
VAR_RE = re.compile(r"\{\{([^}]+)\}\}")
def substitute_vars(cmd, device_obj):
    def repl(m):
        key = m.group(1).strip()
        return str(device_obj.get(key, "") )
    return VAR_RE.sub(repl, cmd)

# --- Lock por host (arquivo no tmp) ---
LOCK_DIR = os.path.join(tempfile.gettempdir(), "collector_telnet_locks")
os.makedirs(LOCK_DIR, exist_ok=True)

def lock_path_for(ip):
    safe = ip.replace(":", "_")
    return os.path.join(LOCK_DIR, f"{safe}.lock")

def acquire_lock(ip, ttl_seconds):
    path = lock_path_for(ip)
    now = time.time()
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                ts = float(f.read().strip() or "0")
        except Exception:
            ts = 0
        if now - ts > ttl_seconds:
            # lock expirado: sobrescrever
            with open(path, "w") as f:
                f.write(str(now))
            return True
        else:
            return False
    else:
        with open(path, "w") as f:
            f.write(str(now))
        return True

def release_lock(ip):
    path = lock_path_for(ip)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

# --- Telnet runner baseline (faz login e executa lista) ---
PROMPT_GUESS_RE = re.compile(r"([A-Za-z0-9\-\_\.]+)[#>]\s*$")

def open_telnet(ip, port, timeout):
    return telnetlib.Telnet(ip, port, timeout)

def read_eager_safe(tn):
    try:
        return tn.read_very_eager().decode("utf-8", errors="ignore")
    except Exception:
        return ""

def read_until_prompt_custom(tn, prompt_re, timeout=3):
    buff = ""
    start = time.time()
    while time.time() - start < timeout:
        try:
            chunk = tn.read_very_eager().decode("utf-8", errors="ignore")
        except Exception:
            chunk = ""
        if chunk:
            buff += chunk
            if prompt_re.search(buff):
                return buff
        else:
            time.sleep(0.1)
    return buff

def extract_hostname_from_prompt(text):
    # tenta achar "Hostname#" ou "Hostname>"
    lines = text.strip().splitlines()
    for ln in reversed(lines[-5:]):  # examina últimas linhas
        m = PROMPT_GUESS_RE.search(ln)
        if m:
            return m.group(1)
    # fallback: tenta achar qualquer token seguido de # no final
    m = re.search(r"([A-Za-z0-9\-\_\.]+)[#>]", text)
    if m:
        return m.group(1)
    return None

# telnet session runner (sincrono)
def telnet_session_run(device, commands, globals_obj, subsession_executor=None):
    ip = device.get("destIP")
    port = device.get("port", globals_obj.get("port", 23))
    username = device.get("username", globals_obj.get("username"))
    password = device.get("password", globals_obj.get("password"))
    enable_pw = device.get("enable_password", globals_obj.get("enable_password"))
    prompt_hint = device.get("prompt", globals_obj.get("prompt"))
    content_lines = []
    tn = None
    hostname = None
    try:
        tn = open_telnet(ip, port, TELNET_TIMEOUT)
        time.sleep(0.3)
        # banner
        b = read_eager_safe(tn)
        content_lines.append(b)

        # login heuristic
        if username:
            # read and attempt prompts
            chunk = read_eager_safe(tn)
            content_lines.append(chunk)
            if re.search(r"[Uu]sername|[Ll]ogin", chunk):
                tn.write((username + "\n").encode("utf-8"))
                time.sleep(0.2)
                chunk = read_eager_safe(tn)
                content_lines.append(chunk)
            if re.search(r"[Pp]assword", chunk):
                tn.write((password + "\n").encode("utf-8"))
                time.sleep(0.3)
                content_lines.append(read_eager_safe(tn))
        else:
            # maybe only password
            chunk = read_eager_safe(tn)
            content_lines.append(chunk)
            if re.search(r"[Pp]assword", chunk) and password:
                tn.write((password + "\n").encode("utf-8"))
                time.sleep(0.3)
                content_lines.append(read_eager_safe(tn))

        # try to determine prompt
        post = read_eager_safe(tn)
        content_lines.append(post)
        if not prompt_hint:
            # try to see last line with prompt char
            hostname = extract_hostname_from_prompt(post)
            if hostname:
                # create regex like r"^hostname[#>]\s*$" but we'll be permissive
                prompt_hint = rf"{re.escape(hostname)}[>#]\s*$"
            else:
                # fallback permissive
                prompt_hint = r".+[>#]\s*$"
        prompt_re = re.compile(prompt_hint, re.MULTILINE)

        # try enable
        if "enable_password" in device:
            # manda enable (com newline)
            tn.write(b"enable\n")
            # aguardamos um pouco e coletamos saída incrementalmente procurando por "Password" ou prompt '#'
            waited = 0.0
            enable_ok = False
            read_buf = ""
            while waited < 4.0:  # timeout total para detectar password ou prompt
                time.sleep(0.25)
                waited += 0.25
                chunk = read_eager_safe(tn)
                if chunk:
                    read_buf += chunk
                    # se pedir senha, responda apenas se houver senha configurada (truthy)
                    if re.search(r"[Pp]assword", read_buf):
                        if device.get("enable_password"):  # só envia se tiver senha não-emptiness
                            tn.write((str(device.get("enable_password")) + "\n").encode("utf-8"))
                            time.sleep(0.3)
                            read_buf += read_eager_safe(tn)
                        # independentemente de termos enviado ou não, continue e aguarde prompt
                    # se já apareceu '#' significa que estamos em enable
                    if re.search(r"[#]\s*$", read_buf):
                        enable_ok = True
                        break
            content_lines.append("\n# [enable attempt output]\n")
            content_lines.append(read_buf)

            # fallback: se não obtivemos enable (ainda '>'), tentar 'en' (atalho)
            if not enable_ok:
                # verifica última parte para ver se ainda tem '>' prompt
                if re.search(r"[>]\s*$", read_buf):
                    tn.write(b"en\n")
                    time.sleep(0.5)
                    more = read_eager_safe(tn)
                    content_lines.append("\n# [fallback 'en' output]\n")
                    content_lines.append(more)
                    if re.search(r"[#]\s*$", more):
                        enable_ok = True


        # run commands sequence
        for raw in commands:
            line = raw.strip()
            if not line:
                continue
            # DIRECTIVES
            if line.upper().startswith("!WAIT"):
                # formato: !WAIT N
                parts = line.split()
                sec = 1
                if len(parts) >= 2:
                    try:
                        sec = float(parts[1])
                    except:
                        sec = 1
                content_lines.append(f"\n# WAIT {sec} seconds\n")
                time.sleep(sec)
                continue
            if line.upper().startswith("!SUBSESSION"):
                # formato: !SUBSESSION name
                parts = line.split()
                if len(parts) >= 2:
                    subname = parts[1]
                    subs = globals_obj.get("subsessions", {})
                    subcmds = subs.get(subname)
                    if subcmds and subsession_executor:
                        # dispara thread paralela que executa subcmds contra o mesmo host
                        device_copy = dict(device)  # shallow copy
                        def run_sub():
                            try:
                                stamped = telnet_session_run(device_copy, subcmds, globals_obj, None)
                                # grava log próprio com sufixo subsession
                                now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                                hostpart = device_copy.get("destIP")
                                hostname_local = None
                                # tenta extrair hostname da saída do parent run (não ideal, mas ok)
                                # fallback use ip
                                try:
                                    hostname_local = extract_hostname_from_prompt(stamped)
                                except:
                                    hostname_local = None
                                fname = f"{hostname_local or hostpart}_sub_{subname}_{now}.log"
                                with open(os.path.join(LOG_DIR, fname), "w", encoding="utf-8") as f:
                                    f.write(stamped)
                            except Exception:
                                pass
                        subsession_executor.submit(run_sub)
                        content_lines.append(f"\n# SUBSESSION {subname} dispatched\n")
                continue

            # normal command -> substitute vars and send
            cmd = substitute_vars(line, device)
            content_lines.append(f"\n# >>> {cmd}\n")
            tn.write((cmd + "\n").encode("utf-8"))
            time.sleep(COMMAND_DELAY)
            out = read_until_prompt_custom(tn, prompt_re, timeout=6)
            content_lines.append(out)
            # try to update hostname if not found yet
            if not hostname:
                maybe = extract_hostname_from_prompt(out)
                if maybe:
                    hostname = maybe

        # close
        tn.write(b"exit\n")
        time.sleep(0.2)
        content_lines.append(read_eager_safe(tn))
    except Exception as e:
        content_lines.append("\n# SESSION ERROR: " + str(e) + "\n")
        content_lines.append(traceback.format_exc())
    finally:
        try:
            if tn:
                tn.close()
        except:
            pass
    return "\n".join(content_lines)

# --- runner por device com retries, lock, gravação de log com hostname ---
def run_for_device_with_policy(device, commands, globals_obj):
    ip = device.get("destIP")
    ttl = device.get("lock_ttl_seconds", globals_obj.get("lock_ttl_seconds", 1800))
    max_retries = device.get("max_retries", globals_obj.get("max_retries", 3))
    attempt = 0
    acquired = False
    while attempt < max_retries:
        attempt += 1
        acquired = acquire_lock(ip, ttl)
        if not acquired:
            # lock ocupado e não expirado -> abortar essa tentativa (espera pequena antes de tentar novamente)
            time.sleep(2 + attempt)
            continue
        # se adquiriu lock, executa sessão
        try:
            # temos um executor temporário para subsessions
            with ThreadPoolExecutor(max_workers=2) as subs_exec:
                out = telnet_session_run(device, commands, globals_obj, subsession_executor=subs_exec)
            # extrai hostname para nome do arquivo
            hostname = extract_hostname_from_prompt(out) or ip
            now = datetime.now().strftime("%Y-%m-%d_%H-%M")
            fname = f"{hostname}_{now}.log"
            path = os.path.join(LOG_DIR, fname)
            with open(path, "w", encoding="utf-8") as f:
                f.write(out)
            # sucesso -> libera lock e retorna caminho
            release_lock(ip)
            return path
        except Exception as e:
            # algo deu errado -> libera lock e tenta novamente após backoff
            release_lock(ip)
            time.sleep(2 * attempt)
            continue
    # se chegou aqui, falhou todas as tentativas
    return None

# --- schedule helpers ---
def get_target_ips_for_now(schedule_entries, devices_list):
    now = datetime.now()
    targets = set()
    for cron_expr, ips in schedule_entries:
        if cron_matches(cron_expr, now):
            if not ips:
                for d in devices_list:
                    targets.add(d['destIP'])
            else:
                for ip in ips:
                    targets.add(ip)
    return targets

def merge_globals_into_device(device, globals_obj):
    merged = dict(globals_obj)
    merged.update(device or {})
    # ensure keys exist
    return merged

# --- main loop ---
def main_loop():
    ensure_dirs()
    commands = load_commands(os.path.join(CONFIG_DIR, "commands.txt"))
    dev_json = load_devices(os.path.join(CONFIG_DIR, "devices.json"))
    # dev_json has "globals" and "devices"
    globals_obj = dev_json.get("globals", {})
    devices_list = dev_json.get("devices", [])
    dev_map = {d['destIP']: d for d in devices_list}
    schedule = load_schedule(os.path.join(CONFIG_DIR, "schedule.conf"))
    print("[collector v2] started ... ctrl-c to stop")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        try:
            while True:
                targets = get_target_ips_for_now(schedule, devices_list)
                if targets:
                    futures = {}
                    for ip in targets:
                        dev = dev_map.get(ip)
                        if not dev:
                            print(f"[warn] ip {ip} not found in devices.json")
                            continue
                        merged = merge_globals_into_device(dev, globals_obj)
                        futures[ex.submit(run_for_device_with_policy, merged, commands, globals_obj)] = ip
                    for fut in as_completed(futures):
                        ip = futures[fut]
                        try:
                            res = fut.result()
                            if res:
                                print(f"[ok] {ip} -> {res}")
                            else:
                                print(f"[fail] {ip} failed after retries")
                        except Exception as e:
                            print(f"[err] {ip} exception: {e}")
                time.sleep(CHECK_INTERVAL_SEC)
        except KeyboardInterrupt:
            print("interrupted, exiting.")

if __name__ == "__main__":
    main_loop()
