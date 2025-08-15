# app.py
import os, json, time, string, zipfile, threading, math, uuid, shutil
from datetime import datetime
from flask import Flask, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename

UPLOAD_DIR = "uploads"
JOBS_DIR = "jobs"
EXTRACT_TMP = "extract_tmp"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(JOBS_DIR, exist_ok=True)
os.makedirs(EXTRACT_TMP, exist_ok=True)

app = Flask(__name__)

# -------------------------
# Utilities
# -------------------------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def human_rate(tried, duration_s):
    if duration_s <= 0:
        return 0.0
    return tried / duration_s

def compute_total_bruteforce(charset_len, min_len, max_len):
    total = 0
    for L in range(min_len, max_len + 1):
        total += charset_len ** L
    return total

def open_zip_entries(zip_bytes, password):
    """Try to open a zip with a password. Return True if password correct."""
    try:
        # Create a ZipFile from bytes without touching disk
        from io import BytesIO
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
        # Try to read the first entry to verify password
        entries = zf.namelist()
        if not entries:
            return False
        # try reading small amount from first file
        first = entries[0]
        with zf.open(first, pwd=password.encode('utf-8')) as fh:
            _ = fh.read(2)  # reading a couple bytes is enough to validate
        return True
    except Exception:
        return False

def load_job(job_id):
    meta_path = os.path.join(JOBS_DIR, f"{job_id}.json")
    if not os.path.exists(meta_path):
        return None
    with open(meta_path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_job(job):
    meta_path = os.path.join(JOBS_DIR, f"{job['id']}.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(job, f, ensure_ascii=False, indent=2)

def get_charset(preset, custom):
    presets = {
        "lower": string.ascii_lowercase,
        "upper": string.ascii_uppercase,
        "digits": string.digits,
        "lowerupper": string.ascii_lowercase + string.ascii_uppercase,
        "lowerdigits": string.ascii_lowercase + string.digits,
        "upperdigits": string.ascii_uppercase + string.digits,
        "alnum": string.ascii_letters + string.digits,
        "alnum_space": string.ascii_letters + string.digits + " ",
        "full": string.ascii_letters + string.digits + string.punctuation + " ",
    }
    if preset == "custom":
        return custom or ""
    return presets.get(preset, presets["alnum"])

def odometer_next(idx, base):
    """In-place increment of the index array in base 'base'. Return False if overflowed."""
    k = len(idx) - 1
    while k >= 0:
        idx[k] += 1
        if idx[k] < base:
            return True
        idx[k] = 0
        k -= 1
    return False

# -------------------------
# Job Worker
# -------------------------
workers = {}  # job_id -> thread
locks = {}    # job_id -> Lock

def run_job(job_id):
    lock = locks[job_id]
    with lock:
        job = load_job(job_id)
        if not job: 
            return
        job["state"] = "running"
        job["started_at"] = job.get("started_at") or now_iso()
        job["message"] = "Job started."
        save_job(job)

    # Load zip bytes once
    with open(job["zip_path"], "rb") as f:
        zip_bytes = f.read()

    started_wall = time.time()
    last_tick = started_wall
    tries_since_tick = 0

    def update_progress(increment=1, current_candidate=None):
        nonlocal last_tick, tries_since_tick
        with locks[job_id]:
            j = load_job(job_id)
            if not j: 
                return False
            if j["state"] in ("stopped", "found", "error", "paused"):
                return False
            j["tried"] += increment
            j["updated_at"] = now_iso()
            if current_candidate is not None:
                j["current_candidate"] = current_candidate
            # rate + ETA
            nowt = time.time()
            tries_since_tick += increment
            dt = nowt - last_tick
            if dt >= 1.0:
                rate = human_rate(tries_since_tick, dt)
                j["rate"] = rate
                tries_since_tick = 0
                last_tick = nowt
                # ETA
                remain = max(0, j["total"] - j["tried"])
                j["eta_seconds"] = float(remain / rate) if rate > 0 else None
            save_job(j)
            return True

    # Dictionary mode
    if job["mode"] == "dictionary":
        wl_path = job.get("wordlist_path")
        words = []
        if wl_path and os.path.exists(wl_path):
            with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.rstrip("\n\r")
                    if w: words.append(w)
        # resume index
        start_idx = job.get("checkpoint", {}).get("dict_index", 0)
        for i in range(start_idx, len(words)):
            with locks[job_id]:
                j = load_job(job_id)
                if j["state"] == "paused":
                    j["checkpoint"]["dict_index"] = i
                    j["message"] = "Paused."
                    save_job(j)
                while j["state"] == "paused":
                    time.sleep(0.3)
                    j = load_job(job_id)
                if j["state"] in ("stopped", "error", "found"):
                    return
            pwd = words[i]
            ok = open_zip_entries(zip_bytes, pwd)
            if not update_progress(1, pwd):
                return
            if ok:
                with locks[job_id]:
                    j = load_job(job_id)
                    j["state"] = "found"
                    j["password"] = pwd
                    j["message"] = "Password found."
                    j["updated_at"] = now_iso()
                    save_job(j)
                return
        with locks[job_id]:
            j = load_job(job_id)
            j["state"] = "stopped"
            j["message"] = "Password not found in wordlist."
            save_job(j)
        return

    # Brute-force mode
    charset = job["charset"]
    min_len = job["min_len"]
    max_len = job["max_len"]
    base = len(charset)

    # resume state
    cp = job.get("checkpoint", {})
    current_len = cp.get("length", min_len)
    if "indices" in cp and isinstance(cp["indices"], list) and len(cp["indices"]) == current_len:
        idx = cp["indices"]
    else:
        idx = [0] * current_len

    while current_len <= max_len:
        # Regen idx length if changed
        if len(idx) != current_len:
            idx = [0] * current_len

        while True:
            with locks[job_id]:
                j = load_job(job_id)
                if j["state"] == "paused":
                    j["checkpoint"] = {"length": current_len, "indices": idx}
                    j["message"] = "Paused."
                    save_job(j)
                while j["state"] == "paused":
                    time.sleep(0.3)
                    j = load_job(job_id)
                if j["state"] in ("stopped", "error", "found"):
                    return

            # Build candidate
            candidate = "".join(charset[i] for i in idx)
            ok = open_zip_entries(zip_bytes, candidate)
            if not update_progress(1, candidate):
                return
            if ok:
                with locks[job_id]:
                    j = load_job(job_id)
                    j["state"] = "found"
                    j["password"] = candidate
                    j["message"] = "Password found."
                    j["updated_at"] = now_iso()
                    save_job(j)
                return

            # Next combination
            if not odometer_next(idx, base):
                break

            # Occasionally persist checkpoint
            if job["tried"] % 5000 == 0:
                with locks[job_id]:
                    j = load_job(job_id)
                    j["checkpoint"] = {"length": current_len, "indices": idx}
                    save_job(j)

        # move to next length
        current_len += 1
        with locks[job_id]:
            j = load_job(job_id)
            j["checkpoint"] = {"length": current_len, "indices": [0]*current_len}
            save_job(j)

    with locks[job_id]:
        j = load_job(job_id)
        j["state"] = "stopped"
        j["message"] = "Exhausted search space."
        save_job(j)

# -------------------------
# API
# -------------------------
@app.route("/api/jobs/start", methods=["POST"])
def start_job():
    """
    form-data:
      zip_file: (required) encrypted zip
      mode: dictionary|bruteforce
      wordlist: optional (.txt), only for dictionary
      charset_preset: lower|upper|digits|lowerupper|lowerdigits|upperdigits|alnum|alnum_space|full|custom (optional)
      custom_charset: optional (used when preset=custom)
      min_len: int (default 1)
      max_len: int (default 4)
    """
    if "zip_file" not in request.files:
        return jsonify({"error":"zip_file is required"}), 400

    job_id = uuid.uuid4().hex
    locks[job_id] = threading.Lock()

    zf = request.files["zip_file"]
    zname = secure_filename(zf.filename or f"{job_id}.zip")
    zip_path = os.path.join(UPLOAD_DIR, f"{job_id}__{zname}")
    zf.save(zip_path)

    mode = request.form.get("mode", "dictionary")
    if mode not in ("dictionary", "bruteforce"):
        return jsonify({"error":"mode must be dictionary or bruteforce"}), 400

    wordlist_path = None
    if mode == "dictionary" and "wordlist" in request.files:
        wf = request.files["wordlist"]
        wname = secure_filename(wf.filename or f"{job_id}.txt")
        wordlist_path = os.path.join(UPLOAD_DIR, f"{job_id}__{wname}")
        wf.save(wordlist_path)

    charset_preset = request.form.get("charset_preset", "alnum")
    custom_charset = request.form.get("custom_charset", "")
    charset = get_charset(charset_preset, custom_charset)

    try:
        min_len = int(request.form.get("min_len", "1"))
        max_len = int(request.form.get("max_len", "4"))
    except:
        return jsonify({"error":"min_len/max_len must be integers"}), 400
    if min_len < 1 or max_len < min_len:
        return jsonify({"error":"invalid length range"}), 400

    # Prepare job object
    job = {
        "id": job_id,
        "state": "queued",
        "mode": mode,
        "zip_path": zip_path,
        "wordlist_path": wordlist_path,
        "charset": charset if mode == "bruteforce" else "",
        "min_len": min_len if mode == "bruteforce" else 0,
        "max_len": max_len if mode == "bruteforce" else 0,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "started_at": None,
        "finished_at": None,
        "tried": 0,
        "total": (len(open(wordlist_path,"r",encoding="utf-8",errors="ignore").read().splitlines()) if (mode=="dictionary" and wordlist_path and os.path.exists(wordlist_path)) else compute_total_bruteforce(len(charset), min_len, max_len)) if mode=="bruteforce" or wordlist_path else 0,
        "rate": 0.0,
        "eta_seconds": None,
        "current_candidate": "",
        "password": None,
        "message": "Queued",
        "checkpoint": {}
    }
    save_job(job)

    # Launch worker thread
    t = threading.Thread(target=run_job, args=(job_id,), daemon=True)
    workers[job_id] = t
    t.start()

    return jsonify({"job_id": job_id})

@app.route("/api/jobs/<job_id>/status", methods=["GET"])
def job_status(job_id):
    job = load_job(job_id)
    if not job:
        return jsonify({"error":"job not found"}), 404
    return jsonify({
        "id": job["id"],
        "state": job["state"],
        "mode": job["mode"],
        "tried": job["tried"],
        "total": job["total"],
        "rate": job.get("rate", 0.0),
        "eta_seconds": job.get("eta_seconds"),
        "current_candidate": job.get("current_candidate"),
        "current_length": job.get("checkpoint", {}).get("length") if job["mode"]=="bruteforce" else None,
        "message": job.get("message"),
        "created_at": job["created_at"],
        "updated_at": job["updated_at"]
    })

@app.route("/api/jobs/<job_id>/result", methods=["GET"])
def job_result(job_id):
    job = load_job(job_id)
    if not job:
        return jsonify({"error":"job not found"}), 404
    if job["state"] != "found":
        return jsonify({"state": job["state"], "message": "Not found yet."})
    return jsonify({"password": job["password"]})

@app.route("/api/jobs/<job_id>/pause", methods=["POST"])
def job_pause(job_id):
    with locks.get(job_id, threading.Lock()):
        job = load_job(job_id)
        if not job: return jsonify({"error":"job not found"}), 404
        if job["state"] not in ("running",):
            return jsonify({"error":"can only pause a running job"}), 400
        job["state"] = "paused"
        job["message"] = "Paused by user."
        job["updated_at"] = now_iso()
        save_job(job)
    return jsonify({"ok": True})

@app.route("/api/jobs/<job_id>/resume", methods=["POST"])
def job_resume(job_id):
    with locks.get(job_id, threading.Lock()):
        job = load_job(job_id)
        if not job: return jsonify({"error":"job not found"}), 404
        if job["state"] not in ("paused",):
            return jsonify({"error":"can only resume a paused job"}), 400
        job["state"] = "running"
        job["message"] = "Resumed by user."
        job["updated_at"] = now_iso()
        save_job(job)
    return jsonify({"ok": True})

@app.route("/api/jobs/<job_id>/stop", methods=["POST"])
def job_stop(job_id):
    with locks.get(job_id, threading.Lock()):
        job = load_job(job_id)
        if not job: return jsonify({"error":"job not found"}), 404
        job["state"] = "stopped"
        job["message"] = "Stopped by user."
        job["updated_at"] = now_iso()
        save_job(job)
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
