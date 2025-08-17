# app.py
import os, json, time, string, zipfile, threading, uuid
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

# -------------------------
# Storage (Render disk friendly)
# -------------------------
DATA_DIR = os.getenv("DATA_DIR", ".")  # set to /data when you attach a persistent disk
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
JOBS_DIR = os.path.join(DATA_DIR, "jobs")
EXTRACT_TMP = os.path.join(DATA_DIR, "extract_tmp")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(JOBS_DIR, exist_ok=True)
os.makedirs(EXTRACT_TMP, exist_ok=True)

# -------------------------
# Config (Render friendly)
# -------------------------
# How many cracking threads to run in parallel for brute-force
N_WORKERS = max(1, int(os.getenv("CRACK_THREADS", str(os.cpu_count() or 2)))))
# Optional upload cap (MiB). Render free tier ~25MB request body.
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "25"))

# Serve static frontend + API under same origin
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

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
        total += (charset_len ** L)
    return total

def open_zip_entries(zip_bytes, password):
    """Try to open a zip with a password. Return True if password correct."""
    try:
        from io import BytesIO
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
        entries = zf.namelist()
        if not entries:
            return False
        first = entries[0]
        with zf.open(first, pwd=password.encode("utf-8")) as fh:
            _ = fh.read(2)
        return True
    except Exception:
        return False

def load_job(job_id):
    path = os.path.join(JOBS_DIR, f"{job_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_job(job):
    path = os.path.join(JOBS_DIR, f"{job['id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(job, f, ensure_ascii=False, indent=2)

def get_charset(preset, custom):
    import string as _s
    presets = {
        "lower": _s.ascii_lowercase,
        "upper": _s.ascii_uppercase,
        "digits": _s.digits,
        "lowerupper": _s.ascii_lowercase + _s.ascii_uppercase,
        "lowerdigits": _s.ascii_lowercase + _s.digits,
        "upperdigits": _s.ascii_uppercase + _s.digits,
        "alnum": _s.ascii_letters + _s.digits,
        "alnum_space": _s.ascii_letters + _s.digits + " ",
        "full": _s.ascii_letters + _s.digits + _s.punctuation + " ",
    }
    if preset == "custom":
        return custom or ""
    return presets.get(preset, presets["alnum"])

def odometer_next_from(idx, base, start_pos):
    """
    Increment idx in base 'base' starting from position 'len(idx)-1' down to 'start_pos'.
    Positions [0..start_pos-1] are treated as fixed.
    Returns False if overflowed.
    """
    k = len(idx) - 1
    while k >= start_pos:
        idx[k] += 1
        if idx[k] < base:
            return True
        idx[k] = 0
        k -= 1
    return False

# -------------------------
# Job Worker
# -------------------------
workers = {}      # job_id -> thread
locks = {}        # job_id -> Lock
stop_flags = {}   # job_id -> threading.Event (signals found/stop across worker threads)

def run_job(job_id):
    """
    Multi-threaded brute-force:
      - Splits the keyspace by the first character index across N_WORKERS threads.
      - Each thread iterates all lengths [min_len..max_len] where idx[0] is in its slice.
    Dictionary mode remains single-thread.
    """
    lock = locks[job_id]
    with lock:
        job = load_job(job_id)
        if not job:
            return
        job["state"] = "running"
        job["started_at"] = job.get("started_at") or now_iso()
        job["message"] = f"Job started with {N_WORKERS if job['mode']=='bruteforce' else 1} worker(s)."
        save_job(job)

    # Load zip bytes once
    with open(job["zip_path"], "rb") as f:
        zip_bytes = f.read()

    last_tick = time.time()
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
            nowt = time.time()
            tries_since_tick += increment
            dt = nowt - last_tick
            if dt >= 1.0:
                rate = human_rate(tries_since_tick, dt)
                j["rate"] = rate
                tries_since_tick = 0
                last_tick = nowt
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
                    if w:
                        words.append(w)
        start_idx = job.get("checkpoint", {}).get("dict_index", 0)
        for i in range(start_idx, len(words)):
            # pause/stop checks
            while True:
                with locks[job_id]:
                    j = load_job(job_id)
                    if j["state"] == "paused":
                        j["checkpoint"]["dict_index"] = i
                        j["message"] = "Paused."
                        save_job(j)
                    if j["state"] in ("stopped", "error", "found"):
                        return
                if load_job(job_id)["state"] != "paused":
                    break
                time.sleep(0.3)

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

    # Brute-force mode (multi-thread)
    charset = job["charset"]
    min_len = job["min_len"]
    max_len = job["max_len"]
    base = len(charset)

    stop_event = threading.Event()
    stop_flags[job_id] = stop_event

    def worker_fn(worker_id):
        # Iterate lengths
        for L in range(min_len, max_len + 1):
            if stop_event.is_set():
                return
            # First-char slice for this worker
            first_indices = list(range(worker_id, base, N_WORKERS))
            for first_idx in first_indices:
                if stop_event.is_set():
                    return
                idx = [0] * L
                idx[0] = first_idx
                # inner positions [1..L-1] roll over
                while True:
                    # Pause/stop/found checks
                    with locks[job_id]:
                        j = load_job(job_id)
                        if j["state"] == "paused":
                            j["checkpoint"] = {"length": L, "indices": idx}
                            j["message"] = "Paused."
                            save_job(j)
                        state = j["state"]
                    while state == "paused":
                        time.sleep(0.3)
                        state = load_job(job_id)["state"]
                    if state in ("stopped", "error", "found") or stop_event.is_set():
                        return

                    candidate = "".join(charset[i] for i in idx)
                    ok = open_zip_entries(zip_bytes, candidate)
                    if not update_progress(1, candidate):
                        return
                    if ok:
                        with locks[job_id]:
                            jj = load_job(job_id)
                            jj["state"] = "found"
                            jj["password"] = candidate
                            jj["message"] = "Password found."
                            jj["updated_at"] = now_iso()
                            save_job(jj)
                        stop_event.set()
                        return

                    # advance inner odometer (positions 1..L-1)
                    if L == 1:
                        break
                    if not odometer_next_from(idx, base, start_pos=1):
                        break

    # Launch workers
    threads = []
    for wid in range(min(N_WORKERS, base)):  # don't spawn more workers than the charset size
        t = threading.Thread(target=worker_fn, args=(wid,), daemon=True)
        threads.append(t)
        t.start()

    # Wait for workers
    for t in threads:
        t.join()

    # Mark completion if not found
    with locks[job_id]:
        j = load_job(job_id)
        if j["state"] != "found" and j["state"] != "stopped":
            j["state"] = "stopped"
            j["message"] = "Exhausted search space."
            save_job(j)

# -------------------------
# API
# -------------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    return jsonify({"error": f"File too large. Limit is {MAX_UPLOAD_MB} MB."}), 413

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "threads": N_WORKERS, "time": now_iso()})

@app.post("/api/jobs/start")
def start_job():
    """
    form-data:
      zip_file: (required) encrypted zip
      mode: dictionary|bruteforce
      wordlist: optional (.txt), only for dictionary
      charset_preset: lower|upper|digits|lowerupper|lowerdigits|upperdigits|alnum|alnum_space|full|custom
      custom_charset: optional (used when preset=custom)
      min_len: int (default 1)
      max_len: int (default 4)
    """
    if "zip_file" not in request.files:
        return jsonify({"error": "zip_file is required"}), 400

    job_id = uuid.uuid4().hex
    locks[job_id] = threading.Lock()

    zf = request.files["zip_file"]
    zname = secure_filename(zf.filename or f"{job_id}.zip")
    zip_path = os.path.join(UPLOAD_DIR, f"{job_id}__{zname}")
    zf.save(zip_path)

    mode = request.form.get("mode", "dictionary")
    if mode not in ("dictionary", "bruteforce"):
        return jsonify({"error": "mode must be dictionary or bruteforce"}), 400

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
        return jsonify({"error": "min_len/max_len must be integers"}), 400
    if min_len < 1 or max_len < min_len:
        return jsonify({"error": "invalid length range"}), 400
    if mode == "bruteforce" and len(charset) == 0:
        return jsonify({"error": "charset is empty"}), 400

    # Total count
    if mode == "dictionary":
        total = 0
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                total = sum(1 for _ in f)
    else:
        total = compute_total_bruteforce(len(charset), min_len, max_len)

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
        "total": total,
        "rate": 0.0,
        "eta_seconds": None,
        "current_candidate": "",
        "password": None,
        "message": "Queued",
        "checkpoint": {}
    }
    save_job(job)

    # Launch worker thread (spawns N_WORKERS internal threads for brute-force)
    t = threading.Thread(target=run_job, args=(job_id,), daemon=True)
    workers[job_id] = t
    t.start()

    return jsonify({"job_id": job_id})

@app.get("/api/jobs/<job_id>/status")
def job_status(job_id):
    job = load_job(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify({
        "id": job["id"],
        "state": job["state"],
        "mode": job["mode"],
        "tried": job["tried"],
        "total": job["total"],
        "rate": job.get("rate", 0.0),
        "eta_seconds": job.get("eta_seconds"),
        "current_candidate": job.get("current_candidate"),
        "current_length": job.get("checkpoint", {}).get("length") if job["mode"] == "bruteforce" else None,
        "message": job.get("message"),
        "created_at": job["created_at"],
        "updated_at": job["updated_at"]
    })

@app.get("/api/jobs/<job_id>/result")
def job_result(job_id):
    job = load_job(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    if job["state"] != "found":
        return jsonify({"state": job["state"], "message": "Not found yet."})
    return jsonify({"password": job["password"]})

@app.post("/api/jobs/<job_id>/pause")
def job_pause(job_id):
    with locks.get(job_id, threading.Lock()):
        job = load_job(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        if job["state"] not in ("running",):
            return jsonify({"error": "can only pause a running job"}), 400
        job["state"] = "paused"
        job["message"] = "Paused by user."
        job["updated_at"] = now_iso()
        save_job(job)
    return jsonify({"ok": True})

@app.post("/api/jobs/<job_id>/resume")
def job_resume(job_id):
    with locks.get(job_id, threading.Lock()):
        job = load_job(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        if job["state"] not in ("paused",):
            return jsonify({"error": "can only resume a paused job"}), 400
        job["state"] = "running"
        job["message"] = "Resumed by user."
        job["updated_at"] = now_iso()
        save_job(job)
    return jsonify({"ok": True})

@app.post("/api/jobs/<job_id>/stop")
def job_stop(job_id):
    with locks.get(job_id, threading.Lock()):
        job = load_job(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        job["state"] = "stopped"
        job["message"] = "Stopped by user."
        job["updated_at"] = now_iso()
        save_job(job)
    # trip the stop event so worker threads exit
    ev = stop_flags.get(job_id)
    if ev:
        ev.set()
    return jsonify({"ok": True})

# -------------------------
# Frontend routes (same origin)
# -------------------------
@app.get("/")
def home():
    return render_template("index.html")

@app.get("/health")
def ui_health():
    return f"OK {now_iso()}"

if __name__ == "__main__":
    # Local dev only; on Render use gunicorn (Procfile)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
