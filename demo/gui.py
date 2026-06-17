"""
gui.py — Due interfacce web per il sistema di voto APS.

  /        → Pannello di Controllo (admin: setup, gestione elezione, monitoraggio)
  /voter   → Portale Elettore    (registrazione, autenticazione, voto, verifica)

API invariate + 2 nuove route di sola lettura:
  GET /api/voter/<voter_id>/check          → esistenza + meta + stato elezione
  GET /api/voter/<voter_id>/wallet-detail  → dati wallet per visualizzazione

Uso:
    python gui.py
"""

import os, sys, json, io, threading, webbrowser, time, uuid
from flask import Flask, jsonify, request, Response

HOST = "127.0.0.1"
PORT = 5050
app  = Flask(__name__)

# ── Log globale ───────────────────────────────────────────────────────────────
_log_lock  = threading.Lock()
_log_lines = []

def _log(msg: str):
    with _log_lock:
        for line in msg.splitlines():
            if line.strip():
                _log_lines.append(line)
        if len(_log_lines) > 600:
            del _log_lines[:len(_log_lines) - 600]

# ── Thread-safe stdout/stderr ─────────────────────────────────────────────────
_tls = threading.local()

class _TLWriter:
    def __init__(self, original):
        self._orig = original
    def write(self, text):
        buf = getattr(_tls, "buf", None)
        if buf is not None:
            buf.write(text)
        else:
            self._orig.write(text)
        if text.strip():
            _log(text)
    def flush(self):
        self._orig.flush()
    def fileno(self):
        return self._orig.fileno()
    def __getattr__(self, name):
        return getattr(self._orig, name)

_orig_stdout = sys.stdout
_orig_stderr = sys.stderr
sys.stdout   = _TLWriter(_orig_stdout)
sys.stderr   = _TLWriter(_orig_stderr)

def _capture(func, *args, **kwargs):
    buf = io.StringIO()
    _tls.buf = buf
    try:
        result = func(*args, **kwargs)
        output = buf.getvalue()
        return {"success": True, "output": output, "result": result}
    except BaseException as exc:
        output = buf.getvalue()
        _log(f"ERRORE: {exc}")
        import traceback
        _log(traceback.format_exc())
        return {"success": False, "output": output, "error": str(exc)}
    finally:
        _tls.buf = None

# ── Job system ────────────────────────────────────────────────────────────────
_jobs      = {}
_jobs_lock = threading.Lock()

def _run_job(job_id: str, func, *args, **kwargs):
    def _worker():
        res = _capture(func, *args, **kwargs)
        with _jobs_lock:
            if res["success"]:
                _jobs[job_id] = {"status": "done",  "result": res}
            else:
                _jobs[job_id] = {"status": "error", "error": res.get("error","Errore sconosciuto"),
                                  "output": res.get("output","")}
    with _jobs_lock:
        _jobs[job_id] = {"status": "running"}
    threading.Thread(target=_worker, daemon=True).start()

def _new_job(func, *args, **kwargs) -> str:
    jid = uuid.uuid4().hex[:10]
    _run_job(jid, func, *args, **kwargs)
    return jid

def _sanitize_for_json(obj):
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.hex()
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(i) for i in obj]
    return obj

@app.route("/api/job/<jid>")
def api_job(jid):
    with _jobs_lock:
        data = _jobs.get(jid, {"status": "not_found"})
    return jsonify(_sanitize_for_json(data))

# ── Stato e helpers ───────────────────────────────────────────────────────────
def _fe(*paths): return all(os.path.exists(p) for p in paths)

def _get_state():
    from config import (CA_KEY_FILE, AA_KEY_FILE, AR_KEY_FILE,
                        AS_SIGN_KEY_FILE, AS_CERT_FILE,
                        SHARE_1_PATH, SHARE_2_PATH, SHARE_3_PATH,
                        EC_KEY_FILE, CONTRACT_INFO_FILE, GANACHE_URL)
    _as_ready = (_fe(SHARE_1_PATH, SHARE_2_PATH, SHARE_3_PATH)
                 and _fe(AS_SIGN_KEY_FILE) and _fe(AS_CERT_FILE))
    s = {"ganache": False, "contract_deployed": _fe(CONTRACT_INFO_FILE),
         "contract_state": "—", "ca_ready": _fe(CA_KEY_FILE),
         "aa_ready": _fe(AA_KEY_FILE), "ar_ready": _fe(AR_KEY_FILE),
         "as_ready": _as_ready, "ec_ready": _fe(EC_KEY_FILE),
         "ballot_count": 0, "final_result": None,
         "merkle_root_urna": None, "merkle_root_bb": None}
    try:
        from web3 import Web3
        from web3.middleware import ExtraDataToPOAMiddleware
        w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        s["ganache"] = w3.is_connected()
    except Exception: pass
    if s["contract_deployed"] and s["ganache"]:
        try:
            import blockchain
            info = blockchain.get_election_info()
            s["contract_state"] = info["state"]
            s["ballot_count"]   = info["ballotCount"]
            s["merkle_root_urna"] = info["merkleRootUrna"][:16]+"…" if info["merkleRootUrna"] else None
            if info["finalResult"] >= 0:
                s["final_result"] = {"si": info["finalResult"],
                                     "no": info["totalVotes"]-info["finalResult"],
                                     "tot": info["totalVotes"]}
                s["merkle_root_bb"] = info["merkleRootBB"][:16]+"…" if info["merkleRootBB"] else None
        except Exception: pass
    return s

def _get_voters():
    from config import AUTHORIZED_VOTERS_FILE, WALLETS_DIR
    import elettore
    if not _fe(AUTHORIZED_VOTERS_FILE): return []
    try:
        with open(AUTHORIZED_VOTERS_FILE) as f: auth = json.load(f)
    except Exception: return []
    out = []
    for vid, info in auth.items():
        meta = elettore._meta(vid)
        seq_num = vote_val = None
        bp = os.path.join(WALLETS_DIR, vid, "ballot.json")
        if os.path.exists(bp):
            try:
                with open(bp) as f: bd = json.load(f)
                seq_num = bd.get("seq_num"); vote_val = bd.get("v")
            except Exception: pass
        out.append({"voter_id": vid, "nome": info.get("nome", vid),
                    "keygen": meta.get("keygen", False),
                    "registered": meta.get("registered", False),
                    "token": meta.get("token", False),
                    "voted": meta.get("voted", False),
                    "seq_num": seq_num, "vote_val": vote_val})
    return out

# ── API routes ────────────────────────────────────────────────────────────────
@app.route("/api/state")
def api_state(): return jsonify(_get_state())

@app.route("/api/voters")
def api_voters(): return jsonify(_get_voters())

@app.route("/api/log")
def api_log():
    with _log_lock: lines = list(_log_lines)
    return jsonify(lines)

# Setup
@app.route("/api/setup/ca", methods=["POST"])
def api_setup_ca():
    import ca
    return jsonify({"job_id": _new_job(ca.setup)})

@app.route("/api/setup/authorities", methods=["POST"])
def api_setup_authorities():
    def _do():
        import aa, ar, as_, ec
        for fn in [aa.setup, ar.setup, as_.setup, ec.setup]:
            res = _capture(fn)
            if not res["success"]:
                raise RuntimeError(res.get("error","Errore inizializzazione"))
    return jsonify({"job_id": _new_job(_do)})

@app.route("/api/setup/deploy", methods=["POST"])
def api_setup_deploy():
    import blockchain
    return jsonify({"job_id": _new_job(blockchain.deploy_contract)})

# Elezione
@app.route("/api/election/open", methods=["POST"])
def api_election_open():
    import ec
    return jsonify({"job_id": _new_job(ec.attest_open)})

@app.route("/api/election/close", methods=["POST"])
def api_election_close():
    import ec
    return jsonify({"job_id": _new_job(ec.attest_close)})

@app.route("/api/election/tally", methods=["POST"])
def api_election_tally():
    import as_
    return jsonify({"job_id": _new_job(as_.tally)})

@app.route("/api/election/declare-overdue", methods=["POST"])
def api_election_declare_overdue():
    import ec
    return jsonify({"job_id": _new_job(ec.declare_scrutiny_overdue)})

@app.route("/api/test/advance-time", methods=["POST"])
def api_test_advance_time():
    import blockchain
    return jsonify({"job_id": _new_job(blockchain.advance_time, 20)})

# Elettori
@app.route("/api/voter/<voter_id>/register", methods=["POST"])
def api_voter_register(voter_id):
    def _do():
        import elettore
        r1 = _capture(elettore.keygen, voter_id)
        if not r1["success"]: raise RuntimeError(r1.get("error","keygen fallito"))
        r2 = _capture(elettore.register, voter_id)
        if not r2["success"]: raise RuntimeError(r2.get("error","register fallito"))
    return jsonify({"job_id": _new_job(_do)})

@app.route("/api/voter/<voter_id>/auth", methods=["POST"])
def api_voter_auth(voter_id):
    import elettore
    return jsonify({"job_id": _new_job(elettore.auth, voter_id)})

@app.route("/api/voter/<voter_id>/vote", methods=["POST"])
def api_voter_vote(voter_id):
    data   = request.get_json(force=True) or {}
    choice = int(data.get("choice", -1))
    if choice not in (0, 1):
        return jsonify({"status":"error","error":"choice deve essere 0 o 1"})
    import elettore
    return jsonify({"job_id": _new_job(elettore.vote, voter_id, choice)})

# Verifica
@app.route("/api/verify/individual/<voter_id>")
def api_verify_individual(voter_id):
    import verifica
    return jsonify({"job_id": _new_job(verifica.verify_individual, voter_id)})

@app.route("/api/verify/universal")
def api_verify_universal():
    import verifica
    return jsonify({"job_id": _new_job(verifica.verify_universal)})

# Reset
@app.route("/api/reset", methods=["POST"])
def api_reset():
    import shutil
    from config import (CA_DIR, AA_DIR, AR_DIR, AS_DIR, EC_DIR,
                        WALLETS_DIR, CONTRACT_INFO_FILE, BB_FILE)
    removed = []; errors = []
    for d in [CA_DIR, AA_DIR, AR_DIR, AS_DIR, EC_DIR, WALLETS_DIR]:
        if os.path.exists(d):
            try: shutil.rmtree(d); removed.append(d)
            except Exception as e: errors.append(str(e))
    for f in [CONTRACT_INFO_FILE, BB_FILE]:
        if os.path.exists(f):
            try: os.remove(f); removed.append(f)
            except Exception as e: errors.append(str(e))
    try:
        import ar as ar_module; ar_module._used_nonces.clear()
    except Exception: pass
    with _log_lock: _log_lines.clear()
    if errors:
        return jsonify({"success": False, "error": "; ".join(errors)})
    _log("Reset completato. Conservati: authorized_voters.json, contracts_out/")
    return jsonify({"success": True})

# ── Nuove route sola-lettura per il Portale Elettore ─────────────────────────

@app.route("/api/voter/<voter_id>/check")
def api_voter_check(voter_id):
    from config import AUTHORIZED_VOTERS_FILE
    if not _fe(AUTHORIZED_VOTERS_FILE):
        return jsonify({"found": False, "reason": "no_voters_file"})
    try:
        with open(AUTHORIZED_VOTERS_FILE) as f:
            auth = json.load(f)
    except Exception:
        return jsonify({"found": False, "reason": "read_error"})
    if voter_id not in auth:
        return jsonify({"found": False, "reason": "not_authorized"})
    import elettore
    meta = elettore._meta(voter_id)
    s    = _get_state()
    return jsonify({
        "found":             True,
        "voter_id":          voter_id,
        "nome":              auth[voter_id].get("nome", voter_id),
        "meta":              meta,
        "election_state":    s["contract_state"],
        "contract_deployed": s["contract_deployed"],
        "ganache":           s["ganache"],
        "final_result":      s["final_result"],
    })

@app.route("/api/voter/<voter_id>/wallet-detail")
def api_voter_wallet_detail(voter_id):
    from config import WALLETS_DIR, AUTHORIZED_VOTERS_FILE
    import elettore
    meta = elettore._meta(voter_id)
    nome = voter_id
    if _fe(AUTHORIZED_VOTERS_FILE):
        try:
            with open(AUTHORIZED_VOTERS_FILE) as f:
                auth = json.load(f)
            nome = auth.get(voter_id, {}).get("nome", voter_id)
        except Exception: pass
    result = {"voter_id": voter_id, "nome": nome, "meta": meta, "files": {}}
    wd = os.path.join(WALLETS_DIR, voter_id)
    for key, fname in [("key","voter_key.pem"),("cert","voter_cert.pem"),
                        ("token","token.json"),("ballot","ballot.json"),
                        ("receipt","receipt.json")]:
        result["files"][key] = os.path.exists(os.path.join(wd, fname))
    bp = os.path.join(wd, "ballot.json")
    if os.path.exists(bp):
        try:
            with open(bp) as f: bd = json.load(f)
            result["seq_num"]  = bd.get("seq_num")
            result["vote_val"] = bd.get("v")
        except Exception: pass
    rp = os.path.join(wd, "receipt.json")
    if os.path.exists(rp):
        try:
            with open(rp) as f: receipt = json.load(f)
            payload = receipt.get("payload", {})
            bh = payload.get("ballot_hash", "")
            result["receipt_summary"] = {
                "seq_num":     payload.get("seq_num"),
                "ballot_hash": (bh[:20] + "...") if bh else None,
                "ts":          payload.get("ts"),
            }
        except Exception: pass
    return jsonify(_sanitize_for_json(result))

# ── HTML: Portale Elettore ────────────────────────────────────────────────────
VOTER_HTML = r"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APS Voting — Portale Elettore</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{--bg:#0d1117;--surface:#161b22;--surface2:#1e2736;--border:#30363d;--text:#e6edf3;--muted:#7d8590;--accent:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149;--cyan:#39c5cf;--r:10px}
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  html{font-size:14px}
  body{background:var(--bg);color:var(--text);font-family:'Syne',sans-serif;min-height:100vh;display:flex;flex-direction:column}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;height:56px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100}
  .logo{font-size:1.1rem;font-weight:800;letter-spacing:.05em;color:var(--accent);text-transform:uppercase}
  .logo span{color:var(--text)}
  .hsub{font-size:.75rem;color:var(--muted);font-weight:600;letter-spacing:.08em;text-transform:uppercase}
  .hright{display:flex;gap:8px;margin-left:auto;align-items:center}
  .badge{font-family:'JetBrains Mono',monospace;font-size:.72rem;padding:3px 10px;border-radius:20px;font-weight:500;border:1px solid transparent;cursor:default;white-space:nowrap}
  .badge-ok{background:#1a3a1f;color:var(--green);border-color:#2d5a35}
  .badge-warn{background:#2d2008;color:var(--yellow);border-color:#4a3510}
  .badge-err{background:#3a1a1a;color:var(--red);border-color:#5a2a2a}
  .badge-info{background:#162032;color:var(--accent);border-color:#1e3a5a}
  .badge-cyan{background:#0d2a2c;color:var(--cyan);border-color:#1a4548}
  .badge-link{text-decoration:none;cursor:pointer}
  main{flex:1;display:flex;flex-direction:column;align-items:center;padding:28px 16px 64px}
  #voter-progress{width:100%;max-width:520px;margin-bottom:18px;display:none}
  .prog-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:13px 16px}
  .voter-info-row{display:flex;align-items:center;gap:8px;margin-bottom:10px}
  .voter-name{font-size:.9rem;font-weight:700}
  .voter-id-tag{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--muted);background:var(--surface2);padding:2px 8px;border-radius:4px}
  .btn-logout{font-family:'Syne',sans-serif;font-size:.72rem;color:var(--muted);background:none;border:none;cursor:pointer;margin-left:auto;padding:3px 8px;border-radius:4px;transition:all .15s}
  .btn-logout:hover{color:var(--red);background:#3a1a1a}
  .steps-row{display:grid;grid-template-columns:repeat(4,1fr);gap:4px}
  .step{font-family:'JetBrains Mono',monospace;font-size:.64rem;font-weight:600;padding:5px 3px;border-radius:5px;text-align:center;letter-spacing:.02em;border:1px solid transparent;transition:all .2s}
  .step-done{background:#1a3a1f;color:var(--green);border-color:#2d5a35}
  .step-active{background:#162032;color:var(--accent);border-color:#1e3a5a}
  .step-todo{background:var(--surface2);color:var(--muted);border-color:var(--border)}
  .screen{display:none;width:100%;max-width:520px}
  .screen.active{display:block}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:30px 26px;text-align:center}
  .card h1{font-size:1.5rem;font-weight:800;margin-bottom:8px;line-height:1.2}
  .card h2{font-size:1.15rem;font-weight:700;margin-bottom:10px}
  .card p{color:var(--muted);font-size:.87rem;line-height:1.65;margin-bottom:18px}
  .card p.last{margin-bottom:0}
  .icon-circle{width:54px;height:54px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.3rem;font-weight:800;margin:0 auto 18px;border:2px solid}
  .ic-blue{background:#162032;border-color:var(--accent);color:var(--accent)}
  .ic-green{background:#1a3a1f;border-color:var(--green);color:var(--green)}
  .ic-yellow{background:#2d2008;border-color:var(--yellow);color:var(--yellow);animation:pulse 2s ease-in-out infinite}
  .ic-cyan{background:#0d2a2c;border-color:var(--cyan);color:var(--cyan)}
  @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.7;transform:scale(.96)}}
  .form-group{text-align:left;margin-bottom:14px}
  .form-group label{display:block;font-size:.78rem;font-weight:600;margin-bottom:5px;color:var(--muted)}
  .form-group input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:9px 13px;color:var(--text);font-family:'Syne',sans-serif;font-size:.9rem;outline:none;transition:border-color .2s}
  .form-group input:focus{border-color:var(--accent)}
  .form-group input::placeholder{color:var(--muted);opacity:.55}
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:9px 18px;border-radius:7px;font-family:'Syne',sans-serif;font-size:.88rem;font-weight:600;cursor:pointer;border:1px solid transparent;transition:all .15s;width:100%;margin-top:8px}
  .btn:disabled{opacity:.4;cursor:not-allowed}
  .btn-primary{background:var(--accent);color:#000;border-color:var(--accent)}
  .btn-primary:not(:disabled):hover{background:#79baff}
  .btn-ghost{background:transparent;color:var(--text);border-color:var(--border)}
  .btn-ghost:not(:disabled):hover{background:var(--surface2)}
  .btn-si{background:var(--green);color:#000;border-color:var(--green);font-size:1rem;padding:13px 18px}
  .btn-si:not(:disabled):hover{background:#5fd96e}
  .btn-no{background:var(--red);color:#fff;border-color:var(--red);font-size:1rem;padding:13px 18px}
  .btn-no:not(:disabled):hover{background:#ff6b65}
  .vote-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px}
  .info-box{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px 13px;margin:10px 0;text-align:left;display:flex;justify-content:space-between;align-items:center;font-size:.82rem}
  .info-box .key{color:var(--muted)}
  .err-msg{color:var(--red);font-size:.82rem;margin-top:8px;padding:8px 12px;background:#3a1a1a;border:1px solid #5a2a2a;border-radius:6px;text-align:left}
  hr{border:none;border-top:1px solid var(--border);margin:18px 0}
  .vote-display{border-radius:8px;padding:13px;margin:10px 0;font-size:1rem;font-weight:700;text-align:center}
  .vote-si{background:#1a3a1f;color:var(--green);border:1px solid #2d5a35}
  .vote-no{background:#3a1a1a;color:var(--red);border:1px solid #5a2a2a}
  .seq-tag{font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--muted);margin-top:4px;text-align:center}
  .vresult-card{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:11px 13px;margin-top:11px;text-align:left}
  .vresult-title{font-size:.72rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-bottom:9px}
  .vresult-title.ok{color:var(--green)}.vresult-title.fail{color:var(--red)}
  .vcheck{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:.81rem;border-bottom:1px solid var(--border)}
  .vcheck:last-child{border-bottom:none}
  .vcheck-ok{color:var(--green)}.vcheck-fail{color:var(--red)}.vcheck-warn{color:var(--yellow)}
  .result-panel{background:linear-gradient(135deg,#1a2d1a,#1e2736);border:1px solid #3d6b3d;border-radius:var(--r);padding:16px;margin-top:14px;text-align:left}
  .result-title{font-size:.65rem;font-weight:700;letter-spacing:.12em;color:var(--green);text-transform:uppercase;margin-bottom:10px}
  .result-nums{display:flex;gap:20px;align-items:baseline}
  .result-big{font-size:2.2rem;font-weight:800;line-height:1}
  .result-lbl{font-size:.72rem;color:var(--muted);margin-top:2px}
  .result-bar{margin-top:10px;height:7px;background:var(--border);border-radius:4px;overflow:hidden}
  .result-fill{height:100%;background:var(--green);transition:width .6s ease}
  .spin{display:inline-block;width:13px;height:13px;border:2px solid rgba(255,255,255,.2);border-top-color:currentColor;border-radius:50%;animation:sp .7s linear infinite}
  @keyframes sp{to{transform:rotate(360deg)}}
  #toast{position:fixed;bottom:22px;right:22px;padding:11px 18px;border-radius:var(--r);font-size:.82rem;font-weight:600;z-index:9999;opacity:0;transform:translateY(10px);transition:all .25s;pointer-events:none;max-width:340px}
  #toast.show{opacity:1;transform:translateY(0)}
  #toast.tok{background:#1a3a1f;color:var(--green);border:1px solid #3d6b3d}
  #toast.terr{background:#3a1a1a;color:var(--red);border:1px solid #6b3d3d}
  .action-list{display:flex;flex-direction:column;gap:10px;margin-top:6px}
  .action-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);padding:16px 18px;cursor:pointer;transition:border-color .18s,background .18s;display:flex;align-items:center;gap:14px}
  .action-card:hover{border-color:var(--accent);background:#1a2233}
  .ac-icon{width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.8rem;font-weight:800;flex-shrink:0;border:2px solid}
  .ac-body{flex:1;text-align:left}
  .ac-title{font-size:.92rem;font-weight:700;margin-bottom:3px}
  .ac-desc{font-size:.78rem;color:var(--muted);line-height:1.5}
  .btn-back{color:var(--muted);background:none;border:none;cursor:pointer;font-family:'Syne',sans-serif;font-size:.82rem;display:flex;align-items:center;gap:5px;padding:4px 0;margin-bottom:14px;transition:color .15s}
  .btn-back:hover{color:var(--text)}
  .voter-bar{display:flex;align-items:center;gap:10px;padding-bottom:14px;margin-bottom:16px;border-bottom:1px solid var(--border)}
  .voter-bar-name{font-weight:700;font-size:.95rem}
  .voter-bar-id{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--muted);background:var(--surface2);padding:2px 8px;border-radius:4px}
  .ok-msg{color:var(--green);font-size:.85rem;margin-top:10px;padding:10px 13px;background:#1a3a1f;border:1px solid #2d5a35;border-radius:6px;text-align:center}
  .state-row{display:flex;justify-content:center;margin-bottom:14px}
</style>
</head>
<body>
<header>
  <div class="logo">APS<span> Voting</span></div>
  <div class="hsub">Portale Elettore</div>
  <div class="hright">
    <span id="hdr-state" class="badge badge-info">—</span>
  </div>
</header>

<main>

  <!-- HOME: 3 azioni -->
  <div id="sc-home" class="screen active">
    <div class="card" style="margin-bottom:16px;text-align:center">
      <h1 style="font-size:1.4rem;font-weight:800;margin-bottom:6px">Portale Elettore</h1>
      <p style="color:var(--muted);font-size:.87rem;margin-bottom:14px">Sistema di voto elettronico APS</p>
      <div class="state-row"><span id="home-state" class="badge badge-info">—</span></div>
    </div>
    <div class="action-list">
      <div class="action-card" onclick="showScreen('register')">
        <div class="ac-icon ic-blue">1</div>
        <div class="ac-body">
          <div class="ac-title">Registrazione presso AA</div>
          <div class="ac-desc">Genera le chiavi crittografiche e ottieni il certificato elettorale dall'Autorita' di Attestazione.</div>
        </div>
        <span style="color:var(--muted);font-size:1.1rem">&#x203A;</span>
      </div>
      <div class="action-card" onclick="showScreen('auth')">
        <div class="ac-icon ic-yellow" style="font-size:.7rem">AR</div>
        <div class="ac-body">
          <div class="ac-title">Autenticazione AR + Voto</div>
          <div class="ac-desc">Autenticati ed esprimi il voto. Il sistema verifica automaticamente il tuo certificato.</div>
        </div>
        <span style="color:var(--muted);font-size:1.1rem">&#x203A;</span>
      </div>
      <div class="action-card" onclick="showScreen('universal')">
        <div class="ac-icon ic-cyan" style="font-size:.68rem">VU</div>
        <div class="ac-body">
          <div class="ac-title">Verifica Universale</div>
          <div class="ac-desc">Verifica l'integrita' del processo elettorale senza credenziali. Dati pubblici.</div>
        </div>
        <span style="color:var(--muted);font-size:1.1rem">&#x203A;</span>
      </div>
    </div>
  </div>

  <!-- REGISTRAZIONE -->
  <div id="sc-register" class="screen">
    <div class="card">
      <button class="btn-back" onclick="goHome()">&#x2190; Home</button>
      <div class="icon-circle ic-blue">1</div>
      <h2 style="text-align:center;font-size:1.1rem;font-weight:700;margin-bottom:8px">Registrazione presso AA</h2>
      <p style="color:var(--muted);font-size:.85rem;text-align:center;margin-bottom:18px;line-height:1.6">Inserisci il tuo ID per generare le chiavi e ottenere il certificato elettorale dall'AA.</p>
      <div class="form-group">
        <label for="reg-vid">ID Elettore</label>
        <input id="reg-vid" type="text" placeholder="es. MarioRossi001"
               onkeydown="if(event.key==='Enter')doRegister()">
      </div>
      <button id="btn-reg" class="btn btn-primary" onclick="doRegister()">Registrati</button>
      <div id="reg-err" style="display:none" class="err-msg"></div>
      <div id="reg-ok"  style="display:none" class="ok-msg"></div>
    </div>
  </div>

  <!-- AUTENTICAZIONE AR -->
  <div id="sc-auth" class="screen">
    <div class="card">
      <button class="btn-back" onclick="goHome()">&#x2190; Home</button>
      <div class="icon-circle ic-yellow" style="font-size:.85rem">AR</div>
      <h2 style="text-align:center;font-size:1.1rem;font-weight:700;margin-bottom:8px">Autenticazione AR</h2>
      <p style="color:var(--muted);font-size:.85rem;text-align:center;margin-bottom:18px;line-height:1.6">Inserisci il tuo ID. Il sistema verifichera' automaticamente il certificato e procedera' con l'autenticazione.</p>
      <div class="form-group">
        <label for="auth-vid">ID Elettore</label>
        <input id="auth-vid" type="text" placeholder="es. MarioRossi001"
               onkeydown="if(event.key==='Enter')doAuthFlow()">
      </div>
      <button id="btn-auth-flow" class="btn btn-primary" onclick="doAuthFlow()">Autenticati</button>
      <div id="auth-err" style="display:none" class="err-msg"></div>
    </div>
  </div>

  <!-- PORTALE DI VOTO (dopo auth) -->
  <div id="sc-voting" class="screen">
    <div class="card">
      <div class="voter-bar">
        <div class="icon-circle ic-green" style="margin:0;width:36px;height:36px;font-size:.85rem;flex-shrink:0">&#x2713;</div>
        <div style="flex:1">
          <div class="voter-bar-name" id="voting-nome">—</div>
          <div class="voter-bar-id"   id="voting-vid">—</div>
        </div>
        <button class="btn-logout" style="margin-left:auto" onclick="goHome()">&#x2190; Home</button>
      </div>
      <!-- Voto non ancora espresso -->
      <div id="voting-section">
        <h2 style="font-size:1.05rem;font-weight:700;margin-bottom:6px">Esprimi il Voto</h2>
        <p style="color:var(--muted);font-size:.84rem;margin-bottom:4px">Sei autenticato. La scelta e' anonima e irrevocabile.</p>
        <div class="vote-grid">
          <button id="btn-vote-si" class="btn btn-si" onclick="doVote(1)">&#x2713; S&#xec;</button>
          <button id="btn-vote-no" class="btn btn-no"  onclick="doVote(0)">&#x2717; No</button>
        </div>
        <div id="vote-err" style="display:none;margin-top:8px" class="err-msg"></div>
      </div>
      <!-- Voto gia' espresso -->
      <div id="voted-section" style="display:none">
        <div id="vote-disp"></div>
        <div id="seq-disp" class="seq-tag"></div>
      </div>
      <!-- Verifica individuale -->
      <button id="btn-vi" class="btn btn-ghost" style="margin-top:14px" onclick="doVerifyIndividual()">Verifica Individuale</button>
      <div id="vi-result"></div>
      <!-- Risultato ufficiale -->
      <div id="official-result" style="display:none"></div>
    </div>
  </div>

  <!-- VERIFICA UNIVERSALE -->
  <div id="sc-universal" class="screen">
    <div class="card">
      <button class="btn-back" onclick="goHome()">&#x2190; Home</button>
      <div class="icon-circle ic-cyan" style="font-size:.72rem">VU</div>
      <h2 style="text-align:center;font-size:1.1rem;font-weight:700;margin-bottom:8px">Verifica Universale</h2>
      <p style="color:var(--muted);font-size:.85rem;text-align:center;margin-bottom:18px;line-height:1.6">Verifica l'integrita' del processo elettorale senza credenziali. Tutti i dati usati sono pubblici.</p>
      <button id="btn-vu" class="btn btn-primary" onclick="doVerifyUniversal()">Esegui Verifica</button>
      <div id="vu-result"></div>
    </div>
  </div>

</main>
<div id="toast"></div>

<script>
let cVid  = null;
let cData = null;
let eState = '—';

(async () => {
  await fetchState();
  setInterval(async () => {
    await fetchState();
    if (cVid && currentScreen() === 'voting') await refreshVoting();
  }, 3000);
})();

async function fetchState() {
  try {
    const s = await (await fetch('/api/state')).json();
    eState = s.contract_state || '—';
    updateStateBadge();
  } catch(e) {}
}

function updateStateBadge() {
  const map = {CREATED:'badge-info',OPEN:'badge-ok',CLOSED:'badge-warn',FINALIZED:'badge-cyan',SCRUTINY_OVERDUE:'badge-err'};
  const cls = map[eState] || 'badge-info';
  const hdr = document.getElementById('hdr-state');
  hdr.className = 'badge ' + cls; hdr.textContent = eState;
  const hm = document.getElementById('home-state');
  if (hm) { hm.className = 'badge ' + cls; hm.textContent = eState; }
}

function goHome() {
  cVid = null; cData = null;
  ['vi-result','vu-result'].forEach(id => { const e=document.getElementById(id); if(e) e.innerHTML=''; });
  ['reg-err','reg-ok','auth-err'].forEach(id => { const e=document.getElementById(id); if(e) e.style.display='none'; });
  const rv = document.getElementById('reg-vid'); if (rv) rv.value = '';
  const av = document.getElementById('auth-vid'); if (av) av.value = '';
  showScreen('home');
}

function showScreen(name) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const t = document.getElementById('sc-' + name);
  if (t) t.classList.add('active');
}

function currentScreen() {
  for (const id of ['home','register','auth','voting','universal']) {
    const el = document.getElementById('sc-' + id);
    if (el && el.classList.contains('active')) return id;
  }
  return null;
}

// ── Registrazione ─────────────────────────────────────────────────────────────
async function doRegister() {
  const vid = document.getElementById('reg-vid').value.trim();
  if (!vid) { showFieldErr('reg-err', 'Inserisci il tuo ID elettore'); return; }
  const btn = document.getElementById('btn-reg');
  document.getElementById('reg-err').style.display = 'none';
  document.getElementById('reg-ok').style.display  = 'none';
  setBusy(btn, 'Registrazione in corso…');
  try {
    const r = await fetch('/api/voter/' + enc(vid) + '/register', {method:'POST'});
    const d = await r.json();
    if (!d.job_id) throw new Error(d.error || 'Nessun job_id');
    const res = await waitJob(d.job_id);
    setReady(btn, 'Registrati');
    if (res.ok) {
      const ok = document.getElementById('reg-ok');
      ok.textContent = '✓ Registrazione completata! Puoi ora autenticarti.';
      ok.style.display = '';
      toast('Registrazione completata!', true);
    } else {
      showFieldErr('reg-err', res.error || 'Registrazione fallita');
    }
  } catch(e) {
    setReady(btn, 'Registrati');
    showFieldErr('reg-err', e.message);
  }
}

// ── Autenticazione + portale voto ─────────────────────────────────────────────
async function doAuthFlow() {
  const vid = document.getElementById('auth-vid').value.trim();
  if (!vid) { showFieldErr('auth-err', 'Inserisci il tuo ID elettore'); return; }
  const btn = document.getElementById('btn-auth-flow');
  document.getElementById('auth-err').style.display = 'none';

  setBusy(btn, 'Verifica certificato…');
  let check;
  try {
    check = await (await fetch('/api/voter/' + enc(vid) + '/check')).json();
  } catch(e) {
    setReady(btn, 'Autenticati');
    showFieldErr('auth-err', 'Errore di connessione: ' + e.message); return;
  }
  if (!check.found) {
    setReady(btn, 'Autenticati');
    showFieldErr('auth-err', 'ID non trovato nel registro degli aventi diritto.'); return;
  }
  const meta = check.meta || {};
  if (!meta.registered) {
    setReady(btn, 'Autenticati');
    showFieldErr('auth-err', 'Certificato non trovato. Registrati prima presso l\'AA.'); return;
  }

  // Gia' autenticato o gia' votato: accedi direttamente al portale
  if (meta.token || meta.voted) {
    cVid = vid; cData = check;
    await loadVotingPortal();
    setReady(btn, 'Autenticati');
    showScreen('voting'); return;
  }

  if (check.election_state !== 'OPEN') {
    setReady(btn, 'Autenticati');
    showFieldErr('auth-err', 'L\'elezione non \xe8 aperta (stato: ' + (check.election_state||'—') + ').'); return;
  }

  setBusy(btn, 'Autenticazione in corso…');
  try {
    const r = await fetch('/api/voter/' + enc(vid) + '/auth', {method:'POST'});
    const d = await r.json();
    if (!d.job_id) throw new Error(d.error || 'Nessun job_id');
    const res = await waitJob(d.job_id);
    if (res.ok) {
      const check2 = await (await fetch('/api/voter/' + enc(vid) + '/check')).json();
      cVid = vid; cData = check2;
      await loadVotingPortal();
      setReady(btn, 'Autenticati');
      toast('Autenticazione completata!', true);
      showScreen('voting');
    } else {
      setReady(btn, 'Autenticati');
      showFieldErr('auth-err', res.error || 'Autenticazione fallita');
    }
  } catch(e) {
    setReady(btn, 'Autenticati');
    showFieldErr('auth-err', e.message);
  }
}

// ── Portale di voto ───────────────────────────────────────────────────────────
async function loadVotingPortal() {
  document.getElementById('voting-nome').textContent = (cData && cData.nome) || cVid || '—';
  document.getElementById('voting-vid').textContent  = cVid || '—';
  document.getElementById('vi-result').innerHTML     = '';
  document.getElementById('vote-err').style.display  = 'none';
  try {
    const data = await (await fetch('/api/voter/' + enc(cVid) + '/wallet-detail')).json();
    renderVotingPortal(data);
  } catch(e) {}
}

function renderVotingPortal(data) {
  const meta = data.meta || {};
  if (meta.voted) {
    document.getElementById('voting-section').style.display = 'none';
    document.getElementById('voted-section').style.display  = '';
    const si = data.vote_val === 1;
    document.getElementById('vote-disp').innerHTML =
      '<div class="vote-display ' + (si ? 'vote-si' : 'vote-no') + '">' +
      (si ? '&#x2713; Hai votato S\xec' : '&#x2717; Hai votato No') + '</div>';
    document.getElementById('seq-disp').textContent =
      'Numero di sequenza: ' + (data.seq_num != null ? data.seq_num : '—');
  } else {
    document.getElementById('voting-section').style.display = '';
    document.getElementById('voted-section').style.display  = 'none';
  }
  const offEl = document.getElementById('official-result');
  if (cData && cData.final_result) {
    const fr = cData.final_result;
    const pct = fr.tot > 0 ? (fr.si / fr.tot * 100).toFixed(1) : 0;
    offEl.style.display = '';
    offEl.innerHTML =
      '<div class="result-panel"><div class="result-title">Risultato Ufficiale</div>' +
      '<div class="result-nums">' +
        '<div><div class="result-big" style="color:var(--green)">' + fr.si + '</div>' +
        '<div class="result-lbl">S\xec (' + pct + '%)</div></div>' +
        '<div style="color:var(--border);font-size:1.3rem;font-weight:300">/</div>' +
        '<div><div class="result-big" style="color:var(--red)">' + fr.no + '</div>' +
        '<div class="result-lbl">No (' + (100-pct).toFixed(1) + '%)</div></div>' +
        '<div style="margin-left:auto;text-align:right">' +
        '<div style="font-size:1.2rem;font-weight:700;color:var(--muted)">' + fr.tot + '</div>' +
        '<div class="result-lbl">Totale</div></div></div>' +
      '<div class="result-bar"><div class="result-fill" style="width:' + pct + '%"></div></div></div>';
  } else { offEl.style.display = 'none'; }
}

async function refreshVoting() {
  if (!cVid) return;
  try {
    const check = await (await fetch('/api/voter/' + enc(cVid) + '/check')).json();
    if (!check.found) { goHome(); return; }
    cData = check; eState = check.election_state || eState;
    updateStateBadge();
    const data = await (await fetch('/api/voter/' + enc(cVid) + '/wallet-detail')).json();
    renderVotingPortal(data);
  } catch(e) {}
}

// ── Voto ─────────────────────────────────────────────────────────────────────
async function doVote(choice) {
  const lbl = choice === 1 ? 'S\xec' : 'No';
  if (!confirm('Confermi il voto "' + lbl + '"?\n\nAttenzione: il voto \xe8 irrevocabile.')) return;
  const si = document.getElementById('btn-vote-si');
  const no = document.getElementById('btn-vote-no');
  si.disabled = no.disabled = true;
  const err = document.getElementById('vote-err');
  err.style.display = 'none';
  try {
    const r = await fetch('/api/voter/' + enc(cVid) + '/vote',
      {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({choice})});
    const d = await r.json();
    if (!d.job_id) throw new Error(d.error || 'Nessun job_id');
    const res = await waitJob(d.job_id);
    si.disabled = no.disabled = false;
    if (res.ok) { toast('Voto espresso con successo!', true); await refreshVoting(); }
    else { err.textContent = res.error || 'Voto non registrato'; err.style.display = ''; }
  } catch(e) {
    si.disabled = no.disabled = false;
    err.textContent = e.message; err.style.display = '';
  }
}

// ── Verifica individuale ──────────────────────────────────────────────────────
async function doVerifyIndividual() {
  if (!cVid) return;
  const btn = document.getElementById('btn-vi');
  const resEl = document.getElementById('vi-result');
  resEl.innerHTML = '';
  setBusy(btn, 'Verifica in corso…');
  try {
    const d = await (await fetch('/api/verify/individual/' + enc(cVid))).json();
    if (!d.job_id) throw new Error('Nessun job_id');
    const res = await waitJob(d.job_id);
    setReady(btn, 'Verifica Individuale');
    const ok = res.ok && res.data && res.data.result;
    const bbReady = eState === 'FINALIZED' || eState === 'CLOSED';
    resEl.innerHTML = '<div class="vresult-card">' +
      '<div class="vresult-title ' + (ok?'ok':'fail') + '">' + (ok?'✓ Verifica Superata':'✗ Verifica Fallita') + '</div>' +
      (ok ?
        '<div class="vcheck vcheck-ok"><span>✓</span><span>Scheda ancorata on-chain</span></div>' +
        '<div class="vcheck vcheck-ok"><span>✓</span><span>Ricevuta AR autentica</span></div>' +
        '<div class="vcheck ' + (bbReady?'vcheck-ok':'vcheck-warn') + '"><span>' + (bbReady?'✓':'?') + '</span>' +
        '<span>Voto conteggiato nel Bulletin Board' + (bbReady?'':' (BB non ancora pubblicato)') + '</span></div>'
        :
        '<div class="vcheck vcheck-fail"><span>✗</span><span>' + esc(res.error||'Verifica non superata') + '</span></div>'
      ) + '</div>';
    toast(ok ? 'Verifica individuale: PASS' : 'Verifica individuale: FALLITA', ok);
  } catch(e) {
    setReady(btn, 'Verifica Individuale');
    resEl.innerHTML = '<div class="err-msg">' + esc(e.message) + '</div>';
  }
}

// ── Verifica universale ───────────────────────────────────────────────────────
async function doVerifyUniversal() {
  const btn = document.getElementById('btn-vu');
  const resEl = document.getElementById('vu-result');
  resEl.innerHTML = '';
  setBusy(btn, 'Verifica in corso…');
  try {
    const d = await (await fetch('/api/verify/universal')).json();
    if (!d.job_id) throw new Error('Nessun job_id');
    const res = await waitJob(d.job_id);
    setReady(btn, 'Esegui Verifica');
    const ok = res.ok && res.data && res.data.result;
    resEl.innerHTML = '<div class="vresult-card" style="margin-top:14px">' +
      '<div class="vresult-title ' + (ok?'ok':'fail') + '">' + (ok?'✓ Elezione Verificata':'✗ Verifica Fallita') + '</div>' +
      (ok ?
        '<div class="vcheck vcheck-ok"><span>✓</span><span>Coerenza commitment AR ↔ AS</span></div>' +
        '<div class="vcheck vcheck-ok"><span>✓</span><span>Conteggio risultati corretto (R = Σv_i)</span></div>' +
        '<div class="vcheck vcheck-ok"><span>✓</span><span>Firma AS sul Bulletin Board valida</span></div>' +
        '<div class="vcheck vcheck-ok"><span>✓</span><span>Attestazione EC valida</span></div>'
        :
        '<div class="vcheck vcheck-fail"><span>✗</span><span>' + esc(res.error||'Verifica non superata') + '</span></div>'
      ) + '</div>';
    toast(ok ? 'Verifica universale: PASS' : 'Verifica universale: FALLITA', ok);
  } catch(e) {
    setReady(btn, 'Esegui Verifica');
    resEl.innerHTML = '<div class="err-msg">' + esc(e.message) + '</div>';
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────
async function waitJob(jid) {
  for (let i = 0; i < 120; i++) {
    await sleep(500);
    try {
      const d = await (await fetch('/api/job/' + jid)).json();
      if (d.status === 'done')  return {ok: true,  data: d.result};
      if (d.status === 'error') return {ok: false, error: d.error, output: d.output||''};
    } catch(e) {}
  }
  return {ok: false, error: 'Timeout (60s)'};
}

function showFieldErr(id, msg) { const e=document.getElementById(id); e.textContent=msg; e.style.display=''; }
function enc(s) { return encodeURIComponent(s); }
function setBusy(btn,msg){btn._orig=btn.innerHTML;btn.innerHTML='<span class="spin"></span> '+msg;btn.disabled=true;}
function setReady(btn,lbl){btn.innerHTML=btn._orig||lbl;btn.disabled=false;}
function toast(msg,ok){
  const e=document.getElementById('toast');
  e.textContent=msg;e.className='show '+(ok?'tok':'terr');
  clearTimeout(window._tt);
  window._tt=setTimeout(()=>{e.className=ok?'tok':'terr';},ok?4000:8000);
}
function esc(s){if(s===null||s===undefined)return '';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function sleep(ms){return new Promise(r=>setTimeout(r,ms));}
</script>
</body>
</html>"""

# ── HTML: Pannello di Controllo (admin) ───────────────────────────────────────
ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APS Voting — Pannello di Controllo</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#0d1117; --surface:#161b22; --surface2:#1e2736; --border:#30363d;
    --text:#e6edf3; --muted:#7d8590; --accent:#58a6ff;
    --green:#3fb950; --yellow:#d29922; --red:#f85149; --cyan:#39c5cf; --r:8px;
  }
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  html{font-size:14px}
  body{background:var(--bg);color:var(--text);font-family:'Syne',sans-serif;min-height:100vh;display:flex;flex-direction:column}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;height:56px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:100}
  .logo{font-size:1.1rem;font-weight:800;letter-spacing:.05em;color:var(--accent);text-transform:uppercase}
  .logo span{color:var(--text)}
  .hsub{font-size:.72rem;color:var(--muted);font-weight:600;letter-spacing:.08em;text-transform:uppercase}
  .hbadges{display:flex;gap:8px;margin-left:auto;align-items:center}
  .badge{font-family:'JetBrains Mono',monospace;font-size:.72rem;padding:3px 10px;border-radius:20px;font-weight:500;border:1px solid transparent;cursor:default}
  .badge-ok{background:#1a3a1f;color:var(--green);border-color:#2d5a35}
  .badge-warn{background:#2d2008;color:var(--yellow);border-color:#4a3510}
  .badge-err{background:#3a1a1a;color:var(--red);border-color:#5a2a2a}
  .badge-info{background:#162032;color:var(--accent);border-color:#1e3a5a}
  .badge-cyan{background:#0d2a2c;color:var(--cyan);border-color:#1a4548}
  .main{display:grid;grid-template-columns:200px 1fr;flex:1;min-height:0}
  .sidebar{border-right:1px solid var(--border);padding:18px 14px;display:flex;flex-direction:column;gap:14px;overflow-y:auto;max-height:calc(100vh - 56px);position:sticky;top:56px}
  .ctrl-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:20px}
  .stitle{font-size:.65rem;font-weight:700;letter-spacing:.12em;color:var(--muted);text-transform:uppercase;margin-bottom:10px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px}
  .sgrid{display:flex;flex-direction:column;gap:6px}
  .srow{display:flex;align-items:center;justify-content:space-between;font-size:.82rem}
  .slabel{color:var(--muted)}
  .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
  .dot-ok{background:var(--green);box-shadow:0 0 6px var(--green)}
  .dot-off{background:var(--border)}
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:7px 14px;border-radius:6px;font-family:'Syne',sans-serif;font-size:.8rem;font-weight:600;cursor:pointer;border:1px solid transparent;transition:all .15s;width:100%;margin-top:6px}
  .btn:disabled{opacity:.4;cursor:not-allowed}
  .btn-primary{background:var(--accent);color:#000;border-color:var(--accent)}
  .btn-primary:not(:disabled):hover{background:#79baff}
  .btn-success{background:var(--green);color:#000;border-color:var(--green)}
  .btn-success:not(:disabled):hover{background:#5fd96e}
  .btn-danger{background:var(--red);color:#fff;border-color:var(--red)}
  .btn-danger:not(:disabled):hover{background:#ff6b65}
  .btn-ghost{background:transparent;color:var(--text);border-color:var(--border)}
  .btn-ghost:not(:disabled):hover{background:var(--surface2)}
  .btn-cyan{background:var(--cyan);color:#000;border-color:var(--cyan)}
  .btn-cyan:not(:disabled):hover{background:#5ee0e6}
  .content{padding:24px;overflow-y:auto;max-height:calc(100vh - 56px)}
  .rpanel{background:linear-gradient(135deg,#1a2d1a,#1e2736);border:1px solid #3d6b3d;border-radius:var(--r);padding:20px;margin-bottom:20px}
  .rtitle{font-size:.65rem;font-weight:700;letter-spacing:.12em;color:var(--green);text-transform:uppercase;margin-bottom:12px}
  .rnums{display:flex;gap:24px;align-items:baseline}
  .rbig{font-size:2.8rem;font-weight:800;line-height:1}
  .rbig.si{color:var(--green)}.rbig.no{color:var(--red)}
  .rlabel{font-size:.75rem;color:var(--muted);margin-top:2px}
  .rbar{margin-top:14px;height:8px;background:var(--border);border-radius:4px;overflow:hidden}
  .rbar-fill{height:100%;background:var(--green);transition:width .6s ease}
  .mval{font-family:'JetBrains Mono',monospace;font-size:.68rem;color:var(--muted);margin-top:4px;word-break:break-all}
  .log-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);margin-top:20px}
  .log-hdr{padding:10px 16px;border-bottom:1px solid var(--border);font-size:.72rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none}
  .log-hdr:hover{color:var(--text)}
  .log-body{font-family:'JetBrains Mono',monospace;font-size:.72rem;padding:12px 16px;max-height:45vh;min-height:180px;overflow-y:auto;line-height:1.7;color:#8b949e}
  .log-body .err{color:var(--red)}.log-body .ok{color:var(--green)}.log-body .info{color:var(--accent)}.log-body .warn{color:var(--yellow)}.log-body .shamir{color:var(--cyan);font-weight:500}
  #toast{position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:var(--r);font-size:.82rem;font-weight:600;z-index:9999;opacity:0;transform:translateY(12px);transition:all .25s;pointer-events:none;max-width:400px}
  #toast.show{opacity:1;transform:translateY(0)}
  #toast.tok{background:#1a3a1f;color:var(--green);border:1px solid #3d6b3d}
  #toast.terr{background:#3a1a1a;color:var(--red);border:1px solid #6b3d3d}
  .spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.2);border-top-color:currentColor;border-radius:50%;animation:sp .7s linear infinite}
  @keyframes sp{to{transform:rotate(360deg)}}
  .empty{grid-column:1/-1;text-align:center;padding:48px;color:var(--muted);font-size:.9rem}
  .vrow{display:flex;align-items:center;gap:8px;font-size:.8rem;margin-top:6px}
</style>
</head>
<body>
<header>
  <div class="logo">APS<span> Voting</span></div>
  <div class="hsub">Pannello di Controllo</div>
  <div class="hbadges">
    <span id="hdr-g" class="badge badge-warn">Ganache…</span>
    <span id="hdr-c" class="badge badge-warn">Contratto…</span>
    <span id="hdr-s" class="badge badge-info">—</span>
  </div>
</header>
<div class="main">
  <aside class="sidebar">
    <div class="stitle">Stato Sistema</div>
    <div class="card">
      <div class="sgrid">
        <div class="srow"><span class="slabel">Ganache</span><span id="d-g" class="dot dot-off"></span></div>
        <div class="srow"><span class="slabel">Contratto</span><span id="d-c" class="dot dot-off"></span></div>
        <div class="srow"><span class="slabel">CA</span><span id="d-ca" class="dot dot-off"></span></div>
        <div class="srow"><span class="slabel">AA</span><span id="d-aa" class="dot dot-off"></span></div>
        <div class="srow"><span class="slabel">AR</span><span id="d-ar" class="dot dot-off"></span></div>
        <div class="srow"><span class="slabel">AS</span><span id="d-as" class="dot dot-off"></span></div>
        <div class="srow"><span class="slabel">EC</span><span id="d-ec" class="dot dot-off"></span></div>
        <div class="srow" style="margin-top:6px;border-top:1px solid var(--border);padding-top:6px">
          <span class="slabel">Schede on-chain</span>
          <span id="d-bal" style="font-family:'JetBrains Mono',monospace;font-size:.8rem">—</span>
        </div>
      </div>
    </div>
  </aside>
  <main class="content">
    <div class="ctrl-grid">
      <div>
        <div class="stitle">Setup</div>
        <div class="card">
          <button id="btn-ca"   class="btn btn-ghost" onclick="run('CA','/api/setup/ca','btn-ca')">Inizializza CA</button>
          <button id="btn-auth" class="btn btn-ghost" onclick="run('AA/AR/AS/EC','/api/setup/authorities','btn-auth')">Inizializza AA/AR/AS/EC</button>
          <button id="btn-dep"  class="btn btn-ghost" onclick="run('Deploy','/api/setup/deploy','btn-dep')">Deploy Contratto</button>
        </div>
      </div>
      <div>
        <div class="stitle">Gestione Elezione</div>
        <div class="card">
          <button id="btn-open"    class="btn btn-primary" onclick="run('Apertura urne','/api/election/open','btn-open',true)">Apri Urne</button>
          <button id="btn-close"   class="btn btn-danger"  onclick="run('Chiusura urne','/api/election/close','btn-close',true)">Chiudi Urne</button>
          <button id="btn-tally"   class="btn btn-cyan"    onclick="run('Scrutinio','/api/election/tally','btn-tally',true)">Esegui Scrutinio</button>
          <button id="btn-advance" class="btn btn-ghost"   onclick="run('Avanza tempo','/api/test/advance-time','btn-advance')" style="font-size:.72rem;color:var(--yellow);border-color:#4a3510">&#x23E9; Avanza clock Ganache (+20s)</button>
          <button id="btn-overdue" class="btn btn-danger"  onclick="run('Inadempienza AS','/api/election/declare-overdue','btn-overdue',true)" style="opacity:.7">&#x26A0; Dichiara Inadempienza AS</button>
        </div>
      </div>
      <div>
        <div class="stitle">Verifica &amp; Sessione</div>
        <div class="card">
          <button id="btn-vu" class="btn btn-ghost" onclick="runVerifyUniversal()">Verifica Universale</button>
          <div id="vres" style="margin-top:8px"></div>
          <hr style="border:none;border-top:1px solid var(--border);margin:12px 0">
          <button class="btn btn-ghost" style="border-color:#5a2a2a;color:var(--red)" onclick="doReset()">&#x21BA; Reset Sessione</button>
        </div>
      </div>
    </div>
    <div id="rpanel"></div>
    <div class="log-panel">
      <div class="log-hdr" onclick="toggleLog()"><span>Log Operazioni</span><span id="ltog">&#x25BE;</span></div>
      <div id="lbody" class="log-body"></div>
    </div>
  </main>
</div>
<div id="toast"></div>
<script>
let sys = {}, logOpen = true, lastLen = 0;

async function poll() {
  try { sys = await (await fetch('/api/state')).json(); renderSidebar(); } catch(e){}
}
async function pollLog() {
  try {
    const lines = await (await fetch('/api/log')).json();
    if (lines.length !== lastLen) { lastLen = lines.length; renderLog(lines); }
  } catch(e){}
}
setInterval(poll, 2000); setInterval(pollLog, 800);
poll(); pollLog();

function renderSidebar() {
  const s = sys;
  setBadge('hdr-g', s.ganache ? ['badge-ok','Ganache ✓'] : ['badge-err','Ganache ✗']);
  setBadge('hdr-c', s.contract_deployed ? ['badge-ok','Contratto ✓'] : ['badge-warn','Contratto ✗']);
  const sc = {'CREATED':'badge-info','OPEN':'badge-ok','CLOSED':'badge-warn','FINALIZED':'badge-cyan','SCRUTINY_OVERDUE':'badge-err','—':'badge-info'};
  const hdrS = document.getElementById('hdr-s');
  hdrS.className = 'badge '+(sc[s.contract_state]||'badge-info');
  hdrS.textContent = s.contract_state;
  setDot('d-g',  s.ganache);
  setDot('d-c',  s.contract_deployed && s.contract_state !== '—');
  setDot('d-ca', s.ca_ready); setDot('d-aa', s.aa_ready);
  setDot('d-ar', s.ar_ready); setDot('d-as', s.as_ready); setDot('d-ec', s.ec_ready);
  document.getElementById('d-bal').textContent = s.ballot_count ?? '—';
  document.getElementById('btn-ca').disabled   = s.ca_ready;
  document.getElementById('btn-auth').disabled = !s.ca_ready||(s.aa_ready&&s.ar_ready&&s.as_ready&&s.ec_ready);
  document.getElementById('btn-dep').disabled  = !s.ganache||s.contract_deployed;
  const cs = s.contract_state;
  document.getElementById('btn-open').disabled    = cs!=='CREATED'||!s.ganache;
  document.getElementById('btn-close').disabled   = cs!=='OPEN';
  document.getElementById('btn-tally').disabled   = cs!=='CLOSED';
  document.getElementById('btn-advance').disabled = cs!=='CLOSED';
  document.getElementById('btn-overdue').disabled = cs!=='CLOSED';
  document.getElementById('btn-vu').disabled      = cs!=='FINALIZED';
  if (s.final_result) {
    const fr = s.final_result;
    const pct = fr.tot>0?(fr.si/fr.tot*100).toFixed(1):0;
    document.getElementById('rpanel').innerHTML = `
      <div class="rpanel">
        <div class="rtitle">Risultato Ufficiale</div>
        <div class="rnums">
          <div><div class="rbig si">${fr.si}</div><div class="rlabel">S\xec (${pct}%)</div></div>
          <div style="color:var(--border);font-size:1.5rem;font-weight:300">/</div>
          <div><div class="rbig no">${fr.no}</div><div class="rlabel">No (${(100-pct).toFixed(1)}%)</div></div>
          <div style="margin-left:auto;text-align:right"><div style="font-size:1.4rem;font-weight:700;color:var(--muted)">${fr.tot}</div><div class="rlabel">Totale</div></div>
        </div>
        <div class="rbar"><div class="rbar-fill" style="width:${pct}%"></div></div>
        ${s.merkle_root_urna?`<div class="mval">MerkleRootUrna: ${s.merkle_root_urna}</div>`:''}
        ${s.merkle_root_bb?`<div class="mval">MerkleRootBB: ${s.merkle_root_bb}</div>`:''}
      </div>`;
  }
}
function setBadge(id,[cls,txt]){const e=document.getElementById(id);e.className='badge '+cls;e.textContent=txt}
function setDot(id,ok){document.getElementById(id).className='dot '+(ok?'dot-ok':'dot-off')}

async function waitJob(jid) {
  for (let i=0; i<120; i++) {
    await sleep(500);
    try {
      const d = await (await fetch(`/api/job/${jid}`)).json();
      if (d.status === 'done')  return {ok:true,  data:d.result};
      if (d.status === 'error') return {ok:false, error:d.error, output:d.output||''};
    } catch(e) {}
  }
  return {ok:false, error:'Timeout: operazione non completata in 60s'};
}

async function run(label, url, btnId, refresh) {
  setBusy(btnId, true);
  let jid;
  try {
    const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}});
    const d = await r.json();
    jid = d.job_id;
    if (!jid) throw new Error(d.error||'Nessun job_id ricevuto');
  } catch(e) {
    setBusy(btnId, false);
    showErr(label+': '+e.message); return;
  }
  const res = await waitJob(jid);
  setBusy(btnId, false);
  if (res.ok) {
    toast(label+' completato ✓', true);
    await poll();
  } else {
    showErr(label+' ERRORE: '+res.error);
    if (res.output) res.output.split('\n').filter(l=>l.trim()).forEach(l=>appendLog(l,'err'));
  }
}

async function runVerifyUniversal() {
  setBusy('btn-vu', true);
  let jid;
  try {
    const d = await (await fetch('/api/verify/universal')).json();
    jid = d.job_id;
  } catch(e) { setBusy('btn-vu',false); showErr('Verifica: '+e.message); return; }
  const res = await waitJob(jid);
  setBusy('btn-vu', false);
  const panel = document.getElementById('vres');
  if (res.ok && res.data && res.data.result) {
    panel.innerHTML=`<div class="card"><div style="font-size:.7rem;font-weight:700;color:var(--green);letter-spacing:.1em;margin-bottom:8px">VERIFICA UNIVERSALE ✓</div>
      <div class="vrow"><span>✓</span> Coerenza AR↔AS</div>
      <div class="vrow"><span>✓</span> Conteggio corretto</div>
      <div class="vrow"><span>✓</span> Firma σ_AS valida</div>
      <div class="vrow"><span>✓</span> Attestazione EC valida</div></div>`;
    toast('Verifica universale: PASS ✓', true);
  } else {
    panel.innerHTML=`<div class="card" style="border-color:var(--red)"><div style="color:var(--red);font-size:.8rem">✗ Verifica fallita</div></div>`;
    showErr('Verifica universale FALLITA: '+(res.error||'verifica non superata'));
  }
}

async function doReset() {
  if (!confirm('Reset Sessione\n\nEliminati: CA, AA, AR, AS, EC, wallets, contract_info, bulletin_board.\nConservati: authorized_voters.json, contracts_out/\n\nDovrai fare un nuovo deploy su Ganache.\n\nConfermi?')) return;
  try {
    const d = await (await fetch('/api/reset',{method:'POST'})).json();
    if (d.success) {
      toast('Sessione resettata ✓', true);
      document.getElementById('rpanel').innerHTML='';
      document.getElementById('vres').innerHTML='';
      setTimeout(()=>{poll();},300);
    } else showErr('Reset parziale: '+d.error);
  } catch(e) { showErr('Reset: '+e.message); }
}

function renderLog(lines) {
  if (!logOpen) return;
  const b = document.getElementById('lbody');
  b.innerHTML = lines.map(l=>{
    let c='';
    if(l.includes('ERRORE')||l.includes('✗')||l.includes('RIFIUTATO'))c='err';
    else if(l.includes('✓')||l.includes('PASS')||l.includes('completato')||l.includes('OK'))c='ok';
    else if(l.includes('[AS-Shamir]'))c='shamir';
    else if(l.includes('[Blockchain]')||l.includes('[EC]'))c='info';
    else if(l.includes('WARN')||l.includes('Attenzione'))c='warn';
    return `<div class="${c}">${esc(l)}</div>`;
  }).join('');
  b.scrollTop=b.scrollHeight;
}
function appendLog(line, cls='') {
  const b=document.getElementById('lbody');
  const d=document.createElement('div');
  d.className=cls; d.textContent=line;
  b.appendChild(d); b.scrollTop=b.scrollHeight;
}
function toggleLog(){
  logOpen=!logOpen;
  document.getElementById('lbody').style.display=logOpen?'':'none';
  document.getElementById('ltog').textContent=logOpen?'▾':'▸';
}

function showErr(msg) { toast(msg, false); appendLog('✗ '+msg, 'err'); }
function toast(msg, ok) {
  const e=document.getElementById('toast');
  e.textContent=msg; e.className='show '+(ok?'tok':'terr');
  clearTimeout(window._tt);
  window._tt=setTimeout(()=>{e.className=ok?'tok':'terr';},ok?4000:9000);
}
function setBusy(id, busy) {
  const e=document.getElementById(id); if(!e)return;
  if(busy){e._orig=e.innerHTML;e.innerHTML='<span class="spin"></span> In corso…';e.disabled=true;}
  else{if(e._orig)e.innerHTML=e._orig;e.disabled=false;}
}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}
</script>
</body>
</html>"""

# ── Route handlers ────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return Response(ADMIN_HTML, mimetype="text/html")

@app.route("/voter")
def voter_ui():
    return Response(VOTER_HTML, mimetype="text/html")

def open_browser():
    time.sleep(1.2)
    webbrowser.open(f"http://{HOST}:{PORT}/")
    time.sleep(0.4)
    webbrowser.open(f"http://{HOST}:{PORT}/voter")

if __name__ == "__main__":
    print(f"╔{'='*46}╗")
    print(f"║  APS Voting — GUI                            ║")
    print(f"║  Admin:    http://{HOST}:{PORT}/              ║")
    print(f"║  Elettore: http://{HOST}:{PORT}/voter         ║")
    print(f"╚{'='*46}╝")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
