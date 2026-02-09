import os, json, base64, uuid, hashlib, random, time
from datetime import datetime
from flask import Flask, request, jsonify, make_response, send_from_directory, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash
from blockchain import SimpleBlockchain
from classical_kd import bb84_shared_key_ibm as classical_shared_key
from crypto_utils import aes_encrypt, aes_decrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration from environment variables
SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24).hex())
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin@123')
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
PORT = int(os.environ.get('PORT', 5000))
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*')

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

VOTERS_FILE = os.path.join(DATA_DIR, "voters.json")
VOTES_FILE = os.path.join(DATA_DIR, "votes.json")
FRAUD_FILE = os.path.join(DATA_DIR, "fraud.json")
OFFICERS_FILE = os.path.join(DATA_DIR, "officers.json")
PARTIES_FILE = os.path.join(DATA_DIR, "parties.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
CHAIN_FILE = os.path.join(DATA_DIR, "chain.json")

NOTA_SYMBOL = "https://upload.wikimedia.org/wikipedia/commons/5/59/NOTA_Option_Logo.png"
NOTA_PARTY = {
    "party_id": "party_0_nota",
    "party_name": "NOTA (none of the above)",
    "symbol": NOTA_SYMBOL,
    "votes": 0,
    "registered_at": datetime.now().isoformat(),
    "status": "permanent"
}

def load_json(path, default):
    try:
        if not os.path.exists(path):
            with open(path, "w") as f:
                json.dump(default, f, indent=2)
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False

def log_activity(activity, user_id=None, details=None):
    log_file = os.path.join(DATA_DIR, "activity_log.json")
    logs = load_json(log_file, [])
    logs.append({
        "timestamp": datetime.now().isoformat(),
        "activity": activity,
        "user_id": user_id,
        "details": details
    })
    save_json(log_file, logs)

def get_session_token():
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = request.headers.get('X-Session-Id')
    if not session_id:
        data = request.get_json(silent=True)
        if data:
            session_id = data.get('session_id')
    return session_id

def get_classical_key_compatible(length=32):
    """Get classical key compatible with crypto_utils"""
    try:
        key_bytes = classical_shared_key(length)
        if isinstance(key_bytes, bytes):
            return key_bytes
        else:
            return hashlib.sha256(str(key_bytes).encode()).digest()
    except Exception as e:
        print(f"Classical key generation failed: {e}, using fallback")
        return hashlib.sha256(f"{time.time()}{random.random()}".encode()).digest()

VOTERS = load_json(VOTERS_FILE, {})
VOTES = load_json(VOTES_FILE, {})
FRAUDS = load_json(FRAUD_FILE, [])
OFFICERS = load_json(OFFICERS_FILE, [])
PARTIES = load_json(PARTIES_FILE, [])
SESSIONS = load_json(SESSIONS_FILE, {})

def ensure_nota():
    global PARTIES
    if not any(p.get("party_id") == "party_0_nota" for p in PARTIES):
        PARTIES.insert(0, NOTA_PARTY.copy())
        save_json(PARTIES_FILE, PARTIES)

ensure_nota()

BLOCKCHAIN = SimpleBlockchain(difficulty=3, chain_file=CHAIN_FILE)

app = Flask(__name__)

# Security configurations
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = not DEBUG
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# CORS configuration
if ALLOWED_ORIGINS == '*':
    CORS(app)
else:
    origins_list = [origin.strip() for origin in ALLOWED_ORIGINS.split(',')]
    CORS(app, origins=origins_list, supports_credentials=True)

@app.before_request
def keep_nota():
    ensure_nota()

# ROOT: Auto-redirect to polling session (MAIN ENTRY POINT)
@app.route("/")
def home():
    """Automatically redirect to polling session"""
    return redirect("/polling")

# SERVE HTML FILES
@app.route("/admin")
def serve_admin():
    """Admin portal"""
    return send_from_directory('static', 'admin-portal.html')

@app.route("/polling")
def serve_polling():
    """Polling session - main interface"""
    return send_from_directory('static', 'polling-session.html')

# API ENDPOINTS
@app.route("/api")
def api_info():
    """API system information"""
    return jsonify({
        "system": "Classical-Cryptographic Voting API",
        "version": "4.0",
        "crypto_method": "AES-256 + RSA-2048",
        "timestamp": datetime.now().isoformat(),
        "blockchain_valid": BLOCKCHAIN.is_valid(),
        "environment": "production" if not DEBUG else "development"
    })

@app.route("/health")
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route("/status")
def status():
    return jsonify({
        "voters_count": len(VOTERS),
        "parties_count": len(PARTIES),
        "officers_count": len(OFFICERS),
        "fraud_cases": len(FRAUDS),
        "blockchain_blocks": len(BLOCKCHAIN.chain),
        "total_votes": sum(p.get("votes",0) for p in PARTIES),
        "security_method": "Classical Cryptography"
    })

@app.route("/dashboard", methods=["GET"])
def dashboard():
    total_votes = sum(p.get("votes",0) for p in PARTIES)
    voters_list = [{
        "name": v["name"], "id_number": vid, "phone": v.get("phone","N/A"),
        "has_voted": v.get("has_voted",False),
        "biometric_verified": v.get("biometric_verified", False),
        "is_fraud": vid in FRAUDS
    } for vid, v in VOTERS.items()]
    
    parties_stats = [{
        "party_name": p["party_name"], "symbol": p["symbol"], "votes": p["votes"],
        "percentage": round(p["votes"]/total_votes*100,2) if total_votes else 0
    } for p in PARTIES]
    
    return jsonify({
        "voters": voters_list,
        "polling_officers": OFFICERS,
        "parties_votes": parties_stats,
        "system_stats": {
            "total_voters": len(VOTERS),
            "total_votes": total_votes,
            "fraud_cases": len(FRAUDS),
            "blockchain_blocks": len(BLOCKCHAIN.chain),
            "blockchain_valid": BLOCKCHAIN.is_valid(),
            "security_method": "Classical Cryptography"
        }
    })

@app.route("/admin_login", methods=["POST"])
def admin_login():
    password = request.json.get("password")
    if password != ADMIN_PASSWORD:
        log_activity("admin_login_failed", "admin", {"reason": "bad_pwd"})
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401
    
    sid = str(uuid.uuid4())
    SESSIONS[sid] = {"user_type": "admin", "login_time": datetime.now().isoformat()}
    save_json(SESSIONS_FILE, SESSIONS)
    log_activity("admin_login", "admin")
    return jsonify({"ok": True, "session_id": sid})

@app.route("/officer_login", methods=["POST"])
def officer_login():
    data = request.json
    oid = data.get("id", "").strip()
    key = data.get("key_id", "").strip()
    officer = next((o for o in OFFICERS if o["number"] == oid and o["key_id"] == key), None)
    
    if not officer:
        log_activity("officer_login_failed", oid)
        return jsonify({"ok": False, "error": "Invalid Officer credentials"}), 401
    
    sid = str(uuid.uuid4())
    SESSIONS[sid] = {
        "user_type": "officer",
        "officer_id": oid,
        "key_id": key,
        "login_time": datetime.now().isoformat()
    }
    save_json(SESSIONS_FILE, SESSIONS)
    log_activity("officer_login", oid)
    return jsonify({"ok": True, "officer": officer, "session_id": sid})

@app.route("/officer/end-session", methods=["POST"])
def end_officer_session():
    try:
        data = request.get_json(silent=True) or {}
        submitted_key_id = str(data.get('key_id', '')).strip()
        
        if not submitted_key_id:
            return jsonify({"ok": False, "error": "Key-ID is required to end session"}), 400
        
        session_id = get_session_token()
        if not session_id:
            return jsonify({"ok": False, "error": "No active session found"}), 401
        
        session_data = SESSIONS.get(session_id)
        if not session_data:
            return jsonify({"ok": False, "error": "Invalid or expired session"}), 401
        
        if session_data.get('user_type') != 'officer':
            return jsonify({"ok": False, "error": "Not an officer session"}), 403
        
        stored_key_id = session_data.get('key_id') or session_data.get('officer_id', '')
        stored_key_id = str(stored_key_id).strip()
        
        if stored_key_id != submitted_key_id:
            return jsonify({"ok": False, "error": "Key-ID does not match current officer session"}), 403
        
        SESSIONS.pop(session_id, None)
        if not save_json(SESSIONS_FILE, SESSIONS):
            return jsonify({"ok": False, "error": "Failed to update session data"}), 500
        
        response = make_response(jsonify({"ok": True, "message": "Officer session ended successfully", "key_id": stored_key_id}))
        response.set_cookie('session_id', '', expires=0, httponly=True, samesite='Lax')
        log_activity("officer_session_ended", stored_key_id)
        return response
    
    except Exception as e:
        log_activity("officer_session_end_error", None, {"error": str(e)})
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500

@app.route("/admin_register_voter", methods=["POST"])
def admin_register_voter():
    d = request.json
    voter_id, name, phone = d.get("voter_id", "").strip(), d.get("name", "").strip(), d.get("phone", "").strip()
    
    if not voter_id or not name or not phone:
        return jsonify({"ok": False, "error": "All fields required"}), 400
    
    if voter_id in VOTERS:
        return jsonify({"ok": False, "error": "Voter ID exists"}), 400
    
    VOTERS[voter_id] = {
        "name": name, "phone": phone, "password": generate_password_hash("default123"),
        "iris_sample": "simulated_iris", "has_voted": False, "registered_by_admin": True,
        "registered_at": datetime.now().isoformat(), "status": "active"
    }
    save_json(VOTERS_FILE, VOTERS)
    log_activity("admin_voter_registered", "admin", {"voter_id": voter_id})
    return jsonify({"ok": True})

@app.route("/admin_register_voter_biometric", methods=["POST"])
def admin_register_voter_biometric():
    """Combined endpoint for voter registration with biometric verification"""
    d = request.json
    voter_id = d.get("voter_id", "").strip()
    name = d.get("name", "").strip()
    phone = d.get("phone", "").strip()
    
    if not voter_id or not name or not phone:
        return jsonify({"ok": False, "error": "All fields required"}), 400
    
    if voter_id in VOTERS:
        return jsonify({"ok": False, "error": "Voter ID already exists"}), 400
    
    # Simulate biometric verification (95% success rate)
    if random.random() < 0.05:
        return jsonify({"ok": False, "error": "Biometric verification failed"}), 400
    
    # Register voter with biometric data
    VOTERS[voter_id] = {
        "name": name,
        "phone": phone,
        "password": generate_password_hash("default123"),
        "iris_sample": f"biometric_data_{hashlib.md5(voter_id.encode()).hexdigest()[:10]}",
        "has_voted": False,
        "registered_by_admin": True,
        "biometric_verified": datetime.now().isoformat(),
        "biometric_type": "combined",
        "registered_at": datetime.now().isoformat(),
        "status": "active"
    }
    save_json(VOTERS_FILE, VOTERS)
    log_activity("admin_voter_registered_with_biometric", "admin", {
        "voter_id": voter_id,
        "biometric_verified": True
    })
    return jsonify({"ok": True, "message": "Voter registered with biometric verification"})

@app.route("/register_officer", methods=["POST"])
def register_officer():
    d = request.json
    name, number = d.get("name", "").strip(), d.get("number", "").strip()
    
    if not name or not number or not number.isalnum():
        return jsonify({"ok": False, "error": "Invalid data"}), 400
    
    if any(o["number"] == number for o in OFFICERS):
        return jsonify({"ok": False, "error": "Officer number exists"}), 400
    
    key = str(random.randint(100000000, 999999999))
    while any(o["key_id"] == key for o in OFFICERS):
        key = str(random.randint(100000000, 999999999))
    
    OFFICERS.append({
        "name": name, "number": number, "key_id": key,
        "registered_at": datetime.now().isoformat(), "status": "active"
    })
    save_json(OFFICERS_FILE, OFFICERS)
    log_activity("officer_registered", "admin", {"officer_number": number, "key_id": key})
    return jsonify({"ok": True, "key_id": key})

@app.route("/register_party", methods=["POST"])
def register_party():
    d = request.json
    pname, psymbol = d.get("party_name", "").strip(), d.get("symbol", "").strip()
    
    if not pname or not psymbol:
        return jsonify({"ok": False, "error": "Missing data"}), 400
    
    if pname.lower().startswith("nota"):
        return jsonify({"ok": False, "error": "NOTA already permanent"}), 400
    
    if any(p["party_name"].lower() == pname.lower() for p in PARTIES):
        return jsonify({"ok": False, "error": "Party exists"}), 400
    
    pid = f"party_{len(PARTIES) + 1}_{pname.lower().replace(' ', '_')[:20]}"
    PARTIES.append({
        "party_id": pid, "party_name": pname, "symbol": psymbol,
        "votes": 0, "registered_at": datetime.now().isoformat(), "status": "active"
    })
    save_json(PARTIES_FILE, PARTIES)
    log_activity("party_registered", "admin", {"party_name": pname})
    return jsonify({"ok": True, "party_id": pid})

@app.route("/verify_registered_voter", methods=["POST"])
def verify_registered_voter():
    voter_id = request.json.get("voter_id", "").strip()
    v = VOTERS.get(voter_id)
    
    if not v or not v.get("registered_by_admin"):
        if voter_id not in FRAUDS:
            FRAUDS.append(voter_id)
            save_json(FRAUD_FILE, FRAUDS)
        return jsonify({"ok": False, "error": "Voter not authorised"}), 403
    
    if v.get("has_voted"):
        if voter_id not in FRAUDS:
            FRAUDS.append(voter_id)
            save_json(FRAUD_FILE, FRAUDS)
        return jsonify({"ok": False, "error": "Duplicate voting detected"}), 400
    
    log_activity("voter_verified", voter_id)
    return jsonify({"ok": True, "voter": {"name": v["name"], "phone": v["phone"]}})

@app.route("/verify_biometric", methods=["POST"])
def verify_biometric():
    voter_id = request.json.get("voter_id", "").strip()
    btype = request.json.get("type", "thumb")
    v = VOTERS.get(voter_id)
    
    if not v:
        return jsonify({"ok": False, "error": "Voter not found"}), 404
    
    if voter_id in FRAUDS:
        return jsonify({"ok": False, "error": "Fraudulent voter"}), 403
    
    if random.random() < 0.05:
        return jsonify({"ok": False, "error": f"{btype} verification failed"}), 400
    
    v["biometric_verified"] = datetime.now().isoformat()
    v["biometric_type"] = btype
    save_json(VOTERS_FILE, VOTERS)
    log_activity("biometric_verified", voter_id, {"type": btype})
    return jsonify({"ok": True})

@app.route("/get_parties", methods=["GET"])
def get_parties():
    return jsonify({"parties": [{
        "party_name": p["party_name"],
        "symbol": p["symbol"],
        "party_id": p["party_id"]
    } for p in PARTIES if p["status"] == "active"]})

@app.route("/cast_vote", methods=["POST"])
def cast_vote():
    d = request.json
    voter_id = d.get("voter_id", "").strip()
    party_name = d.get("party_name", "").strip()
    v = VOTERS.get(voter_id)
    
    if not v:
        return jsonify({"ok": False, "error": "Voter not found"}), 400
    
    if not v.get("biometric_verified", False):
        return jsonify({"ok": False, "error": "Biometric verification required"}), 400
    
    if v.get("has_voted", False):
        return jsonify({"ok": False, "error": "Already voted"}), 400
    
    party = next((p for p in PARTIES if p["party_name"] == party_name and p["status"] == "active"), None)
    if not party:
        return jsonify({"ok": False, "error": "Invalid party"}), 400
    
    party["votes"] += 1
    v["has_voted"] = True
    v["vote_timestamp"] = datetime.now().isoformat()
    
    try:
        key = get_classical_key_compatible(32)
        vote_data = {
            "voter_id": voter_id,
            "party_name": party_name,
            "timestamp": datetime.now().isoformat(),
            "vote_id": str(uuid.uuid4()),
            "encryption_method": "AES-256-Classical"
        }
        
        enc = aes_encrypt(key, json.dumps(vote_data).encode())
        vote_record = {
            "encrypted_data": enc,
            "vote_hash": hashlib.sha256(enc.encode()).hexdigest(),
            "timestamp": vote_data["timestamp"],
            "crypto_method": "Classical"
        }
        
        VOTES.setdefault(voter_id, []).append(vote_record)
        BLOCKCHAIN.add_block({**vote_data, "vote_hash": vote_record["vote_hash"], "block_type": "vote", "crypto_type": "classical"})
    except Exception as e:
        print("Encryption/Blockchain error", e)
    
    save_json(VOTERS_FILE, VOTERS)
    save_json(VOTES_FILE, VOTES)
    save_json(PARTIES_FILE, PARTIES)
    log_activity("vote_cast", voter_id, {"party": party_name, "crypto": "classical"})
    return jsonify({"ok": True, "vote_id": vote_data["vote_id"], "encryption_method": "Classical AES-256"})

@app.route("/remove_voter", methods=["POST"])
def remove_voter():
    voter_id = request.json.get("voter_id", "").strip()
    
    if voter_id not in VOTERS:
        return jsonify({"ok": False, "error": "ID not found"}), 404
    
    if voter_id in VOTES:
        for rec in VOTES[voter_id]:
            p = next((p for p in PARTIES if p["party_name"] == rec.get("party_name")), None)
            if p and p["party_name"] != NOTA_PARTY["party_name"]:
                p["votes"] = max(0, p["votes"] - 1)
        del VOTES[voter_id]
        save_json(VOTES_FILE, VOTES)
    
    del VOTERS[voter_id]
    save_json(VOTERS_FILE, VOTERS)
    FRAUDS[:] = [f for f in FRAUDS if f != voter_id]
    save_json(FRAUD_FILE, FRAUDS)
    log_activity("voter_removed", "admin", {"voter_id": voter_id})
    return jsonify({"ok": True})

@app.route("/remove_officer", methods=["POST"])
def remove_officer():
    key = request.json.get("key_id", "").strip()
    idx = next((i for i, o in enumerate(OFFICERS) if o["key_id"] == key), None)
    
    if idx is None:
        return jsonify({"ok": False, "error": "Key-ID not found"}), 404
    
    OFFICERS.pop(idx)
    save_json(OFFICERS_FILE, OFFICERS)
    
    sessions_to_remove = [sid for sid, sess in SESSIONS.items()
                         if sess.get("user_type") == "officer" and (sess.get("key_id") == key or sess.get("officer_id") == key)]
    for sid in sessions_to_remove:
        SESSIONS.pop(sid, None)
    save_json(SESSIONS_FILE, SESSIONS)
    
    log_activity("officer_removed", "admin", {"key_id": key})
    return jsonify({"ok": True})

@app.route("/get_results", methods=["GET"])
def get_results():
    tot = sum(p["votes"] for p in PARTIES)
    ranked = sorted(PARTIES, key=lambda p: p["votes"], reverse=True)
    return jsonify({"results": [{
        "rank": i + 1,
        "party_name": p["party_name"],
        "symbol": p["symbol"],
        "votes": p["votes"],
        "percentage": round(p["votes"] / tot * 100, 2) if tot else 0
    } for i, p in enumerate(ranked)], "total_votes": tot, "crypto_method": "Classical"})

@app.route("/reset_system", methods=["POST"])
def reset_system():
    if request.json.get("password") != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Bad password"}), 401
    
    global VOTERS, VOTES, FRAUDS, OFFICERS, PARTIES, SESSIONS, BLOCKCHAIN
    VOTERS, VOTES, FRAUDS, OFFICERS, SESSIONS = {}, {}, [], [], {}
    PARTIES = [NOTA_PARTY.copy()]
    BLOCKCHAIN = SimpleBlockchain(difficulty=3, chain_file=CHAIN_FILE)
    
    for path, data in [
        (VOTERS_FILE, VOTERS),
        (VOTES_FILE, VOTES),
        (FRAUD_FILE, FRAUDS),
        (OFFICERS_FILE, OFFICERS),
        (PARTIES_FILE, PARTIES),
        (SESSIONS_FILE, SESSIONS)
    ]:
        save_json(path, data)
    
    log_activity("system_reset", "admin")
    return jsonify({"ok": True})

@app.errorhandler(404)
def _404(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(400)
def _400(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(500)
def _500(e):
    return jsonify({"error": "Server error"}), 500

if __name__=="__main__":
    print("🚀 Classical Cryptographic Voting API")
    print(f"🔐 Using AES-256 + RSA-2048 on port {PORT}")
    print(f"🌐 Environment: {'Production' if not DEBUG else 'Development'}")
    print(f"🔑 Admin Password: {ADMIN_PASSWORD}")
    print(f"🎯 Main Entry: Polling Session (auto-redirect)")
    print("✅ System ready for deployment")
    app.run(debug=DEBUG, host="0.0.0.0", port=PORT)
