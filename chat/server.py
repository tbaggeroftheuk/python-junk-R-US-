#!/usr/bin/env python3
import os
import json
import secrets
import base64
import threading
import logging
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_socketio import SocketIO, emit, disconnect, join_room

# ===== Home directory setup =====
HOME_DIR = os.path.expanduser("~")
SHARED_DIR = os.path.join(HOME_DIR, "Users")
LOG_DIR = os.path.join(HOME_DIR, "Logs")
os.makedirs(SHARED_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ===== Logging setup =====
log_file = os.path.join(LOG_DIR, f"{datetime.now().strftime('%Y-%m-%d')}.log")
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

def log_debug(msg):
    logging.debug(msg)

# ===== Flask + SocketIO =====
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")  # Cloudflare-compatible
log_debug("Server initialized")

# ===== JSON helpers =====
def safe_load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        log_debug(f"JSON load error at {path}: {e}")
        return None

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# ===== Account management =====
def get_account_by_username(username):
    for device_id in os.listdir(SHARED_DIR):
        account_file = os.path.join(SHARED_DIR, device_id, "account.info")
        data = safe_load_json(account_file)
        if data and data.get("username") == username:
            return data
    return None

def register_user(username, password):
    if get_account_by_username(username):
        log_debug(f"Registration failed: Username {username} exists")
        return False, "Username exists"
    device_id = secrets.token_hex(8)
    device_dir = os.path.join(SHARED_DIR, device_id)
    os.makedirs(device_dir, exist_ok=True)
    save_json(os.path.join(device_dir, "account.info"),
              {"username": username, "password": password, "device_id": device_id})
    log_debug(f"Registered new user {username} with device_id {device_id}")
    return True, device_id

def authenticate_user(username, password):
    account = get_account_by_username(username)
    if not account or account.get("password") != password:
        log_debug(f"Authentication failed for {username}")
        return False, None
    log_debug(f"Authentication successful for {username}")
    return True, account["device_id"]

# ===== Connected clients =====
connected_clients = {}  # sid -> {"device_id":..., "username":...}

# ===== WebSocket Events =====
@socketio.on('connect')
def ws_connect():
    log_debug(f"WebSocket connection from {request.remote_addr}")
    emit('message', {'msg': 'Authenticate by sending {"username": "...", "password": "..."} via "authenticate" event'})

@socketio.on('authenticate')
def ws_auth(data):
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        log_debug(f"WebSocket auth missing credentials from {request.remote_addr}")
        disconnect()
        return
    ok, device_id = authenticate_user(username, password)
    if not ok:
        disconnect()
        return
    connected_clients[request.sid] = {"device_id": device_id, "username": username}
    join_room(username)
    log_debug(f"{username} authenticated via WebSocket with device_id {device_id}")
    emit('authenticated', {'username': username, 'device_id': device_id})
    emit('message', {'msg': f'[SERVER] {username} joined.'}, broadcast=True, include_self=False)

@socketio.on('message')
def ws_message(data):
    client = connected_clients.get(request.sid)
    if not client:
        disconnect()
        return
    msg = data.get('msg')
    if not msg:
        return
    if data.get('type') == 'pm':
        target_name = data.get('target')
        log_debug(f"PM from {client['username']} to {target_name}: {msg}")
        emit('message', {'msg': f'[PM from {client["username"]}] {msg}'}, room=target_name)
        emit('message', {'msg': f'[PM to {target_name}] {msg}'})
    elif data.get('type') == 'file':
        target_name = data.get('target')
        filename = data.get('filename')
        b64_data = data.get('b64')
        log_debug(f"File transfer from {client['username']} to {target_name}: {filename} ({len(b64_data)} bytes)")
        emit('file', {'from': client["username"], 'filename': filename, 'b64': b64_data}, room=target_name)
        emit('message', {'msg': f'File {filename} sent to {target_name}.'})
    else:
        log_debug(f"Broadcast from {client['username']}: {msg}")
        emit('message', {'msg': f'[{client["username"]}] {msg}'}, broadcast=True)

@socketio.on('disconnect')
def ws_disconnect():
    client = connected_clients.pop(request.sid, None)
    if client:
        log_debug(f"{client['username']} disconnected")
        emit('message', {'msg': f'[SERVER] {client["username"]} left.'}, broadcast=True)

# ===== Flask API =====
@app.route("/api/register", methods=["POST"])
def api_register():
    username = request.form.get("username")
    password = request.form.get("password")
    if not username or not password:
        abort(400, "username and password required")
    ok, resp = register_user(username, password)
    if ok:
        log_debug(f"API register success: {username}")
        return jsonify({"status":"OK","device_id":resp})
    return jsonify({"status":"error","reason":resp}), 400

@app.route("/api/login", methods=["POST"])
def api_login():
    username = request.form.get("username")
    password = request.form.get("password")
    if not username or not password:
        abort(400, "username and password required")
    ok, device_id = authenticate_user(username, password)
    if not ok:
        abort(403, "Invalid credentials")
    log_debug(f"API login success: {username}")
    return jsonify({"status":"OK","username":username,"device_id":device_id})

@app.route("/api/broadcast", methods=["POST"])
def api_broadcast():
    username = request.form.get("username")
    password = request.form.get("password")
    msg = request.form.get("message")
    if not username or not password or not msg:
        abort(400)
    ok, device_id = authenticate_user(username, password)
    if not ok:
        abort(403)
    log_debug(f"API broadcast from {username}: {msg}")
    socketio.emit('message', {'msg': f'[API Broadcast from {username}] {msg}'})
    return jsonify({"status":"OK"})

@app.route("/api/pm", methods=["POST"])
def api_pm():
    username = request.form.get("username")
    password = request.form.get("password")
    target = request.form.get("target")
    msg = request.form.get("message")
    if not username or not password or not target or not msg:
        abort(400)
    ok, device_id = authenticate_user(username, password)
    if not ok:
        abort(403)
    log_debug(f"API PM from {username} to {target}: {msg}")
    socketio.emit('message', {'msg': f'[PM from {username}] {msg}'}, room=target)
    return jsonify({"status":"OK"})

@app.route("/api/sendfile", methods=["POST"])
def api_sendfile():
    username = request.form.get("username")
    password = request.form.get("password")
    target = request.form.get("target")
    file = request.files.get("file")
    if not username or not password or not target or not file:
        abort(400)
    ok, device_id = authenticate_user(username, password)
    if not ok:
        abort(403)
    b64_data = base64.b64encode(file.read()).decode()
    log_debug(f"API file from {username} to {target}: {file.filename} ({len(b64_data)} bytes)")
    socketio.emit('file', {'from': username, 'filename': file.filename, 'b64': b64_data}, room=target)
    return jsonify({"status":"OK"})

# ===== Server commands (console) =====
def server_commands():
    while True:
        try:
            cmd = input("[SERVER CMD] ").strip()
            if cmd.startswith("broadcast "):
                msg = cmd[len("broadcast "):]
                log_debug(f"Server broadcast: {msg}")
                socketio.emit('message', {'msg': f'[SERVER] {msg}'})
            elif cmd.startswith("list"):
                log_debug("Connected clients:")
                for sid, info in connected_clients.items():
                    log_debug(f" - {info['username']} (device_id: {info['device_id']})")
            elif cmd.startswith("kick "):
                target = cmd[len("kick "):].strip()
                kicked = False
                for sid, info in list(connected_clients.items()):
                    if info['username'].lower() == target.lower():
                        log_debug(f"Kicking {target}")
                        socketio.emit('message', {'msg': f'[SERVER] You have been kicked.'}, room=sid)
                        socketio.disconnect(sid)
                        kicked = True
                        break
                if not kicked:
                    log_debug(f"No such client: {target}")
            elif cmd in ("exit", "quit"):
                log_debug("Shutting down server...")
                os._exit(0)
            else:
                log_debug("Unknown command. Available: broadcast <msg>, list, kick <user>, exit")
        except Exception as e:
            log_debug(f"Command error: {e}")

# ===== Run server =====
if __name__ == "__main__":
    log_debug("Starting server on 0.0.0.0:5003")
    threading.Thread(target=server_commands, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5003, log_output=False)
