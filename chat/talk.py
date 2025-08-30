import os
import sys
import base64
import requests
import socketio
from PyQt6 import QtWidgets, QtCore
from PyQt6.QtWidgets import QFileDialog, QMessageBox

# ===== Server URLs =====
SERVER_HTTP = "https://services.lifetheuniverseandeverything.co.uk/Chat/"
SERVER_WS   = "https://services.lifetheuniverseandeverything.co.uk/"   # base only (no /Chat here)
sio = socketio.Client()
USERNAME = None
PASSWORD = None
connected_users = set()
can_type = True

# ===== Chat Window =====
class ChatClient(QtWidgets.QWidget):
    new_message_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("TBag inc Chat Network")  # App branding
        self.resize(600, 400)

        layout = QtWidgets.QVBoxLayout()

        # Chat display
        self.chat_box = QtWidgets.QTextEdit()
        self.chat_box.setReadOnly(True)
        layout.addWidget(self.chat_box)

        # Input line
        self.input_line = QtWidgets.QLineEdit()
        layout.addWidget(self.input_line)

        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        self.send_btn = QtWidgets.QPushButton("Send")
        self.pm_btn = QtWidgets.QPushButton("Send PM")
        self.file_btn = QtWidgets.QPushButton("Send File")
        self.who_btn = QtWidgets.QPushButton("Who")
        btn_layout.addWidget(self.send_btn)
        btn_layout.addWidget(self.pm_btn)
        btn_layout.addWidget(self.file_btn)
        btn_layout.addWidget(self.who_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

        # Connect signals
        self.new_message_signal.connect(self.add_message)
        self.send_btn.clicked.connect(self.send_message)
        self.input_line.returnPressed.connect(self.send_message)
        self.pm_btn.clicked.connect(self.send_pm)
        self.file_btn.clicked.connect(self.send_file)
        self.who_btn.clicked.connect(self.show_users)

    def add_message(self, msg):
        self.chat_box.append(msg)
        self.chat_box.verticalScrollBar().setValue(
            self.chat_box.verticalScrollBar().maximum()
        )

    def send_message(self):
        msg = self.input_line.text().strip()
        if msg and can_type:
            sio.emit('message', {'msg': msg})
            self.input_line.clear()

    def send_pm(self):
        target, ok = QtWidgets.QInputDialog.getText(self, "Private Message", "Recipient:")
        if ok and target:
            msg, ok2 = QtWidgets.QInputDialog.getText(self, "Private Message", "Message:")
            if ok2 and msg:
                sio.emit('message', {'type': 'pm', 'target': target, 'msg': msg})

    def send_file(self):
        target, ok = QtWidgets.QInputDialog.getText(self, "Send File", "Recipient:")
        if ok and target:
            filepath, _ = QFileDialog.getOpenFileName(self, "Select File")
            if filepath:
                with open(filepath, "rb") as f:
                    b64_data = base64.b64encode(f.read()).decode()
                filename = os.path.basename(filepath)
                sio.emit('message', {
                    'type': 'file',
                    'target': target,
                    'filename': filename,
                    'b64': b64_data
                })

    def show_users(self):
        users = ", ".join(connected_users) if connected_users else "No users yet"
        QMessageBox.information(self, "Known Users", users)

# ===== SocketIO Events =====
@sio.event
def connect():
    main_window.new_message_signal.emit("[System] Connected to server")
    sio.emit('authenticate', {'username': USERNAME, 'password': PASSWORD})

@sio.event
def disconnect():
    main_window.new_message_signal.emit("[System] Disconnected from server")

@sio.on('authenticated')
def on_authenticated(data):
    main_window.new_message_signal.emit(f"[System] Authenticated as {data['username']}")

@sio.on('message')
def on_message(data):
    msg = data.get('msg')
    if msg:
        main_window.new_message_signal.emit(msg)
        if msg.startswith("[PM from "):
            sender = msg.split("]")[0][9:]
            connected_users.add(sender)

@sio.on('file')
def on_file(data):
    sender = data.get('from')
    filename = f"[from_{sender}]_{data.get('filename')}"
    file_bytes = base64.b64decode(data.get('b64'))
    with open(filename, "wb") as f:
        f.write(file_bytes)
    main_window.new_message_signal.emit(
        f"[System] Received file '{filename}' from {sender}"
    )
    connected_users.add(sender)

@sio.on('connect_error')
def on_connect_error(data):
    print(f"[ERROR] Connection failed: {data}")
    main_window.new_message_signal.emit(f"[ERROR] Connection failed: {data}")

@sio.on('error')
def on_error(err):
    print(f"[ERROR] {err}")
    main_window.new_message_signal.emit(f"[ERROR] {err}")

# ===== API Helpers =====
def api_register(username, password):
    try:
        r = requests.post(f"{SERVER_HTTP}api/register",
                          data={"username": username, "password": password})
        if r.status_code != 200:
            print(f"[ERROR] Register failed: {r.status_code} {r.text}")
        return r.status_code == 200
    except Exception as e:
        print(f"[ERROR] Register exception: {e}")
        return False

def api_login(username, password):
    try:
        r = requests.post(f"{SERVER_HTTP}api/login",
                          data={"username": username, "password": password})
        if r.status_code != 200:
            print(f"[ERROR] Login failed: {r.status_code} {r.text}")
        return r.status_code == 200
    except Exception as e:
        print(f"[ERROR] Login exception: {e}")
        return False

# ===== Login / Signup Dialog =====
def login_signup_dialog():
    dialog = QtWidgets.QDialog()
    dialog.setWindowTitle("Login or Signup - TBag inc Chat Network")
    layout = QtWidgets.QVBoxLayout()
    label = QtWidgets.QLabel("Choose an option:")
    layout.addWidget(label)
    login_btn = QtWidgets.QPushButton("Login")
    signup_btn = QtWidgets.QPushButton("Signup")
    layout.addWidget(login_btn)
    layout.addWidget(signup_btn)
    dialog.setLayout(layout)

    result = {"mode": None}
    login_btn.clicked.connect(lambda: (result.update({"mode": "login"}), dialog.accept()))
    signup_btn.clicked.connect(lambda: (result.update({"mode": "signup"}), dialog.accept()))

    dialog.exec()
    return result.get("mode")

# ===== Main =====
app = QtWidgets.QApplication(sys.argv)

mode = login_signup_dialog()
if not mode:
    sys.exit()

username, ok1 = QtWidgets.QInputDialog.getText(None, mode.capitalize(), "Username:")
if not ok1:
    sys.exit()
password, ok2 = QtWidgets.QInputDialog.getText(
    None, mode.capitalize(), "Password:", QtWidgets.QLineEdit.EchoMode.Password
)
if not ok2:
    sys.exit()

USERNAME = username
PASSWORD = password

# Attempt login or register
try:
    if mode == "login":
        if not api_login(USERNAME, PASSWORD):
            raise Exception("Login failed, see console for details")
    else:
        if not api_register(USERNAME, PASSWORD):
            raise Exception("Signup failed, see console for details")
except Exception as e:
    print(f"[ERROR] {e}")
    QMessageBox.critical(None, "Error", str(e))
    sys.exit()

# Launch main window
main_window = ChatClient()
main_window.show()

# Connect SocketIO with correct path
try:
    sio.connect(
        SERVER_WS,
        socketio_path="/Chat/socket.io",     # <-- fix here
        transports=["websocket", "polling"]
    )
except Exception as e:
    print(f"[ERROR] Could not connect to server: {e}")
    QMessageBox.critical(None, "Error", f"Could not connect to server:\n{e}")
    sys.exit()

sys.exit(app.exec())
