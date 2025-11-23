import socket, threading, os
from flask import Flask, request, render_template_string
import qrcode, psutil, ctypes
from ctypes import POINTER, cast
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
import mss

authorized_token = None

def authorize(token):
    global authorized_token
    authorized_token = token
    print(f"[ACCESS] Device '{token}' authorized.")
    return f"Device '{token}' authorized."

def revoke():
    global authorized_token
    authorized_token = None
    print("[ACCESS] Access revoked.")
    return "Access revoked."

def check_access(token):
    return token == authorized_token

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def generate_qr(token):
    ip = get_local_ip()
    url = f"http://{ip}:5000/control?token={token}"
    qr = qrcode.make(url)
    qr.show()
    print(f"[QR] Scan this to open control panel: {url}")

def execute_command(token, command):
    if command == "authorize":
        return authorize(token)
    elif command == "revoke":
        return revoke()
    elif not check_access(token):
        return "Access denied."

    try:
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume = cast(interface, POINTER(IAudioEndpointVolume))
    except:
        volume = None

    if command == "volume up" and volume:
        current = volume.GetMasterVolumeLevelScalar()
        volume.SetMasterVolumeLevelScalar(min(current + 0.05, 1.0), None)
        return f"Volume increased to {int(min(current + 0.05, 1.0) * 100)}%"

    elif command == "volume down" and volume:
        current = volume.GetMasterVolumeLevelScalar()
        volume.SetMasterVolumeLevelScalar(max(current - 0.05, 0.0), None)
        return f"Volume decreased to {int(max(current - 0.05, 0.0) * 100)}%"

    elif command == "mute" and volume:
        volume.SetMute(1, None)
        return "Muted"

    elif command == "unmute" and volume:
        volume.SetMute(0, None)
        return "Unmuted"

    elif command == "shutdown":
        os.system("shutdown /s /t 1")
        return "Shutdown initiated."

    elif command == "restart":
        os.system("shutdown /r /t 1")
        return "Restarting..."

    elif command == "sleep":
        os.system("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
        return "Sleeping..."

    elif command == "lock":
        ctypes.windll.user32.LockWorkStation()
        return "Locked screen."

    elif command == "screenshot":
        try:
            with mss.mss() as sct:
                sct.shot(output="screenshot.png")
            return "Screenshot saved as screenshot.png"
        except Exception as e:
            return f"Screenshot error: {e}"

    elif command == "stats":
        stats = {
            "CPU": psutil.cpu_percent(),
            "RAM": psutil.virtual_memory().percent,
            "Battery": psutil.sensors_battery().percent if psutil.sensors_battery() else "N/A"
        }
        return f"Stats: {stats}"

    elif command.startswith("popup "):
        msg = command[6:]
        ctypes.windll.user32.MessageBoxW(0, msg, "Remote Prompt", 1)
        return f"Popup shown: {msg}"

    elif command == "wifi off":
        os.system("netsh interface set interface name=\"Wi-Fi\" admin=disable")
        return "Wi-Fi turned off."

    elif command == "wifi on":
        os.system("netsh interface set interface name=\"Wi-Fi\" admin=enable")
        return "Wi-Fi turned on."

    elif command == "bluetooth off":
        os.system("powershell -Command \"Disable-NetAdapter -Name 'Bluetooth' -Confirm:$false\"")
        return "Bluetooth turned off."

    elif command == "bluetooth on":
        os.system("powershell -Command \"Enable-NetAdapter -Name 'Bluetooth' -Confirm:$false\"")
        return "Bluetooth turned on."

    return "Unknown command."

def start_socket_server():
    HOST = '0.0.0.0'
    PORT = 9999
    BUFFER_SIZE = 1024
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SOCKET] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(BUFFER_SIZE).decode()
                if not data:
                    continue
                response = execute_command(*data.strip().split("::", 1))
                conn.sendall(response.encode())

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>Remote Control</title>
  <style>
    body { font-family: sans-serif; text-align: center; padding: 20px; }
    h2 { font-size: 28px; margin-bottom: 20px; }
    button {
      font-size: 28px;
      padding: 20px 40px;
      margin: 10px;
      border-radius: 12px;
      border: none;
      background-color: #0078D7;
      color: white;
      cursor: pointer;
    }
    button:hover {
      background-color: #005bb5;
    }
    input[type=text] {
      font-size: 20px;
      padding: 10px;
      width: 60%;
      margin-top: 10px;
    }
  </style>
</head>
<body>
<h2>📱 Remote Control Panel</h2>
<form method="get" action="/send">
  <input type="hidden" name="token" value="{{ token }}">
  <button name="cmd" value="volume up"> Volume Up</button>
  <button name="cmd" value="volume down"> Volume Down</button>
  <button name="cmd" value="mute"> Mute</button>
  <button name="cmd" value="unmute"> Unmute</button>
  <button name="cmd" value="shutdown"> Shutdown</button>
  <button name="cmd" value="restart"> Restart</button>
  <button name="cmd" value="sleep"> Sleep</button>
  <button name="cmd" value="lock"> Lock Screen</button>
  <button name="cmd" value="screenshot"> Screenshot</button>
  <button name="cmd" value="stats"> System Stats</button>
  <button name="cmd" value="wifi off"> Wi-Fi Off</button>
  <button name="cmd" value="wifi on"> Wi-Fi On</button>
  <button name="cmd" value="bluetooth off"> Bluetooth Off</button>
  <button name="cmd" value="bluetooth on"> Bluetooth On</button>
  <br><br>
  <input type="text" name="cmd" placeholder="popup Your message here">
  <button type="submit"> Send Popup</button>
</form>
</body>
</html>
"""

@app.route("/control")
def control_panel():
    token = request.args.get("token")
    if not token:
        return "Missing token", 400
    authorize(token)
    return render_template_string(HTML_TEMPLATE, token=token)

@app.route("/send")
def send_command():
    token = request.args.get("token")
    cmd = request.args.get("cmd")
    if not token or not cmd:
        return "Missing token or command", 400
    response = execute_command(token, cmd)
    return f"<pre>{response}</pre><br><a href='/control?token={token}'>Back</a>"

def start_flask():
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    token = "mark123"
    threading.Thread(target=start_flask, daemon=True).start()
    generate_qr(token)

    start_socket_server()


