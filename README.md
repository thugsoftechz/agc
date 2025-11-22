
---

# **AGC (Advanced Secure Chat)**

AGC is a **secure, multi-functional chat ecosystem** designed for privacy and versatility. Whether you prefer a command-line interface, a graphical desktop app, or a web browser experience, AGC has you covered with end-to-end encryption, file sharing, and voice calling capabilities.

## **Key Features**

*   🔒 **End-to-End Encryption** – All console and GUI chats are encrypted using **Fernet (AES-128)** symmetric encryption.
*   🔄 **Multi-Platform Access** – Use **CLI**, **GUI (Tkinter)**, or **Web (Flask)** interfaces.
*   📎 **File Sharing** – Securely transfer files between peers directly within the chat.
*   🔊 **Voice Calls** – Real-time, low-latency voice communication using `pyaudio`.
*   🌍 **NAT Traversal** – Automatic UPnP support to help you host chats without manual router configuration.
*   🕸️ **Modern Web UI** – A sleek, dark-themed web interface for local network chatting.
*   💾 **Chat History** – Option to save and review your conversation logs.

---

## **Installation**

Ensure you have **Python 3.8+** installed.

### **1. Install via Pip**
```bash
pip install agc
```

### **2. Install from Source (Recommended for latest features)**
```bash
git clone https://github.com/thugsoftechz/agc.git
cd agc
pip install -r requirements.txt  # or install manually below
```

### **Dependencies**
Install the specific feature sets you need:

*   **Core (CLI/GUI Secure Chat):**
    ```bash
    pip install cryptography pyperclip miniupnpc
    ```
*   **Voice Features:**
    ```bash
    pip install pyaudio
    ```
*   **Web Interface:**
    ```bash
    pip install flask flask-socketio eventlet
    ```
*   **All Features:**
    ```bash
    pip install cryptography pyperclip miniupnpc pyaudio flask flask-socketio eventlet
    ```

> **Note:** Linux users may need to install system audio libraries for PyAudio (e.g., `sudo apt install portaudio19-dev`).

---

## **Usage Guide**

You can run AGC in interactive mode or use command-line flags for quick access.

### **Interactive Mode**
Simply run the command:
```bash
python agc.py
```
You will be presented with a menu to choose your desired mode.

---

### **1. Secure Chat (CLI & GUI)**
Establish a direct, encrypted connection with a peer. One user acts as the **Host**, and the other as the **Client**.

#### **Hosting a Session**
1.  Run `python agc.py --host` (Console) or `python agc.py --gui-host` (GUI).
2.  Set a **Session Password**.
3.  AGC will display your **WAN IP** (Public) and **LAN IP** (Local).
4.  Share your IP, Port, and Password with your peer securely.

#### **Joining a Session**
1.  Run `python agc.py --join` (Console) or `python agc.py --gui-join` (GUI).
2.  Enter the **Host's IP Address** and **Port**.
3.  Enter the **Session Password**.
4.  Once authenticated, the secure session begins!

**In-Chat Commands:**
*   `/file <filepath>` – Send a file securely.
*   `/delchat` – Clear local chat history.
*   `/exit` – Disconnect.

---

### **2. Voice Calling**
A standalone encrypted voice channel for crystal-clear audio.

*   **Host:** `python agc.py --voice-host`
    *   Binds to port 6000 (default). Share your IP with the caller.
*   **Join:** `python agc.py --voice-join`
    *   Enter the Host's IP and Port to connect.

---

### **3. Web Interface**
A modern, browser-based chat for local networks (LAN). Great for quick group chats.

*   **Start Server:**
    ```bash
    python agc.py --web
    ```
*   **Access:**
    Open your browser and navigate to `http://localhost:5000` (or your LAN IP:5000).
*   **Features:**
    *   Dark Mode UI.
    *   Real-time messaging.
    *   Nickname support.

---

## **Advanced Usage & Flags**

| Flag | Description |
| :--- | :--- |
| `--host` | Start Host in Console Mode |
| `--join` | Start Client in Console Mode |
| `--gui-host` | Start Host in GUI Mode |
| `--gui-join` | Start Client in GUI Mode |
| `--voice-host` | Start Voice Call Host |
| `--voice-join` | Join Voice Call |
| `--web` | Launch Web Interface |
| `--update` | Pull latest changes from Git |
| `--help` | Show all available commands |

---

## **Troubleshooting**

### **Connection Refused / Timeout**
*   **Firewall:** Ensure your firewall allows traffic on the chosen port (default 5000).
*   **NAT/Port Forwarding:** If connecting over the internet, ensure UPnP succeeded or manually forward port 5000 on your router.
*   **IP Address:** Double-check you are using the correct Public IP (WAN) for internet connections or Local IP (LAN) for same-network connections.

### **Voice Call Issues**
*   **PyAudio Error:** Ensure `portaudio` is installed on your system.
*   **No Sound:** Check your system's default microphone and speaker settings.

### **Web Interface Not Loading**
*   Ensure `flask` and `flask-socketio` are installed.
*   If accessing from another device, use the host's LAN IP (e.g., `192.168.1.x:5000`), not `localhost`.

---

## **Contributing**
We welcome contributions!
1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature-name`).
3.  Commit your changes.
4.  Push to the branch and open a Pull Request.

---

### **License**
This project is open-source and available for educational and personal use.

---
*Created by [ThugsOfTechz](https://github.com/thugsoftechz)*
