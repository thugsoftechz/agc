

---

# **AGC - 

AGC is a **secure, multi-user chat system** offering **CLI, GUI, and Web interfaces**. Designed for **real-time conversations**, AGC supports **persistent chat history**, **file transfers**, and **voice calling**.

## **Features**
- 🔒 **Secure Chat** – Messages are encrypted using **Fernet** for privacy.
- 🔄 **Unified Login** – Enter a **chat nickname** and a **shared session password** to join.
- 💾 **Persistent Chat History** – Chats are stored and loaded in GUI & Web modes.
- 📎 **File Transfers** – Share files securely during conversations.
- 🔊 **Voice Call Support** – High-quality **real-time audio communication** via PyAudio.
- 🌎 **Web Chat Interface** – Browser-based **Flask-SocketIO chat** with login, history, and a "+" button to add details.
- 🖥️ **GUI Mode** – A **Tkinter-powered chat window** for intuitive interactions.
- ⚙️ **NAT Assistance** – Detects **public IP** and configures **UPnP port mapping**.
- ⚡ **Fast & Lightweight** – Simple and efficient, built for seamless group chats.

---

## **Installation**
First, install **AGC** via pip:

```bash
pip install agc
```

### **Optional Extras**
To enable additional features:
- **Voice Call Support:**  
  ```bash
  pip install agc[voice]```
- **Web Chat Interface:**  
  ```bash
  pip install agc[web]```
- **Full Installation (Voice & Web):**  
  ```bash
  pip install agc[full]```

---

## **Usage**

### **CLI Mode**
Run AGC and choose an option:

```bash
agc
```

You can:
1️⃣ **Host a chat session**  
2️⃣ **Join a chat session**  
3️⃣ **Start a voice call**  
4️⃣ **Reconnect to the last session**  

### **Web Mode**
Run the Web interface:

```bash
python app.py
```

Then open **[http://localhost:5000](http://localhost:5000)** in your browser.  
Log in with your **chat nickname** and **session password** to access the chat.  
Previous chat history is loaded automatically.

### **GUI Mode**
Run **AGC GUI** with persistent chat history:

```bash
agc --gui
```

Enjoy a **friendly, interactive chat window** with a **plus ("+") button** to add details.

### **Voice Call**
Start or join a voice call:

```bash
agc --voice
```

You'll connect to a **real-time audio chat** with other participants.

---

## **Updating AGC**
If installed from Git, update with:

```bash
agc update
```

---

## **System Requirements**
AGC runs on:
- **Windows, Linux, macOS** ✅
- Python **3.8+**
- Recommended dependencies: `cryptography`, `pyperclip`, `miniupnpc`, `pyaudio`, `flask`, `flask-socketio`

---

## **Contributing**
Want to improve AGC?  
Fork the repo and send a pull request! 🚀  
For major changes, open an issue to discuss.
<!-- GitAds-Verify: WQWAW8CCB8LY4ZV45DPQ5S8UVJ2RFZ5I -->

---

### **Final Notes**
- **Simplified Login** – Use **chat nickname** and **session password** for **seamless connections**.
- **Persistent History** – Chat logs load automatically in **Web & GUI interfaces**.
- **Integrated Features** – **Text, voice, file sharing** built into **one platform**.

## GitAds Sponsored
[![Sponsored by GitAds](https://gitads.dev/v1/ad-serve?source=thugsoftechz/agc@github)](https://gitads.dev/v1/ad-track?source=thugsoftechz/agc@github)

