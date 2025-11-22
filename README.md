
---

# **AGC (Advanced Secure Chat)**

AGC is a **secure, multi-functional chat ecosystem** designed for privacy and versatility. Whether you prefer a command-line interface, a graphical desktop app, or a web browser experience, AGC has you covered with end-to-end encryption, file sharing, and high-quality video/voice calling.

## **Key Features**

*   🔒 **End-to-End Encryption** – Chats are secured using **Fernet (AES-128)** with **RSA Key Exchange**.
*   🔄 **Multi-Platform Access** – Windows, Linux, macOS, and Android support.
*   📎 **File Sharing** – Securely transfer files between peers directly within the chat.
*   🔊 **Voice Calls** – Real-time encrypted voice communication.
*   📹 **Video Calls** – Encrypted video calls via OpenCV (Desktop) or WebRTC (Web).
*   🌍 **NAT Traversal** – Automatic UPnP support for easy hosting.
*   🕸️ **Modern Web UI** – A sleek, dark-themed web interface (PWA ready).

---

## **Installation & Build**

### **Desktop (Windows, Linux, macOS)**

#### **1. Quick Install via Pip**
```bash
pip install -r requirements.txt
```

#### **2. Build Executable (Standalone)**
You can create a standalone executable (`.exe`, binary, or `.app`) that runs without Python installed.

1.  Clone the repo and install dependencies:
    ```bash
    git clone https://github.com/thugsoftechz/agc.git
    cd agc
    pip install -r requirements.txt
    pip install pyinstaller
    ```
2.  Run the build script:
    ```bash
    python build_app.py
    ```
3.  The executable will be in the `dist/` folder.

#### **3. Install Shortcuts (Start Menu/Desktop)**
To add AGC to your system's application menu/desktop:

```bash
python install.py
```

---

### **Android Support**

AGC supports Android in two ways: **Native Termux** (CLI) or **Native App** (APK).

#### **Option 1: Build the APK (Recommended)**
We include a tool to help you build a native Android APK using `buildozer`.

1.  **Requirements:** Linux (Ubuntu) or macOS. Windows users should use WSL2.
2.  **Run the Builder:**
    ```bash
    python3 build_apk.py
    ```
    This script will check your environment and run `buildozer` to compile the APK.
    *   *Note: This process can take 15-30 minutes on the first run as it downloads the Android SDK/NDK.*

3.  **Install:** Transfer the resulting `.apk` file (found in `bin/`) to your phone and install it.

#### **Option 2: Termux**
See **[ANDROID_README.md](ANDROID_README.md)** for instructions on running the Python code directly on your phone.

---

## **Usage Guide**

### **Interactive Mode**
Simply run the command (or double-click the executable):
```bash
python agc.py  # OR ./dist/AGC
```
You will be presented with a menu to choose your desired mode.

### **1. Secure Chat**
*   **Host:** Generates an RSA key pair and waits for a client.
*   **Client:** Connects, generates a session key, and encrypts it with the Host's public key.
*   **Result:** A secure AES-128 encrypted channel for text and files.

### **2. Encrypted Voice/Video Calls**
*   **Voice:** Runs on Port 6000. Audio chunks are encrypted with Fernet before transmission.
*   **Video:** Runs on Port 7000. Video frames are JPEG-encoded, encrypted, and sent over TCP.

### **3. Web Interface (LAN)**
*   Run `python agc.py --web`.
*   Open `http://localhost:5000` in your browser.
*   Supports **Video Calls (WebRTC)** and **File Sharing**.

---

## **Troubleshooting**

### **Connection Issues**
*   **Firewall:** Allow ports 5000 (Chat), 6000 (Voice), and 7000 (Video).
*   **NAT:** Use UPnP or manually forward ports if connecting over the internet.

### **Video/Audio Issues**
*   **Dependencies:** Ensure `opencv-python` and `pyaudio` are installed.
*   **Permissions:** Grant camera/microphone access to your terminal or browser.

---

### **License**
This project is open-source and available for educational and personal use.

---
*Created by [ThugsOfTechz](https://github.com/thugsoftechz)*
