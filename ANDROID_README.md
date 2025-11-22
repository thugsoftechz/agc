# Running AGC on Android

While AGC provides desktop executables for Windows, Mac, and Linux, running it on Android requires a slightly different approach. Because AGC uses Python, you can run the **exact same code** on your Android device using **Termux**.

Alternatively, you can use the **Web Interface** to connect to a host from any Android browser.

---

## **Method 1: The "Native" App Experience (Termux)**
This method runs the full AGC application (CLI mode) on your phone.

### **1. Install Termux**
Download **Termux** from F-Droid (recommended) or the Google Play Store.
*   [F-Droid Link](https://f-droid.org/en/packages/com.termux/)

### **2. Install Python & Dependencies**
Open Termux and run the following commands one by one:

```bash
pkg update && pkg upgrade
pkg install python git cmake libjpeg-turbo build-essential
```

### **3. Install AGC**
Clone the repository and install the requirements:

```bash
git clone https://github.com/thugsoftechz/agc.git
cd agc
pip install cryptography pyperclip miniupnpc flask flask-socketio eventlet
```

> *Note: `opencv-python` and `pyaudio` might be difficult to install on Android due to hardware access restrictions. For video/voice, we recommend Method 2.*

### **4. Run AGC**
Start the app just like on a PC:

```bash
python agc.py
```

You can now:
*   **Join a Secure Chat:** Connect to a host running on a PC.
*   **Host a Session:** Allow others to connect to your phone (requires being on the same Wi-Fi).

---

## **Method 2: The Web Interface (Recommended for Video/Voice)**
This method allows you to use AGC's modern UI, File Transfer, and Video Calls on Android without installing Python.

### **1. Host on PC**
On your Windows/Mac/Linux computer, run:

```bash
python agc.py --web
```

### **2. Connect from Android**
1.  Ensure your Android phone is on the **same Wi-Fi network** as your PC.
2.  Find your PC's **Local IP Address** (AGC displays this when starting, e.g., `192.168.1.X`).
3.  Open **Chrome** or **Firefox** on Android.
4.  Navigate to: `http://<YOUR_PC_IP>:5000`

### **3. Install as App (PWA)**
To make it look like a native app:
1.  Tap the browser menu (three dots).
2.  Select **"Add to Home Screen"** or **"Install App"**.
3.  An AGC icon will appear on your Android home screen. Launch it for a full-screen experience!

---
