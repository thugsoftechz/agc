import os
import sys
import platform
import shutil
import subprocess

APP_NAME = "AGC"
EXECUTABLE_NAME = "AGC" if platform.system() != "Windows" else "AGC.exe"
DIST_PATH = os.path.join(os.getcwd(), "dist", EXECUTABLE_NAME)

def create_linux_desktop_entry():
    print("[INFO] Creating Linux .desktop entry...")
    desktop_entry = f"""[Desktop Entry]
Name={APP_NAME}
Comment=Advanced Secure Chat
Exec={DIST_PATH}
Icon=utilities-terminal
Terminal=true
Type=Application
Categories=Network;
"""

    desktop_path = os.path.expanduser(f"~/.local/share/applications/{APP_NAME.lower()}.desktop")
    os.makedirs(os.path.dirname(desktop_path), exist_ok=True)

    with open(desktop_path, "w") as f:
        f.write(desktop_entry)

    # Make it executable
    os.chmod(desktop_path, 0o755)
    print(f"[SUCCESS] Installed to {desktop_path}")

def create_windows_shortcut():
    print("[INFO] Creating Windows Shortcut...")
    try:
        # Use PowerShell to create shortcut to avoid external dependencies like winshell
        desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
        start_menu = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs')

        targets = [desktop, start_menu]

        for target_dir in targets:
            link_path = os.path.join(target_dir, f"{APP_NAME}.lnk")

            ps_script = f"""
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("{link_path}")
            $Shortcut.TargetPath = "{DIST_PATH}"
            $Shortcut.Description = "Advanced Secure Chat"
            $Shortcut.Save()
            """

            subprocess.run(["powershell", "-Command", ps_script], check=True)
            print(f"[SUCCESS] Shortcut created at {link_path}")

    except Exception as e:
        print(f"[ERROR] Failed to create Windows shortcut: {e}")

def create_mac_app_bundle():
    print("[INFO] Creating macOS .app bundle...")
    # This is a basic wrapper. PyInstaller can do this automatically with --windowed,
    # but if we just have the binary:
    app_path = os.path.join(os.getcwd(), "dist", f"{APP_NAME}.app")
    contents_path = os.path.join(app_path, "Contents")
    macos_path = os.path.join(contents_path, "MacOS")

    if os.path.exists(app_path):
        shutil.rmtree(app_path)

    os.makedirs(macos_path)

    # Copy binary
    dest_binary = os.path.join(macos_path, EXECUTABLE_NAME)
    shutil.copy(DIST_PATH, dest_binary)
    os.chmod(dest_binary, 0o755)

    # Info.plist
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>{EXECUTABLE_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>com.thugsoftechz.agc</string>
    <key>CFBundleName</key>
    <string>{APP_NAME}</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
"""
    with open(os.path.join(contents_path, "Info.plist"), "w") as f:
        f.write(plist)

    print(f"[SUCCESS] .app bundle created at {app_path}")
    print("To install, drag this folder to your Applications folder.")

def install():
    if not os.path.exists(DIST_PATH):
        print(f"[ERROR] Executable not found at {DIST_PATH}. Run build_app.py first.")
        return

    system = platform.system()
    if system == "Linux":
        create_linux_desktop_entry()
    elif system == "Windows":
        create_windows_shortcut()
    elif system == "Darwin":
        create_mac_app_bundle()
    else:
        print(f"[WARN] Unsupported system for auto-install: {system}")

if __name__ == "__main__":
    install()
