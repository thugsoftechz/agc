import os
import sys
import subprocess
import shutil
import time

def check_buildozer():
    """Check if buildozer is installed."""
    try:
        subprocess.run(["buildozer", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_instructions():
    """Print instructions for installing Buildozer."""
    print("\n[ERROR] Buildozer is not installed or not in PATH.")
    print("To build the APK, you need 'buildozer'.")
    print("\n=== Installation Instructions ===")
    print("1. Ensure you are on Linux (Ubuntu recommended) or macOS.")
    print("   (Windows is supported via WSL2 only)")
    print("2. Install system dependencies:")
    print("   sudo apt update")
    print("   sudo apt install -y git zip unzip openjdk-17-jdk python3-pip autoconf libtool pkg-config zlib1g-dev libncurses5-dev libncursesw5-dev libtinfo5 cmake libffi-dev libssl-dev")
    print("3. Install Buildozer:")
    print("   pip3 install --user --upgrade buildozer")
    print("   export PATH=$PATH:~/.local/bin")
    print("\n=== Running the Build ===")
    print("Once installed, run this script again: python3 build_apk.py")
    print("Or run manually: buildozer android debug")

def build_apk():
    """Run the buildozer command."""
    print("="*40)
    print("      AGC APK Builder Wrapper")
    print("="*40)

    if not check_buildozer():
        install_instructions()
        return

    print("[INFO] Buildozer detected.")
    print("[INFO] Checking buildozer.spec...")
    if not os.path.exists("buildozer.spec"):
        print("[ERROR] buildozer.spec not found! Please download the full repo.")
        return

    print("[INFO] Starting Build Process... This may take a long time (15+ mins) on first run.")
    print("[INFO] Downloading Android SDK/NDK and compiling Python for Android...")

    try:
        # Run buildozer
        # we use pexpect logic via subprocess if we wanted interaction, but simple run is usually enough
        cmd = ["buildozer", "android", "debug"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Stream output
        for line in process.stdout:
            print(line, end="")

        process.wait()

        if process.returncode == 0:
            print("\n[SUCCESS] APK Build Successful!")
            print("Check the 'bin/' directory for your .apk file.")
        else:
            print("\n[ERROR] Build Failed. Check the logs above.")

    except KeyboardInterrupt:
        print("\n[WARN] Build cancelled by user.")

if __name__ == "__main__":
    build_apk()
