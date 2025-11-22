import os
import sys
import platform
import subprocess

def check_pyinstaller():
    try:
        import PyInstaller
        return True
    except ImportError:
        return False

def build():
    if not check_pyinstaller():
        print("[ERROR] PyInstaller not found. Installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            import PyInstaller.__main__ # Verify import
        except Exception as e:
            print(f"[ERROR] Failed to install PyInstaller: {e}")
            return

    import PyInstaller.__main__

    system = platform.system()
    print(f"[INFO] Detected system: {system}")

    # Core options
    options = [
        'agc.py',
        '--onefile',
        '--name=AGC',
        '--clean',
        # Include Web Assets
        '--add-data=templates:templates',
        '--add-data=static:static',
        # Ensure agc_lib is traversed
        '--hidden-import=agc_lib',
        '--hidden-import=agc_lib.security',
        '--hidden-import=agc_lib.networking',
        '--hidden-import=agc_lib.media',
        '--hidden-import=agc_lib.ui',
        '--hidden-import=agc_lib.utils',
    ]

    # OS Specifics
    if system == "Windows":
        # If we had an icon: options.append('--icon=icon.ico')
        pass
    elif system == "Darwin":
        options.append('--windowed') # .app bundle preferred on Mac

    # Hidden imports for heavy libs (often missed by PI)
    dynamic_libs = [
        'engineio.async_drivers.eventlet',
        'flask_socketio',
        'pyaudio',
        'cv2',
        'numpy',
        'cryptography'
    ]
    for lib in dynamic_libs:
        options.append(f'--hidden-import={lib}')

    print(f"[INFO] Building AGC with options: {options}")

    try:
        PyInstaller.__main__.run(options)
        print("\n" + "="*40)
        print("[SUCCESS] Build Complete!")
        print(f"Executable location: {os.path.abspath('dist')}")
        print("="*40 + "\n")
    except Exception as e:
        print(f"[ERROR] Build Failed: {e}")

if __name__ == "__main__":
    build()
