import PyInstaller.__main__
import os
import sys
import platform

def build():
    system = platform.system()
    print(f"[INFO] Detected system: {system}")

    options = [
        'agc.py',
        '--onefile',
        '--name=AGC',
        '--clean',
        '--add-data=templates:templates',  # Include web templates
        '--add-data=static:static',        # Include web static files
    ]

    if system == "Windows":
        options.append('--icon=icon.ico') # Assuming an icon exists, otherwise ignore
    elif system == "Darwin": # macOS
        options.append('--windowed') # For GUI apps on Mac

    # Handling hidden imports for dynamic libraries
    hidden_imports = [
        'engineio.async_drivers.threading',
        'engineio.async_drivers.eventlet',
        'flask_socketio',
        'pyaudio',
        'cv2',
        'numpy',
        'cryptography',
        'pyperclip',
        'miniupnpc',
        'imutils',
        'flask'
    ]

    for hidden in hidden_imports:
        options.append(f'--hidden-import={hidden}')

    print(f"[INFO] Starting build with options: {options}")
    PyInstaller.__main__.run(options)
    print("[INFO] Build complete. check 'dist/' folder.")

if __name__ == "__main__":
    build()
