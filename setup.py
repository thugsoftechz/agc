from setuptools import setup

setup(
    name="agc",
    version="0.5.0",  # Major update: Video/Audio Call & Web Features
    author="Priyanshu",
    description=(
        "A secure, user-friendly chat application with CLI, GUI, and Web interfaces. "
        "Features E2E encryption, file transfer, voice calls, and video calls."
    ),
    packages=["agc_lib"],
    py_modules=["agc"],
    install_requires=[
        "cryptography",
        "pyperclip",
        "miniupnpc",
    ],
    extras_require={
        "voice": ["pyaudio"],
        "video": ["opencv-python", "imutils", "numpy"],
        "web": ["flask", "flask-socketio", "eventlet"],
        "all": ["pyaudio", "flask", "flask-socketio", "eventlet", "opencv-python", "imutils", "numpy"],
    },
    entry_points={
        "console_scripts": [
            "agc=agc:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
