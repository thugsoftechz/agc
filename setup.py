from setuptools import setup

setup(
    name="agc",
    version="0.5.0",  # Updated version reflecting added features
    author="Priyanshu",
    description=(
        "A secure, user-friendly CLI chat application with clipboard integration "
        "and NAT assistance, with optional voice call, video call and web interface features."
    ),
    py_modules=["agc"],
    install_requires=[
        "cryptography",
        "pyperclip",
        "miniupnpc",
        "opencv-python",
    ],
    extras_require={
        "voice": ["pyaudio"],
        "web": ["flask", "flask-socketio"],
        "all": ["pyaudio", "flask", "flask-socketio", "opencv-python"],
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
