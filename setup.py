from setuptools import setup

setup(
    name="agc",
    version="0.4.0",  # Updated version reflecting added features
    author="Priyanshu",
    description=(
        "A secure, user-friendly CLI chat application with clipboard integration "
        "and NAT assistance, with optional voice call and web interface features."
    ),
    py_modules=["agc"],
    install_requires=[
        "cryptography",
        "pyperclip",
        "miniupnpc",
    ],
    extras_require={
        "voice": ["pyaudio"],
        "web": ["flask", "flask-socketio"],
        "all": ["pyaudio", "flask", "flask-socketio"],
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