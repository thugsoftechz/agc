from setuptools import setup, find_packages

setup(
    name="agc",
    version="0.6.0",
    author="Priyanshu",
    description="Advanced Secure Chat with CLI, GUI, Web, Voice, and Video support.",
    packages=find_packages(),
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
        "full": [
            "pyaudio", "flask", "flask-socketio", "eventlet",
            "opencv-python", "imutils", "numpy"
        ],
    },
    entry_points={
        "console_scripts": [
            "agc=agc:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",
    ],
    python_requires='>=3.7',
)
