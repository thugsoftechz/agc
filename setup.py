from setuptools import setup

setup(
    name="agc",
    version="0.3.0",
    author="Priyanshu",
    description="A secure, user-friendly CLI chat application with clipboard integration and NAT assistance (via UPnP) for easy long-distance connection sharing.",
    py_modules=["agc"],
    install_requires=["cryptography", "pyperclip", "miniupnpc"],
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
