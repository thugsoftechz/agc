from setuptools import setup

setup(
    name="agc",
    version="0.1.0",
    author="Your Name",
    description="A secure, cross-platform command-line chat application",
    py_modules=["agc"],
    install_requires=[
        "cryptography"
    ],
    entry_points={
        "console_scripts": [
            "agc=agc:main",
        ],
    },
)
