from setuptools import setup

setup(
    name="agc",
    version="0.2.0",
    author="Priyanshu",
    description="A secure, cross-platform CLI chat application with encryption support",
    py_modules=["agc"],
    install_requires=["cryptography"],
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
