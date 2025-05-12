agc - Secure CLI Chat Application

## Overview
agc (Anonymous Group Chat) is a secure, cross-platform command-line chat application that supports encrypted peer-to-peer messaging and file transfer. It uses **Fernet symmetric encryption** to ensure secure communication.

## Features
- **End-to-end encryption** using the `cryptography` module.
- **Peer-to-peer connection** via socket programming.
- **File transfer** with encryption.
- **Persistent settings** including chat history preferences.
- **Command-based interaction** for intuitive usage.

## Installation
### Prerequisites:
- Python 3.x installed
- `pip` package manager available

### Steps:
1. Clone or download the repository:
   ```sh
   git clone https://github.com/yourusername/agc.git
   cd agc
   ```
2. Install the package and dependencies:
   ```sh
   pip install .
   ```

## Usage
### Running as Host (Server)
To host a chat session:
```sh
python agc.py
```
Select `1` to start a session. Share your IP and port with your peer.

### Connecting as Client
To join a hosted session:
```sh
python agc.py
```
Select `2` and enter the host's IP and port.

### Chat Commands
| Command         | Description                               |
|---------------|----------------------------------|
| `/file path/to/file`  | Send a file securely |
| `/delchat`   | Delete chat history |
| `/exit`    | Quit chat session |

## Security & Authentication
- A password-based authentication ensures peer verification.
- Messages and files are encrypted using **Fernet encryption**.
- Session keys are dynamically generated for each chat session.

## Contribution
Feel free to **fork**, **submit issues**, or create **pull requests** to improve the project.

---
