Below is the complete content for your **README.md** file. You can copy and paste it into your repository:

```markdown
# agc - Secure CLI Chat Application (Anonymous Group Chat)

## Overview

**agc** (Anonymous Group Chat) is a lightweight, cross-platform command-line chat application that empowers you to communicate securely. It supports encrypted peer-to-peer messaging and file transfers using **Fernet symmetric encryption**, ensuring your conversations remain private.

## Features

- **End-to-End Encryption:** Secure your messages with Python's `cryptography` module.
- **Peer-to-Peer Connectivity:** Establish direct socket connections for real-time chat.
- **Encrypted File Transfer:** Safely send and receive files with encryption.
- **Persistent Settings:** Save your chat history preferences and configuration.
- **Command-Based Interface:** Simple, intuitive commands for a streamlined experience.

## Installation

### Prerequisites

- Python 3.x installed
- `pip` package manager available

### Installation Steps

1. **Clone the Repository:**
   ```sh
   git clone https://github.com/thugsoftechz/agc.git
   cd agc
   ```
2. **Install Dependencies:**
   ```sh
   pip install .
   ```

## Usage

### Running as Host (Server Mode)

To host a chat session, run:

```sh
python agc.py
```

Select option `1` when prompted to start a session. Share your IP address, port number, and session password with your peer.

### Connecting as Client

To join an existing session, run:

```sh
python agc.py
```

Select option `2`, then enter the host's IP address and port number.

### Chat Commands

| Command              | Description                   |
|----------------------|-------------------------------|
| `/file path/to/file` | Securely send a file          |
| `/delchat`           | Delete chat history           |
| `/exit`              | Quit the chat session         |

## Security & Authentication

- **Authentication:** A password-based verification ensures that only authorized peers connect.
- **Encryption:** All messages and files are encrypted using **Fernet encryption**.
- **Dynamic Session Keys:** Every chat session generates a unique encryption key for enhanced security.

## Contributing

Contributions are welcome! Feel free to **fork** the repository, **submit issues**, or open **pull requests**. Your ideas and improvements will help make agc even better.

Enjoy using **agc** for secure, streamlined command-line communication!
```

This README provides an overview of the project, its features, installation instructions, usage guidelines, and contribution details. Let me know if you need any further modifications or additional sections!
