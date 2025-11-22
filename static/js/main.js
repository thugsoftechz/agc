document.addEventListener("DOMContentLoaded", function() {
    var socket = io();
    var username = "";

    const loginModal = document.getElementById('login-modal');
    const appContainer = document.getElementById('app-container');
    const usernameInput = document.getElementById('username-input');
    const joinBtn = document.getElementById('join-btn');
    const chatBox = document.getElementById('chat-box');
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');

    // Join Chat
    joinBtn.addEventListener('click', function() {
        const name = usernameInput.value.trim();
        if (name) {
            username = name;
            loginModal.style.display = "none";
            appContainer.style.display = "flex";
            socket.emit('join', { username: username });
        }
    });

    usernameInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            joinBtn.click();
        }
    });

    // Send Message
    function sendMessage() {
        const text = messageInput.value.trim();
        if (text && username) {
            socket.emit('send_message', { username: username, text: text });
            messageInput.value = "";
        }
    }

    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    // Receive Message
    socket.on('message', function(data) {
        const msgDiv = document.createElement('div');
        msgDiv.classList.add('message');

        if (data.type === 'system') {
            msgDiv.classList.add('system');
            msgDiv.textContent = data.text;
        } else {
            if (data.user === username) {
                msgDiv.classList.add('sent');
            } else {
                msgDiv.classList.add('received');
                const nameSpan = document.createElement('span');
                nameSpan.classList.add('sender-name');
                nameSpan.textContent = data.user;
                msgDiv.appendChild(nameSpan);
            }

            const textSpan = document.createElement('span');
            textSpan.textContent = data.text;
            msgDiv.appendChild(textSpan);

            const metaSpan = document.createElement('span');
            metaSpan.classList.add('meta');
            metaSpan.textContent = data.time;
            msgDiv.appendChild(metaSpan);
        }

        chatBox.appendChild(msgDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
    });
});
