document.addEventListener("DOMContentLoaded", function() {
    var socket = io();
    var username = "";

    // WebRTC Variables
    let localStream;
    let peerConnection;
    const configuration = { 'iceServers': [{ 'urls': 'stun:stun.l.google.com:19302' }] };

    const loginModal = document.getElementById('login-modal');
    const appContainer = document.getElementById('app-container');
    const usernameInput = document.getElementById('username-input');
    const joinBtn = document.getElementById('join-btn');
    const chatBox = document.getElementById('chat-box');
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');

    // File Transfer Elements
    const fileInput = document.getElementById('file-input');
    const fileBtn = document.getElementById('file-btn');

    // Video Call Elements
    const videoBtn = document.getElementById('video-btn');
    const videoArea = document.getElementById('video-area');
    const localVideo = document.getElementById('localVideo');
    const remoteVideo = document.getElementById('remoteVideo');
    const hangupBtn = document.getElementById('hangup-btn');

    // Typing Indicator
    let typingTimeout;
    const chatHeader = document.querySelector('.chat-header');
    const typingDiv = document.createElement('div');
    typingDiv.style.fontSize = '0.8rem';
    typingDiv.style.color = '#00a884';
    typingDiv.style.marginLeft = '10px';
    typingDiv.style.display = 'none';
    chatHeader.appendChild(typingDiv);

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
            socket.emit('stop_typing', { username: username });
        }
    }

    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        } else {
            socket.emit('typing', { username: username });
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(() => {
                socket.emit('stop_typing', { username: username });
            }, 1000);
        }
    });

    // Handle File Sending
    fileBtn.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', function() {
        const file = this.files[0];
        if (file && username) {
            const reader = new FileReader();
            reader.onload = function(evt) {
                const base64data = evt.target.result; // Data URL
                socket.emit('send_file', {
                    username: username,
                    fileName: file.name,
                    fileData: base64data
                });
            };
            reader.readAsDataURL(file);
        }
        this.value = ""; // reset
    });

    // Receive Message
    socket.on('message', function(data) {
        appendMessage(data);
    });

    // Receive Fingerprint
    socket.on('security_fingerprint', function(data) {
        const fingerprintSpan = document.createElement('div');
        fingerprintSpan.style.fontSize = '0.7rem';
        fingerprintSpan.style.color = '#8696a0';
        fingerprintSpan.style.textAlign = 'center';
        fingerprintSpan.style.marginTop = '10px';
        fingerprintSpan.textContent = `🔒 Secured (Fingerprint: ${data.fingerprint})`;
        chatBox.appendChild(fingerprintSpan);
    });

    // Typing Events
    socket.on('display_typing', function(data) {
        typingDiv.textContent = `${data.user} is typing...`;
        typingDiv.style.display = 'block';
    });

    socket.on('hide_typing', function(data) {
        typingDiv.style.display = 'none';
    });

    // Receive File
    socket.on('file_shared', function(data) {
        const msgDiv = document.createElement('div');
        msgDiv.classList.add('message');
        if (data.user === username) msgDiv.classList.add('sent');
        else {
            msgDiv.classList.add('received');
            const nameSpan = document.createElement('span');
            nameSpan.classList.add('sender-name');
            nameSpan.textContent = data.user;
            msgDiv.appendChild(nameSpan);
        }

        const link = document.createElement('a');
        link.href = data.fileData;
        link.download = data.fileName;
        link.textContent = "📎 " + data.fileName;
        link.classList.add('file-link');
        msgDiv.appendChild(link);

        const metaSpan = document.createElement('span');
        metaSpan.classList.add('meta');
        metaSpan.textContent = data.time;
        msgDiv.appendChild(metaSpan);

        chatBox.appendChild(msgDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
    });

    function appendMessage(data) {
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

            // Add ticks if it's a sent message
            let tickHtml = "";
            if (data.user === username) {
                tickHtml = `<span class="tick">✓✓</span>`; // Double tick simulation
            }

            metaSpan.innerHTML = `${data.time} ${tickHtml}`;
            msgDiv.appendChild(metaSpan);
        }

        chatBox.appendChild(msgDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    // --- WebRTC Video Call Logic ---

    videoBtn.addEventListener('click', async () => {
        videoArea.style.display = "flex";
        try {
            localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
            localVideo.srcObject = localStream;
            startCall();
        } catch (e) {
            alert("Could not access camera/microphone.");
            console.error(e);
        }
    });

    hangupBtn.addEventListener('click', () => {
        closeCall();
        socket.emit('call_signal', { type: 'hangup' });
    });

    function closeCall() {
        if (peerConnection) {
            peerConnection.close();
            peerConnection = null;
        }
        if (localStream) {
            localStream.getTracks().forEach(track => track.stop());
        }
        videoArea.style.display = "none";
    }

    async function startCall() {
        peerConnection = new RTCPeerConnection(configuration);

        // Add local tracks
        localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));

        // Handle remote tracks
        peerConnection.ontrack = event => {
            remoteVideo.srcObject = event.streams[0];
        };

        // Handle ICE candidates
        peerConnection.onicecandidate = event => {
            if (event.candidate) {
                socket.emit('call_signal', { type: 'candidate', candidate: event.candidate });
            }
        };

        // Create Offer
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);
        socket.emit('call_signal', { type: 'offer', offer: offer });
    }

    async function handleOffer(offer) {
        videoArea.style.display = "flex";
        if (!localStream) {
             localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
             localVideo.srcObject = localStream;
        }

        peerConnection = new RTCPeerConnection(configuration);

        localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));

        peerConnection.ontrack = event => {
            remoteVideo.srcObject = event.streams[0];
        };

        peerConnection.onicecandidate = event => {
            if (event.candidate) {
                socket.emit('call_signal', { type: 'candidate', candidate: event.candidate });
            }
        };

        await peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);
        socket.emit('call_signal', { type: 'answer', answer: answer });
    }

    async function handleAnswer(answer) {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
    }

    async function handleCandidate(candidate) {
        if (peerConnection) {
            await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
        }
    }

    socket.on('call_signal', async (data) => {
        if (data.type === 'offer') {
            await handleOffer(data.offer);
        } else if (data.type === 'answer') {
            await handleAnswer(data.answer);
        } else if (data.type === 'candidate') {
            await handleCandidate(data.candidate);
        } else if (data.type === 'hangup') {
            closeCall();
        }
    });

});
