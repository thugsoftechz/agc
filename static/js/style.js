document.addEventListener("DOMContentLoaded", function() {
  var socket = io();

  function sendMessage() {
    var input = document.getElementById('messageInput');
    var msg = input.value;
    if (msg.trim() !== "") {
      socket.send(msg);
      input.value = "";
    }
  }

  socket.on('message', function(msg) {
    var chat = document.getElementById('chat');
    var p = document.createElement('p');
    p.textContent = msg;
    chat.appendChild(p);
    chat.scrollTop = chat.scrollHeight;
  });

  document.getElementById('sendButton').addEventListener('click', sendMessage);
  document.getElementById('messageInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      sendMessage();
    }
  });
});