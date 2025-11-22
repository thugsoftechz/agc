from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'agc_secret_key_change_this'
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('join')
def handle_join(data):
    username = data.get('username')
    if username:
        timestamp = datetime.datetime.now().strftime('%H:%M')
        emit('message', {'user': 'System', 'text': f'{username} has joined the chat.', 'time': timestamp, 'type': 'system'}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    username = data.get('username')
    text = data.get('text')
    if username and text:
        timestamp = datetime.datetime.now().strftime('%H:%M')
        emit('message', {'user': username, 'text': text, 'time': timestamp, 'type': 'user'}, broadcast=True)

@socketio.on('send_file')
def handle_file(data):
    username = data.get('username')
    file_name = data.get('fileName')
    file_data = data.get('fileData') # Base64 string
    if username and file_name and file_data:
        timestamp = datetime.datetime.now().strftime('%H:%M')
        emit('file_shared', {'user': username, 'fileName': file_name, 'fileData': file_data, 'time': timestamp}, broadcast=True)

# --- WebRTC Signaling ---
@socketio.on('call_signal')
def handle_call_signal(data):
    # Broadcast signaling data (offer/answer/ice candidates) to all other clients
    # In a real app, you'd target specific room/user. Here we broadcast to everyone else.
    emit('call_signal', data, broadcast=True, include_self=False)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
