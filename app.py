from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import datetime
import os
import agc  # Import core logic for fingerprinting if needed, though web usually generates its own session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'agc_secret_key_change_this'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state for this simple server
CONNECTED_USERS = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')

@app.route('/service-worker.js')
def service_worker():
    return app.send_static_file('service-worker.js')

@socketio.on('join')
def handle_join(data):
    username = data.get('username')
    if username:
        CONNECTED_USERS[request.sid] = username
        timestamp = datetime.datetime.now().strftime('%H:%M')
        # Broadcast join message
        emit('message', {'user': 'System', 'text': f'{username} has joined the chat.', 'time': timestamp, 'type': 'system'}, broadcast=True)

        # Simulate "Security Fingerprint" for the web session (Simulated for WebRTC context)
        # In a real E2E web app, this would be derived from the WebRTC DTLS fingerprint or a client-side key.
        # Here we generate a per-session code for UI demonstration of the "Security" feature.
        import hashlib
        fingerprint = hashlib.sha256(app.config['SECRET_KEY'].encode() + username.encode()).hexdigest()[:16].upper()
        emit('security_fingerprint', {'fingerprint': fingerprint}, to=request.sid)

@socketio.on('send_message')
def handle_message(data):
    username = data.get('username')
    text = data.get('text')
    if username and text:
        timestamp = datetime.datetime.now().strftime('%H:%M')
        # Add status: 'sent' initially. Client updates to 'read' later if we impl that.
        emit('message', {'user': username, 'text': text, 'time': timestamp, 'type': 'user', 'status': 'sent'}, broadcast=True)

@socketio.on('send_file')
def handle_file(data):
    username = data.get('username')
    file_name = data.get('fileName')
    file_data = data.get('fileData') # Base64 string
    if username and file_name and file_data:
        timestamp = datetime.datetime.now().strftime('%H:%M')
        emit('file_shared', {'user': username, 'fileName': file_name, 'fileData': file_data, 'time': timestamp}, broadcast=True)

@socketio.on('typing')
def handle_typing(data):
    username = data.get('username')
    emit('display_typing', {'user': username}, broadcast=True, include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    username = data.get('username')
    emit('hide_typing', {'user': username}, broadcast=True, include_self=False)

# --- WebRTC Signaling ---
@socketio.on('call_signal')
def handle_call_signal(data):
    emit('call_signal', data, broadcast=True, include_self=False)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
