from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import datetime
import os
import hashlib

# Import from new package structure if needed for backend logic
from agc_lib import SecurityManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'agc_secret_key_change_this'
socketio = SocketIO(app, cors_allowed_origins="*")

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
        emit('message', {'user': 'System', 'text': f'{username} has joined.', 'time': timestamp, 'type': 'system'}, broadcast=True)

        # Generate a visual fingerprint for the session
        # In a full web implementation, this would use client-side keys, but for this demo we verify the backend exists
        fingerprint = hashlib.sha256(app.config['SECRET_KEY'].encode() + username.encode()).hexdigest()[:16].upper()
        emit('security_fingerprint', {'fingerprint': fingerprint}, to=request.sid)

@socketio.on('send_message')
def handle_message(data):
    username = data.get('username')
    text = data.get('text')
    if username and text:
        timestamp = datetime.datetime.now().strftime('%H:%M')
        emit('message', {'user': username, 'text': text, 'time': timestamp, 'type': 'user', 'status': 'sent'}, broadcast=True)

@socketio.on('send_file')
def handle_file(data):
    username = data.get('username')
    file_name = data.get('fileName')
    file_data = data.get('fileData')
    if username and file_name and file_data:
        timestamp = datetime.datetime.now().strftime('%H:%M')
        emit('file_shared', {'user': username, 'fileName': file_name, 'fileData': file_data, 'time': timestamp}, broadcast=True)

@socketio.on('typing')
def handle_typing(data):
    emit('display_typing', {'user': data.get('username')}, broadcast=True, include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    emit('hide_typing', {'user': data.get('username')}, broadcast=True, include_self=False)

@socketio.on('call_signal')
def handle_call_signal(data):
    emit('call_signal', data, broadcast=True, include_self=False)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
