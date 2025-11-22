from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import datetime

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

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
