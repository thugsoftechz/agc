from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, send, join_room, leave_room
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'this_should_be_a_secret_key'
socketio = SocketIO(app)

# Route for the main page
@app.route('/')
def index():
    return render_template('index.html')

# Listen for messages from clients
@socketio.on('message')
def handle_message(msg):
    print("Received message: " + msg)
    # Send broadcast to all connected clients
    send(msg, broadcast=True)

# (Optional) Listen for JSON messages or add additional events
@socketio.on('json')
def handle_json(json_msg):
    print("Received JSON: " + str(json_msg))
    emit('json', json_msg, broadcast=True)

if __name__ == '__main__':
    # Run the Flask app with SocketIO.
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)