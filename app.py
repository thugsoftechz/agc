from flask import Flask, render_template
from flask_socketio import SocketIO, send

app = Flask(__name__)
# Change this key to a random secret in a real deployment.
app.config['SECRET_KEY'] = 'your_secret_key_here'
socketio = SocketIO(app)

@app.route('/')
def index():
    # Renders the main chat interface from 'templates/index.html'
    return render_template('index.html')

@socketio.on('message')
def handle_message(msg):
    print(f"Received message: {msg}")
    # Broadcasts the message to all connected clients.
    send(msg, broadcast=True)

if __name__ == '__main__':
    # Run the Flask app on all interfaces (0.0.0.0) on port 5000 with debug mode on.
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)