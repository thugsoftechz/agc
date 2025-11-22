import threading
import webbrowser
import socket
import os
import sys

# Ensure we can find local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Kivy Imports
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.clock import Clock
from kivy.core.window import Window

# Import Flask App
# We import here to avoid top-level side effects before Kivy starts
try:
    from app import app, socketio
except ImportError as e:
    print(f"Failed to import app: {e}")
    app = None

class AGCAndroidApp(App):
    def build(self):
        self.title = "AGC Secure Chat"
        self.layout = BoxLayout(orientation='vertical', padding=20, spacing=10)
        self.status_label = Label(text="Initializing AGC Secure Core...", font_size='20sp')
        self.info_label = Label(text="Please wait while encryption services start.", font_size='14sp', color=(0.8, 0.8, 0.8, 1))
        self.layout.add_widget(self.status_label)
        self.layout.add_widget(self.info_label)

        if app:
            # Start Flask in a background thread
            self.server_thread = threading.Thread(target=self.run_flask)
            self.server_thread.daemon = True
            self.server_thread.start()

            # Schedule browser launch
            Clock.schedule_once(self.open_browser, 3)
        else:
            self.status_label.text = "Critical Error: Web Core Not Found"
            self.info_label.text = "Could not load 'app.py'. Check installation."

        return self.layout

    def run_flask(self):
        try:
            # On Android, permissions are critical.
            # Flask-SocketIO runs a gevent/eventlet server.
            socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
        except Exception as e:
            print(f"Flask Server Error: {e}")
            # We can't easily update UI from this thread without Clock, but logging helps.

    def open_browser(self, dt):
        url = "http://localhost:5000"
        self.status_label.text = "AGC Active"
        self.info_label.text = f"Service running at {url}\nLaunching interface..."
        try:
            webbrowser.open(url)
        except Exception as e:
            self.info_label.text += f"\nError opening browser: {e}"

    def on_stop(self):
        # Cleanup if needed
        pass

if __name__ == '__main__':
    AGCAndroidApp().run()
