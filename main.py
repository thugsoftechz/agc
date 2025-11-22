import threading
import webbrowser
import socket
import os
import sys

# Ensure we can find local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.clock import Clock
from kivy.core.window import Window

# Safe Import of Flask App
try:
    from app import app, socketio
except ImportError as e:
    print(f"Failed to import app: {e}")
    app = None

class AGCAndroidApp(App):
    def build(self):
        self.title = "AGC Secure Chat"
        self.layout = BoxLayout(orientation='vertical', padding=20, spacing=10)
        self.status_label = Label(text="Initializing AGC System...", font_size='20sp')
        self.info_label = Label(text="Starting Encryption Services...", font_size='14sp')
        self.layout.add_widget(self.status_label)
        self.layout.add_widget(self.info_label)

        if app:
            self.server_thread = threading.Thread(target=self.run_flask)
            self.server_thread.daemon = True
            self.server_thread.start()
            Clock.schedule_once(self.open_browser, 3)
        else:
            self.status_label.text = "Critical Error"
            self.info_label.text = "Could not load web core."

        return self.layout

    def run_flask(self):
        try:
            socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
        except Exception as e:
            print(f"Flask Server Error: {e}")

    def open_browser(self, dt):
        url = "http://localhost:5000"
        self.status_label.text = "AGC Active"
        self.info_label.text = f"Running at {url}\nLaunching Interface..."
        try:
            webbrowser.open(url)
        except Exception as e:
            self.info_label.text += f"\nBrowser Error: {e}"

if __name__ == '__main__':
    AGCAndroidApp().run()
