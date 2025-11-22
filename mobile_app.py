from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.clock import Clock
from kivy.core.window import Window
import threading
import time
import webbrowser
import socket

# Import the web app logic
# Note: In a real APK build, we might need to adjust imports or run this in a subprocess.
# For Kivy, running Flask in a thread is a common pattern.
from app import app, socketio

class AGCAndroidApp(App):
    def build(self):
        self.layout = BoxLayout(orientation='vertical')
        self.status_label = Label(text="Starting AGC Service...", font_size='20sp')
        self.layout.add_widget(self.status_label)

        # Start Flask in a background thread
        self.server_thread = threading.Thread(target=self.run_flask)
        self.server_thread.daemon = True
        self.server_thread.start()

        # Schedule opening the browser
        Clock.schedule_once(self.open_browser, 3)

        return self.layout

    def run_flask(self):
        # Run Flask on a local port
        try:
            socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
        except Exception as e:
            print(f"Flask Error: {e}")

    def open_browser(self, dt):
        self.status_label.text = "AGC Running on http://localhost:5000\nOpening Browser..."
        webbrowser.open("http://localhost:5000")

if __name__ == '__main__':
    AGCAndroidApp().run()
