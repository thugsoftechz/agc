import os
import pytest

def test_main_exists():
    assert os.path.exists("main.py"), "main.py does not exist, buildozer will fail"
    assert not os.path.exists("mobile_app.py"), "mobile_app.py should have been renamed"

def test_app_debug_disabled():
    with open("app.py", "r") as f:
        content = f.read()
    assert "debug=False" in content, "Flask debug mode should be disabled"

def test_ui_thread_safe():
    with open("agc_lib/ui.py", "r") as f:
        content = f.read()
    assert "self.root.after" in content, "GUI UI updates must be thread-safe using root.after"
