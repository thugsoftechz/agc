import pytest
import os

def test_werkzeug_socketio():
    with open('app.py', 'r') as f:
        assert 'allow_unsafe_werkzeug=True' in f.read(), "allow_unsafe_werkzeug missing in app.py"
    with open('agc.py', 'r') as f:
        assert 'allow_unsafe_werkzeug=True' in f.read(), "allow_unsafe_werkzeug missing in agc.py"
    if os.path.exists('main.py'):
        with open('main.py', 'r') as f:
            assert 'allow_unsafe_werkzeug=True' in f.read(), "allow_unsafe_werkzeug missing in main.py"

def test_ui_after():
    with open('agc_lib/ui.py', 'r') as f:
        content = f.read()
        assert 'self.root.after(0, ' in content or 'self.root.after(1, ' in content, "root.after missing in ui.py"

def test_main_py_exists():
    assert os.path.exists('main.py'), "main.py does not exist"
    assert not os.path.exists('mobile_app.py'), "mobile_app.py should have been renamed"

def test_gitignore():
    with open('.gitignore', 'r') as f:
        content = f.read()
        assert 'build/' in content
        assert 'dist/' in content
        assert '*.egg-info/' in content
        assert '*.spec' in content
