import pytest
import re

def test_flask_socketio_debug_disabled():
    with open('app.py', 'r') as f:
        content = f.read()

    # We want to check if socketio.run is called with debug=False
    match = re.search(r"socketio\.run\(.*debug=False.*\)", content)
    assert match is not None, "socketio.run should explicitly disable debug mode"
