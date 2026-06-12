import sys
import os
sys.path.insert(0, os.path.abspath('.'))

def test_imports():
    import agc
    import app
    import agc_lib
    import agc_lib.media
    import agc_lib.networking
    import agc_lib.security
    import agc_lib.ui
    import agc_lib.utils
