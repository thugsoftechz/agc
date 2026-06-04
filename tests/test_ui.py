import pytest
from unittest.mock import MagicMock
import tkinter as tk

# We need to mock tk before importing GUI from agc_lib.ui
# Wait, agc_lib.ui already imports tkinter.
# We'll just create the mock instance.
import sys
from agc_lib.ui import GUI

def test_gui_log_thread_safety(monkeypatch):
    # Mock Tkinter components
    mock_tk = MagicMock()
    monkeypatch.setattr('tkinter.Tk', mock_tk)
    monkeypatch.setattr('tkinter.scrolledtext.ScrolledText', MagicMock())
    monkeypatch.setattr('tkinter.Entry', MagicMock())
    monkeypatch.setattr('tkinter.Frame', MagicMock())
    monkeypatch.setattr('tkinter.Button', MagicMock())

    conn = MagicMock()
    sec = MagicMock()

    gui = GUI(conn, sec)

    # Reset mock to track calls
    gui.root.after = MagicMock()

    # Test _log
    gui._log("Test Message")

    # Check if root.after was called
    gui.root.after.assert_called_once_with(0, gui._real_log, "Test Message")

    # Test _real_log
    gui.txt = MagicMock()
    gui._real_log("Real Test")
    gui.txt.config.assert_any_call(state='normal')
    gui.txt.insert.assert_any_call(tk.END, "Real Test\n")
    gui.txt.see.assert_any_call(tk.END)
    gui.txt.config.assert_any_call(state='disabled')
