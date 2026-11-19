"""Installed Settings Center: inspection and previews do not publish; confirmed edits do."""
import os
from pathlib import Path
import sys
import tomllib

from installed_test import chat_terminal
from screen_reader import terminal_reader

with chat_terminal(Path(sys.argv[1]).resolve(strict=True), 'loopback', '') as (master, database, _):
    wait_text = terminal_reader()
    config = database.parent.parent / 'config.toml'
    before = config.read_bytes()
    os.write(master, b'/settings\r')
    wait_text(master, b'Settings Center')
    os.write(master, b'/')
    wait_text(master, b'Search settings')
    os.write(master, b'context.auto_compact\r')
    wait_text(master, b'1 result')
    os.write(master, b'e')
    wait_text(master, b'Value (JSON)')
    os.write(master, b'false\r')
    wait_text(master, b'Confirm change')
    assert config.read_bytes() == before
    os.write(master, b'y')
    wait_text(master, b'Saved to user config')
    assert tomllib.loads(config.read_text())['context']['auto_compact'] is False
    os.write(master, b'r')
    wait_text(master, b'Confirm reset')
    os.write(master, b'y')
    wait_text(master, b'Reset user override')
    assert 'auto_compact' not in tomllib.loads(config.read_text()).get('context', {})
    os.write(master, b'\x1b')


with chat_terminal(Path(sys.argv[1]).resolve(strict=True), 'loopback', '',
                   before_start=lambda home: (home / '.rivect/config.toml').unlink()) as (master, database, _):
    wait_text = terminal_reader(b'Saved to user config')
    os.write(master, b'/workflow off\r')
    wait_text(master, b'config_version = 1')
    os.write(master, b'y\x1b')
    wait_text(master, b'Message')
    assert not (database.parent.parent / 'config.toml').exists()
