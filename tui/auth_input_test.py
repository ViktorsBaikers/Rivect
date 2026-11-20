"""A callback pasted into the ordinary composer must never become a goal or echo its code."""
import os
import base64
from pathlib import Path
import re
import sqlite3
import sys

from installed_test import chat_terminal
from screen_reader import terminal_reader

def configure_login(home):
    with (home / '.rivect/config.toml').open('a') as config:
        config.write('[connections.openai-codex]\nkind = "api_key"\nendpoint = "https://chatgpt.com/backend-api/codex"\n'
                     'credential_ref = "keychain:rivect-test/openai-codex"\nprofile = "openai-codex"\n'
                     '[profiles.openai-codex]\ncredential_ref = "keychain:rivect-test/openai-codex"\n')


with chat_terminal(Path(sys.argv[1]).resolve(strict=True), 'loopback', '', before_start=configure_login) as (master, database, _):
    secret = b'private-test-code-42'
    see = terminal_reader(secret)
    callback = b'http://localhost:1455/auth/callback?state=wrong&code=' + secret
    os.write(master, b'/login\r')  # Browser PKCE begin produces a URL locally; no token exchange.
    see(master, b'Paste the callback URL')
    os.write(master, b'\x19')  # Ctrl+Y copies only the authorization URL.
    copied = see(master, b'Copy requested.')
    payload = re.search(rb'\x1b\]52;c;([A-Za-z0-9+/=]+)', copied)
    assert payload, 'missing terminal clipboard write'
    authorize = base64.b64decode(payload[1], validate=True)
    assert authorize.startswith(b'https://auth.openai.com/oauth/authorize?')
    assert b'code_challenge_method=S256&state=' in authorize
    assert b'originator=' in authorize and b' ' not in authorize and secret not in authorize
    os.write(master, b'\x1b[200~' + callback.replace(b'/callback?', b'/wrong?') + b'\x1b[201~\r')
    assert secret not in see(master, b'Input discarded')
    os.write(master, b'\x1b')
    assert secret not in see(master, b'Login pending')
    os.write(master, b'\x1b[200~' + callback + b'\x1b[201~\r')
    result = see(master, b'Private login')
    assert secret not in result
    os.write(master, b'\x1b')
    restored = see(master, b'Message')
    assert secret not in restored
    os.write(master, b'http://localhost:1455/auth/callback?')
    see(master, b'Private login')
    os.write(master, b'code=' + secret + b'\r\x1b')
    see(master, b'Message')
    os.write(master, b'/login cancel\r')
    assert secret not in see(master, b'Login cancelled.')
    os.write(master, b'/permissions\r')
    result = see(master, b'Permissions:')
    assert secret not in result
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
        assert db.execute('select (select count(*) from tasks), (select count(*) from usage_settlements)').fetchone() == (0, 0)
