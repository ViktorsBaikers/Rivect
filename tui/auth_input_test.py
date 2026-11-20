"""A callback pasted into the ordinary composer must never become a goal or echo its code."""
import os
from pathlib import Path
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
    see(master, b'Open OpenAI sign-in')
    see(master, b'Paste the callback URL')
    os.write(master, b'\x19')
    def complete_url(screen):
        # Join visible content cells across wraps, excluding the sidebar.
        content = b''.join(row.rsplit('│'.encode(), 1)[-1].strip() for row in screen.splitlines())
        return b'https://auth.openai.com/oauth/authorize?' in content and b'&originator=omp' in content

    see(master, b'complete authorization URL', screen_matches=complete_url)
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
