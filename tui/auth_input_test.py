"""The sign-in picker reaches every provider, and a pasted callback never
becomes a goal, never echoes its code and never leaves the private panel."""
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

    # The picker lists every provider the core can sign in to, and the search
    # filters by name and id.
    os.write(master, b'/login\r')
    see(master, b'Sign in to a provider')
    see(master, b'OpenAI (ChatGPT)')
    see(master, b'Anthropic (Claude)')
    # Interactive legs come first: Anthropic, Copilot, Kimi, OpenAI, Z.AI.
    os.write(master, b'\x1b[B\x1b[B\x1b[B')
    see(master, b'\xe2\x96\xaa OpenAI (ChatGPT)')
    os.write(master, b'\r')
    see(master, b'Sign in \xc2\xb7 OpenAI (ChatGPT)')
    see(master, b'Device code')

    # A provider with two methods asks once; the browser leg takes it.
    os.write(master, b'\r')
    see(master, b'Open sign-in page')
    see(master, b'Paste the redirect URL')
    os.write(master, b'\x19')
    def complete_url(screen):
        # Join visible content cells across wraps, excluding the sidebar.
        content = b''.join(row.rsplit('│'.encode(), 1)[-1].strip() for row in screen.splitlines())
        return b'https://auth.openai.com/oauth/authorize?' in content and b'&originator=omp' in content

    see(master, b'complete authorization URL', screen_matches=complete_url)

    # A stale redirect is refused without echoing the code, and the private
    # entry stays hidden.
    os.write(master, b'\x1b[200~' + callback.replace(b'/callback?', b'/wrong?') + b'\x1b[201~\r')
    assert secret not in see(master, b'Redirect refused')

    # A callback pasted outside the panel is discarded before it can become a
    # goal or a stored task.
    os.write(master, b'\x1b')
    see(master, b'Login cancelled.')
    os.write(master, b'\x1b[200~' + callback + b'\x1b[201~\r')
    assert secret not in see(master, b'Callback discarded')
    assert secret not in see(master, b'Message')

    # A stored-key provider reaches its hidden key prompt without touching a
    # credential store; Esc walks back out of the picker.
    os.write(master, b'/login deepseek\r')
    see(master, b'DeepSeek')
    os.write(master, b'\r')
    see(master, b'API key \xc2\xb7 DeepSeek')
    see(master, b'Paste the key')
    os.write(master, b'\x1b')
    see(master, b'Sign in \xc2\xb7 DeepSeek')
    os.write(master, b'\x1b')
    see(master, b'Sign in to a provider')
    os.write(master, b'\x1b')
    see(master, b'Message')

    os.write(master, b'\x1b[200~/permissions\x1b[201~\r')
    result = see(master, b'Permissions:')
    assert secret not in result
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
        assert db.execute('select (select count(*) from tasks), (select count(*) from usage_settlements)').fetchone() == (0, 0)
