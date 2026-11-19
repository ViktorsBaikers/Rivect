"""Measure editing and local transport cancellation with history visible in an installed PTY."""
from http.client import parse_headers
import json
import os
from pathlib import Path
import select
import socket
import sqlite3
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tui.installed_test import chat_terminal, wait_text


def tree_rss(pid):
    rows = [list(map(int, line.split())) for line in subprocess.check_output(
        ['ps', '-axo', 'pid=,ppid=,rss='], text=True).splitlines()]
    owned = {pid}
    while children := {child for child, parent, _ in rows if parent in owned} - owned:
        owned.update(children)
    return sum(rss for child, _, rss in rows if child in owned), len(owned)


def chunk(text, finish=None):
    data = {'id':'c1', 'object':'chat.completion.chunk', 'choices':[
        {'index':0, 'delta':{'content':text}, 'finish_reason':finish}]}
    return ('data: ' + json.dumps(data) + '\n\n').encode()


def accept_goal(listener, master, goal):
    os.write(master, goal.encode() + b'\r')
    # Large frames can fill the PTY before the client dispatches its request.
    deadline = time.monotonic() + listener.gettimeout()
    while True:
        ready, _, _ = select.select([listener, master], [], [], max(0, deadline - time.monotonic()))
        if listener in ready:
            break
        if not ready or time.monotonic() >= deadline:
            raise TimeoutError(f'no local request for {goal!r}')
        if not os.read(master, 65536):
            raise EOFError(goal)
    peer, _ = listener.accept()
    try:
        peer.settimeout(5)
        with peer.makefile('rb') as request:
            assert request.readline().startswith(b'POST /v1/chat/completions ')
            headers = parse_headers(request)
            assert goal.encode() in request.read(int(headers['Content-Length']))
        peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n')
        return peer
    except BaseException:
        peer.close()
        raise


def sample(binary, count):
    with socket.create_server(('127.0.0.1', 0)) as listener:
        listener.settimeout(5)
        endpoint = f'http://127.0.0.1:{listener.getsockname()[1]}/v1'
        with chat_terminal(binary, 'vllm', endpoint) as (master, database, child):
            for n in range(count):
                # Every receipt has a different glyph: a terminal diff may omit unchanged hex digits.
                marker = chr(0x410 + n)
                # A historical patch in a real model reply, not a synthetic Diff widget.
                text = ('--- old\n+++ new\n' + ''.join(f'@@ hunk {i} @@\n-before\n+after\n' for i in range(20))
                        if n == count - 1 else '') + marker
                with accept_goal(listener, master, f'committed receipt {n}') as peer:
                    peer.sendall(chunk(text, 'stop') + b'data: [DONE]\n\n')
                wait_text(master, marker.encode())
            with accept_goal(listener, master, 'pending final message') as peer:
                peer.sendall(chunk('early fragment'))
                os.write(master, b'\x1b[5~')
                wait_text(master, b'@@ hunk ')
                peer.sendall(chunk(' while reading'))
                started = time.monotonic_ns()
                os.write(master, b'input-latency')
                peer.sendall(chunk(' while editing'))
                wait_text(master, b'input-latency')
                echo = time.monotonic_ns()
                rss, processes = tree_rss(child.pid)
                assert processes >= 2, 'core missing from RSS sample'
                cancel = time.monotonic_ns()
                os.write(master, b'\x03')
                assert peer.recv(1) == b'', 'transport still open'
                eof = time.monotonic_ns()
                deadline = time.monotonic() + 8
                with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                    while db.execute("SELECT count(*) FROM tasks WHERE lifecycle='cancelled'").fetchone() != (1,):
                        if time.monotonic() >= deadline:
                            raise TimeoutError('owner did not settle the cancelled task')
                        if select.select([master], [], [], .01)[0]:
                            os.read(master, 65536)
                settled = time.monotonic_ns()
            with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                assert dict(db.execute('SELECT lifecycle, count(*) FROM tasks GROUP BY lifecycle')) == {'waiting':count, 'cancelled':1}
            assert not select.select([listener], [], [], .1)[0], 'history or cancellation sent another POST'
            return {'tasks': count, 'input_ms': (echo-started)/1e6,
                    'cancel_to_peer_eof_ms': (eof-cancel)/1e6, 'cancel_to_durable_ms': (settled-cancel)/1e6,
                    'tree_rss_kib': rss, 'processes_sampled': processes}


if __name__ == '__main__':
    binary = Path(sys.argv[1]).resolve(strict=True)
    for count in (1, 100):
        print(json.dumps(sample(binary, count)), flush=True)
