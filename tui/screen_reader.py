"""Match the current VT screen, not just the most recent incremental repaint."""
import os
import select
import time

from installed_test import painted_text


def terminal_reader(*forbidden):
    history = bytearray()
    checked = 0
    frame_end = b'\x1b[?2026l'

    def wait_text(fd, marker):
        nonlocal checked
        fresh = bytearray()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
            part = os.read(fd, 65536)
            if not part:
                raise EOFError(marker)
            fresh.extend(part)
            history.extend(part)
            if any(token in history for token in forbidden):
                raise AssertionError('private callback appeared in terminal output')
            screen = b''
            while (end := history.find(frame_end, checked)) >= 0:
                checked = end + len(frame_end)
                if forbidden or marker not in fresh:
                    screen = painted_text(fd, history[:checked])
                if any(token in screen for token in forbidden):
                    raise AssertionError('private callback appeared in terminal output')
            if marker in fresh or marker in screen:
                return fresh
        raise AssertionError(f'missing {marker!r} on screen: {painted_text(fd, history)!r}')

    return wait_text
