#!/usr/bin/env python3
"""Read-only, no-reset serial logger for ESP DUTs.

Opening a CH343/CP210x port pulses DTR/RTS through the board auto-reset
circuit and reboots the ESP. The pulse happens inside the tty open()
itself, so it cannot be suppressed after the fact: every fresh open of
the port resets the board and corrupts any measurement taken while a
monitor attaches.

The only reliable rule is therefore "open once, never reopen":
  - one holder opens the port a single time (the one acceptable reset,
    at session setup, before any measurement), then holds it open for
    the whole session,
  - it is strictly read-only and appends timestamped lines to a
    logfile,
  - all diagnostics tail the logfile and never touch the port, so
    nothing perturbs the DUT during a test.

To make the rule enforceable, the holder refuses to start if the port
is already open (which would reset the board). Clearing HUPCL keeps a
clean close from dropping DTR, but is a courtesy only; do not rely on
reopen being reset-free, because open() itself is the reset.
"""
import argparse
import os
import subprocess
import sys
import termios
import time

import serial


def port_already_open(port_path):
    """True if any process holds the port open (reopening resets it)."""
    try:
        result = subprocess.run(["fuser", port_path], capture_output=True)
        return result.returncode == 0
    except FileNotFoundError:
        pass
    # No fuser: scan every process's descriptors for the device itself
    target = os.path.realpath(port_path)
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or pid == str(os.getpid()):
            continue
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                if os.path.realpath(f"/proc/{pid}/fd/{fd}") == target:
                    return True
        except OSError:
            continue
    return False


def hold_lines_and_clear_hupcl(fd):
    """Keep DTR/RTS steady and stop a clean close from lowering DTR."""
    attrs = termios.tcgetattr(fd)
    attrs[2] &= ~termios.HUPCL   # cflag: do not drop DTR on close
    attrs[2] |= termios.CLOCAL   # ignore modem status lines
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port")
    parser.add_argument("logfile")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--force", action="store_true",
                        help="open even if the port is already held "
                             "(this WILL reset the board)")
    args = parser.parse_args()

    if port_already_open(args.port) and not args.force:
        sys.exit(f"refusing to open {args.port}: already held by another "
                 f"process; reopening would reset the board. Tail the "
                 f"existing logfile instead, or pass --force.")

    port = serial.Serial()
    port.port = args.port
    port.baudrate = args.baud
    port.timeout = 1
    # Leave both control lines de-asserted and, crucially, unchanging.
    port.dtr = False
    port.rts = False
    port.open()
    hold_lines_and_clear_hupcl(port.fileno())

    logfile = open(args.logfile, "ab", buffering=0)
    pending = bytearray()
    while True:
        chunk = port.read(4096)
        if not chunk:
            continue
        for byte in chunk:
            pending.append(byte)
            if byte == 0x0A:
                stamp = time.strftime("%H:%M:%S").encode()
                logfile.write(b"[" + stamp + b"] " + bytes(pending))
                pending = bytearray()


if __name__ == "__main__":
    main()
