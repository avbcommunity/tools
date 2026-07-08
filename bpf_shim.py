"""macOS BPF backend for atdecc_controller.py raw Ethernet I/O.

Drop-in replacements for open_raw_socket / get_mac_address / send_frame /
recv_frame. BPF requires root. A kernel-side filter accepts only untagged
ethertype 0x22F0 so the AVTP media streams (VLAN-tagged) never reach us.
"""
import ctypes
import fcntl
import os
import re
import select
import struct
import subprocess

ETH_P_AVTP = 0x22F0

BIOCGBLEN = 0x40044266
BIOCSETF = 0x80104267
BIOCPROMISC = 0x20004269
BIOCSETIF = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCSHDRCMPLT = 0x80044275
BIOCSSEESENT = 0x80044277


class _BpfInsn(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint),
                ("bf_insns", ctypes.POINTER(_BpfInsn))]


class MacBpfSocket:
    def __init__(self, interface: str, ethertype=ETH_P_AVTP):
        fd = None
        for i in range(256):
            try:
                fd = os.open(f"/dev/bpf{i}", os.O_RDWR)
                break
            except PermissionError:
                raise
            except OSError:
                continue
        if fd is None:
            raise OSError("no free /dev/bpf device")
        self.fd = fd
        self.blen = struct.unpack(
            "I", fcntl.ioctl(fd, BIOCGBLEN, struct.pack("I", 0)))[0]
        fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", interface.encode()))
        fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
        fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack("I", 1))
        fcntl.ioctl(fd, BIOCSSEESENT, struct.pack("I", 1))
        # ldh [12]; jeq <ethertype[i]> ? accept : next / drop.
        # `ethertype` may be a single value or an iterable of them.
        ets = (ethertype,) if isinstance(ethertype, int) else tuple(ethertype)
        n = len(ets)
        insns = [_BpfInsn(0x28, 0, 0, 12)]
        for i, et in enumerate(ets):
            jt = n - 1 - i           # skip remaining jeqs to the accept
            jf = 0 if i < n - 1 else 1  # last mismatch falls to the drop
            insns.append(_BpfInsn(0x15, jt, jf, et))
        insns.append(_BpfInsn(0x06, 0, 0, 0xFFFFFFFF))
        insns.append(_BpfInsn(0x06, 0, 0, 0))
        self._insns = (_BpfInsn * len(insns))(*insns)
        prog = _BpfProgram(len(insns), self._insns)
        fcntl.ioctl(fd, BIOCSETF, bytes(prog))
        # Multicast dst (ADP/ACMP 91:e0:f0:01:00:00) needs promiscuous RX.
        fcntl.ioctl(fd, BIOCPROMISC, 0)
        self._q = []

    def _refill(self):
        try:
            data = os.read(self.fd, self.blen)
        except BlockingIOError:
            return
        off = 0
        while off + 18 <= len(data):
            ts_sec, ts_usec = struct.unpack_from("II", data, off)
            caplen, datalen, hdrlen = struct.unpack_from("IIH", data, off + 8)
            pkt = data[off + hdrlen: off + hdrlen + caplen]
            if pkt:
                self._q.append((ts_sec + ts_usec / 1e6, pkt))
            off += (hdrlen + caplen + 3) & ~3

    def fileno(self):
        return self.fd

    def setblocking(self, flag):
        pass

    def close(self):
        os.close(self.fd)


def open_raw_socket(interface: str):
    return MacBpfSocket(interface)


def get_mac_address(interface: str) -> bytes:
    out = subprocess.run(["ifconfig", interface], capture_output=True,
                         text=True).stdout
    m = re.search(r"ether ([0-9a-f:]{17})", out)
    if not m:
        raise RuntimeError(f"no MAC found for {interface}")
    return bytes.fromhex(m.group(1).replace(":", ""))


def send_frame(sock, interface: str, dest_mac: bytes, src_mac: bytes,
               payload: bytes) -> None:
    frame = struct.pack("!6s6sH", dest_mac, src_mac, ETH_P_AVTP) + payload
    os.write(sock.fd, frame)


def recv_frame(sock, timeout: float = 0.1):
    if not sock._q:
        ready, _, _ = select.select([sock.fd], [], [], timeout)
        if not ready:
            return None
        sock._refill()
    if not sock._q:
        return None
    _, data = sock._q.pop(0)
    if len(data) < 18:
        return None
    src_mac = data[6:12]
    ethertype = struct.unpack("!H", data[12:14])[0]
    if ethertype != ETH_P_AVTP:
        return None
    return src_mac, data[14:]


def recv_raw_ts(sock, timeout: float = 0.1):
    """Like recv_frame but returns (bpf_timestamp, dst_mac, src_mac,
    ethertype, payload) for any accepted frame."""
    if not sock._q:
        ready, _, _ = select.select([sock.fd], [], [], timeout)
        if not ready:
            return None
        sock._refill()
    if not sock._q:
        return None
    ts, data = sock._q.pop(0)
    if len(data) < 14:
        return None
    return (ts, data[0:6], data[6:12],
            struct.unpack("!H", data[12:14])[0], data[14:])
