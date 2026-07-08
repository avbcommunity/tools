#!/usr/bin/env python3
"""
AVTP Streamer - emit AAF or IEC 61883-6 (AM824) PCM streams of a sine wave.

Generates a sine wave at a configurable frequency, packs the resulting PCM
into AVTP packets (IEEE 1722-2016 AAF or AM824), and transmits them on a
raw AF_PACKET socket at the SR class A (8000 pps) or class B (4000 pps)
packet rate. The stream contains N total channels; the first M channels
carry the sine wave and the remaining N-M channels carry silence.

Protocol references:
  - IEEE 1722-2016 Section 7 (AAF)
  - IEEE 1722-2016 Section 9 / IEC 61883-6 (AM824)

Usage:
  sudo python3 avtp_streamer.py -i eno1 \
      --stream-id 00:1b:21:01:02:03:00:01 --format aaf \
      --freq 1000 --duration 5 --channels 8 --active-channels 2

  sudo python3 avtp_streamer.py -i eno1 \
      --stream-id 00:1b:21:01:02:03:00:02 --format am824 \
      --freq 440 --duration 10 --channels 2 --active-channels 2 \
      --dest-mac 91:e0:f0:00:fe:01 --vlan 2
"""

import argparse
import fcntl
import math
import socket
import struct
import sys
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ETH_P_AVTP = 0x22F0
ETH_P_VLAN = 0x8100
ETH_HLEN = 14
SIOCGIFHWADDR = 0x8927

AVTP_SUBTYPE_61883 = 0x00
AVTP_SUBTYPE_AAF = 0x02

# AAF format codes (IEEE 1722-2016 Table 7-2).
AAF_FORMAT_INT32 = 0x02
AAF_FORMAT_INT24 = 0x03
AAF_FORMAT_INT16 = 0x04

AAF_FORMAT_BY_BITS = {
    16: AAF_FORMAT_INT16,
    24: AAF_FORMAT_INT24,
    32: AAF_FORMAT_INT32,
}

# AAF "nominal sample rate" field (Table 7-3).
AAF_NSR = {
    8000:   0x01,
    16000:  0x02,
    32000:  0x03,
    44100:  0x04,
    48000:  0x05,
    88200:  0x06,
    96000:  0x07,
    176400: 0x08,
    192000: 0x09,
}

# IEC 61883-6 SFC bits inside CIP header FDF byte for audio.
IEC61883_SFC = {
    32000:  0x00,
    44100:  0x01,
    48000:  0x02,
    88200:  0x03,
    96000:  0x04,
    176400: 0x05,
    192000: 0x06,
}

# IEC 61883-6 AM824 label for multi-bit linear audio.
AM824_LABEL_MBLA = 0x40

# SR class packet rates and default 802.1Q PCP.
SR_CLASS_PPS = {"A": 8000, "B": 4000}
SR_CLASS_PCP = {"A": 3, "B": 2}

# Default stream destination MAC (locally-administered AVTP multicast range).
DEFAULT_DEST_MAC = b"\x91\xe0\xf0\x00\xfe\x00"


# ---------------------------------------------------------------------------
# Argument parsers
# ---------------------------------------------------------------------------

def parse_mac(s: str) -> bytes:
    s = s.strip().lower().replace("-", ":")
    if ":" in s:
        parts = s.split(":")
        if len(parts) != 6:
            raise argparse.ArgumentTypeError(f"MAC must have 6 octets: {s}")
        return bytes(int(p, 16) for p in parts)
    if len(s) != 12:
        raise argparse.ArgumentTypeError(f"MAC must be 12 hex chars: {s}")
    return bytes.fromhex(s)


def parse_stream_id(s: str) -> bytes:
    s = s.strip().lower().replace("-", ":")
    if ":" in s:
        parts = s.split(":")
        if len(parts) != 8:
            raise argparse.ArgumentTypeError(
                f"StreamID must have 8 octets, got {len(parts)}: {s}")
        return bytes(int(p, 16) for p in parts)
    if len(s) != 16:
        raise argparse.ArgumentTypeError(f"StreamID must be 16 hex chars: {s}")
    return bytes.fromhex(s)


def format_mac(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def format_stream_id(sid: bytes) -> str:
    return ":".join(f"{b:02x}" for b in sid)


# ---------------------------------------------------------------------------
# Socket / interface
# ---------------------------------------------------------------------------

def get_interface_mac(interface: str) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(
            s.fileno(), SIOCGIFHWADDR,
            struct.pack("256s", interface.encode("utf-8")[:15]),
        )
        return info[18:24]
    finally:
        s.close()


def open_tx_socket(interface: str) -> socket.socket:
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETH_P_AVTP))
    except PermissionError:
        print("Error: raw sockets require root privileges (sudo) or CAP_NET_RAW.",
              file=sys.stderr)
        sys.exit(1)
    sock.bind((interface, ETH_P_AVTP))
    return sock


def raw_send(sock, frame: bytes, interface: str) -> None:
    sock.sendto(frame, (interface, 0))


if sys.platform == "darwin":
    # macOS has no AF_PACKET; transmit through the BPF backend
    # (bpf_shim.py, same directory). Expect a little more pacing
    # jitter than on Linux -- fine for a test-signal generator.
    import os as _os
    from bpf_shim import MacBpfSocket  # noqa: F811
    from bpf_shim import get_mac_address as get_interface_mac  # noqa: F811

    def open_tx_socket(interface):  # noqa: F811
        return MacBpfSocket(interface, ethertype=ETH_P_AVTP)

    def raw_send(sock, frame, interface):  # noqa: F811
        _os.write(sock.fd, frame)


def build_eth_header(dst: bytes, src: bytes, vlan: int, pcp: int) -> bytes:
    """Build an Ethernet (II) header, optionally with a single 802.1Q tag."""
    if vlan is None:
        return struct.pack("!6s6sH", dst, src, ETH_P_AVTP)
    tci = ((pcp & 0x07) << 13) | (vlan & 0x0FFF)
    return struct.pack("!6s6sHHH", dst, src, ETH_P_VLAN, tci, ETH_P_AVTP)


# ---------------------------------------------------------------------------
# AVTP headers
# ---------------------------------------------------------------------------

def build_aaf_header(seq: int, stream_id: bytes, avtp_ts: int,
                     channels: int, sample_rate: int, bit_depth: int,
                     stream_data_length: int) -> bytes:
    """Build a 24-byte AAF AVTPDU header (IEEE 1722-2016 §7.3)."""
    # byte 1 = sv(1) | version(3) | mr(1) | rsv(1) | gv(1) | tv(1) = 0x81
    flags = 0x81
    tu = 0x00
    nsr = AAF_NSR[sample_rate]
    fmt = AAF_FORMAT_BY_BITS[bit_depth]
    chan_h = (channels >> 8) & 0x03
    chan_l = channels & 0xFF
    return (
        struct.pack("!BBBB", AVTP_SUBTYPE_AAF, flags, seq & 0xFF, tu) +
        stream_id +
        struct.pack("!I", avtp_ts & 0xFFFFFFFF) +
        struct.pack("!B", fmt) +
        struct.pack("!B", (nsr << 4) | chan_h) +
        struct.pack("!B", chan_l) +
        struct.pack("!B", bit_depth) +
        struct.pack("!H", stream_data_length) +
        struct.pack("!BB", 0x00, 0x00)
    )


def build_am824_header(seq: int, stream_id: bytes, avtp_ts: int,
                       stream_data_length: int) -> bytes:
    """Build a 24-byte IEC 61883-6 AVTPDU header (no CIP yet)."""
    flags = 0x81  # sv=1, tv=1
    tu = 0x00
    # tag=01b (CIP follows), channel=31 (locally-administered), tcode=0xA, sy=0
    tag_channel = (0x01 << 6) | 31
    tcode_sy = (0x0A << 4) | 0
    return (
        struct.pack("!BBBB", AVTP_SUBTYPE_61883, flags, seq & 0xFF, tu) +
        stream_id +
        struct.pack("!I", avtp_ts & 0xFFFFFFFF) +
        struct.pack("!I", 0x00000000) +  # gateway_info
        struct.pack("!H", stream_data_length) +
        struct.pack("!BB", tag_channel, tcode_sy)
    )


def build_cip_header(dbs: int, dbc: int, sample_rate: int,
                     syt: int = 0xFFFF) -> bytes:
    """Build an 8-byte IEC 61883-6 CIP header for AM824 audio (2 quadlets)."""
    sid = 0x3F
    sfc = IEC61883_SFC[sample_rate]
    q0_byte0 = sid & 0x3F            # bits 7-6 = 00, bits 5-0 = SID
    q0_byte1 = dbs & 0xFF            # DBS in quadlets (= channels)
    q0_byte2 = 0x00                  # FN=0, QPC=0, SPH=0
    q0_byte3 = dbc & 0xFF            # DBC continuity counter
    q1_byte0 = 0x80 | (0x10 & 0x3F)  # '10' marker + FMT=0x10 (audio)
    q1_byte1 = sfc & 0xFF            # FDF = SFC for audio
    return struct.pack(
        "!BBBBBBH",
        q0_byte0, q0_byte1, q0_byte2, q0_byte3,
        q1_byte0, q1_byte1, syt & 0xFFFF,
    )


# ---------------------------------------------------------------------------
# Sample generation
# ---------------------------------------------------------------------------

class SineGenerator:
    """Yields signed integer PCM samples for a continuous sine wave.

    Holds a phase accumulator across packet boundaries so the wave is
    continuous regardless of how the producer batches samples.
    """

    def __init__(self, freq: float, sample_rate: int, bit_depth: int,
                 amplitude: float):
        if amplitude <= 0:
            raise ValueError("amplitude must be > 0")
        self.delta = 2.0 * math.pi * freq / sample_rate
        # AM824 carries a 24-bit sample regardless; for AAF we honor bit_depth.
        max_val = (1 << (bit_depth - 1)) - 1
        self.amp = amplitude * max_val
        self.max_val = max_val
        self.min_val = -(1 << (bit_depth - 1))
        self.phase = 0.0

    def next_block(self, n: int) -> list:
        out = []
        for _ in range(n):
            v = int(round(self.amp * math.sin(self.phase)))
            self.phase += self.delta
            if v > self.max_val:
                v = self.max_val
            elif v < self.min_val:
                v = self.min_val
            out.append(v)
        # Keep phase bounded to avoid losing precision over long runs.
        if self.phase > 2 * math.pi:
            self.phase = math.fmod(self.phase, 2 * math.pi)
        return out


# ---------------------------------------------------------------------------
# Payload encoders
# ---------------------------------------------------------------------------

def encode_aaf_payload(samples: list, channels: int, active: int,
                       bit_depth: int) -> bytes:
    """Interleave `samples` across `channels`; channels >= `active` get zero.

    AAF stores samples as big-endian containers, MSB-aligned for sub-container
    bit depths (24-in-32). For 32-bit Int32, the full container is the sample.
    """
    out = bytearray()
    if bit_depth == 24:
        silent = b"\x00\x00\x00\x00"
        for s in samples:
            container = struct.pack("!I", (s & 0xFFFFFF) << 8)
            for ch in range(channels):
                out += container if ch < active else silent
    elif bit_depth == 32:
        silent = b"\x00\x00\x00\x00"
        for s in samples:
            container = struct.pack("!I", s & 0xFFFFFFFF)
            for ch in range(channels):
                out += container if ch < active else silent
    elif bit_depth == 16:
        silent = b"\x00\x00"
        for s in samples:
            container = struct.pack("!H", s & 0xFFFF)
            for ch in range(channels):
                out += container if ch < active else silent
    else:
        raise ValueError(f"unsupported bit depth: {bit_depth}")
    return bytes(out)


def encode_am824_payload(samples: list, channels: int, active: int) -> bytes:
    """Interleave 24-bit samples as AM824 quadlets (MBLA label + 24-bit value)."""
    silent_quad = bytes([AM824_LABEL_MBLA, 0, 0, 0])
    out = bytearray()
    for s in samples:
        active_quad = bytes([
            AM824_LABEL_MBLA,
            (s >> 16) & 0xFF,
            (s >> 8) & 0xFF,
            s & 0xFF,
        ])
        for ch in range(channels):
            out += active_quad if ch < active else silent_quad
    return bytes(out)


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------

def now_tai_ns() -> int:
    """Return monotonically-increasing nanoseconds suitable for avtp_timestamp.

    Prefer CLOCK_TAI (matches gPTP epoch when the host is PTP-synced); fall
    back to CLOCK_REALTIME on kernels where CLOCK_TAI is unavailable.
    """
    try:
        return time.clock_gettime_ns(time.CLOCK_TAI)
    except (AttributeError, OSError):
        return time.clock_gettime_ns(time.CLOCK_REALTIME)


def pace(target_ns: int) -> int:
    """Sleep until target_ns (monotonic). If we've already passed it, return immediately.

    Resyncs the deadline if we've fallen >100 packet-intervals behind, to
    avoid issuing a huge burst after a stall.
    """
    now = time.monotonic_ns()
    diff = target_ns - now
    if diff > 200_000:  # > 0.2 ms
        time.sleep(diff / 1e9)
    elif diff < -10_000_000:  # > 10 ms behind: resync
        return now
    return target_ns


# ---------------------------------------------------------------------------
# Main streamers
# ---------------------------------------------------------------------------

def stream(sock: socket.socket, interface: str, args, src_mac: bytes) -> int:
    pps = SR_CLASS_PPS[args.sr_class]
    samples_per_packet = max(1, args.sample_rate // pps)
    interval_ns = 1_000_000_000 // pps
    total_samples = int(round(args.duration * args.sample_rate))
    presentation_offset_ns = int(args.presentation_offset * 1_000_000)
    eth_prefix = build_eth_header(args.dest_mac, src_mac, args.vlan, args.pcp)
    gen = SineGenerator(args.freq, args.sample_rate, args.bit_depth,
                        args.amplitude)

    bd_for_payload = 24 if args.format == "am824" else args.bit_depth
    container_bytes = {16: 2, 24: 4, 32: 4}[bd_for_payload]
    pkt_bytes_est = ETH_HLEN + (4 if args.vlan is not None else 0)
    pkt_bytes_est += 24 + (8 if args.format == "am824" else 0)
    pkt_bytes_est += samples_per_packet * args.channels * (4 if args.format == "am824" else container_bytes)

    print(f"AVTP streamer on {interface}")
    print(f"  format={args.format} bit_depth={args.bit_depth} sample_rate={args.sample_rate}")
    print(f"  channels={args.channels} active={args.active_channels} freq={args.freq}Hz "
          f"amp={args.amplitude}")
    print(f"  sr_class={args.sr_class} pps={pps} samples/packet={samples_per_packet}")
    print(f"  duration={args.duration}s total_samples={total_samples}")
    print(f"  dest={format_mac(args.dest_mac)} src={format_mac(src_mac)} "
          f"stream_id={format_stream_id(args.stream_id)}")
    if args.vlan is not None:
        print(f"  vlan={args.vlan} pcp={args.pcp}")
    print(f"  est packet size={pkt_bytes_est}B est rate={pkt_bytes_est*pps*8/1e6:.2f} Mbit/s")
    print()

    seq = 0
    dbc = 0
    sample_idx = 0
    packets_sent = 0
    bytes_sent = 0
    start_ns = time.monotonic_ns()
    target = start_ns
    next_report = start_ns + 1_000_000_000

    try:
        while sample_idx < total_samples:
            this_n = min(samples_per_packet, total_samples - sample_idx)
            mono = gen.next_block(this_n)

            if args.format == "aaf":
                payload = encode_aaf_payload(mono, args.channels,
                                             args.active_channels,
                                             args.bit_depth)
                avtp_ts = (now_tai_ns() + presentation_offset_ns) & 0xFFFFFFFF
                header = build_aaf_header(
                    seq, args.stream_id, avtp_ts, args.channels,
                    args.sample_rate, args.bit_depth, len(payload))
                avtp_pdu = header + payload
            else:  # am824
                pcm_payload = encode_am824_payload(mono, args.channels,
                                                   args.active_channels)
                cip = build_cip_header(dbs=args.channels, dbc=dbc,
                                       sample_rate=args.sample_rate)
                stream_data = cip + pcm_payload
                avtp_ts = (now_tai_ns() + presentation_offset_ns) & 0xFFFFFFFF
                header = build_am824_header(seq, args.stream_id, avtp_ts,
                                            len(stream_data))
                avtp_pdu = header + stream_data
                dbc = (dbc + this_n) & 0xFF

            frame = eth_prefix + avtp_pdu
            if len(frame) < 60:
                frame += b"\x00" * (60 - len(frame))
            raw_send(sock, frame, interface)

            seq = (seq + 1) & 0xFF
            sample_idx += this_n
            packets_sent += 1
            bytes_sent += len(frame)

            target += interval_ns
            target = pace(target)

            if time.monotonic_ns() >= next_report:
                _print_progress(packets_sent, sample_idx, total_samples,
                                bytes_sent, start_ns)
                next_report = time.monotonic_ns() + 1_000_000_000
    except KeyboardInterrupt:
        print("\nInterrupted.")

    elapsed = max(1e-9, (time.monotonic_ns() - start_ns) / 1e9)
    print()
    print("=" * 64)
    print("Streaming summary")
    print("=" * 64)
    print(f"  Packets sent:   {packets_sent}")
    print(f"  Samples sent:   {sample_idx} (target {total_samples})")
    print(f"  Bytes sent:     {bytes_sent}")
    print(f"  Elapsed:        {elapsed:.3f}s")
    print(f"  Actual pps:     {packets_sent/elapsed:.1f} (target {pps})")
    print(f"  Actual sample rate: {sample_idx/elapsed:.1f} Hz (target {args.sample_rate})")
    print(f"  Actual bit rate: {bytes_sent*8/elapsed/1e6:.2f} Mbit/s")
    delivered_fraction = sample_idx / total_samples if total_samples else 1.0
    return 0 if delivered_fraction >= 0.999 else 2


def _print_progress(packets, samples, total, bytes_sent, start_ns):
    elapsed = max(1e-9, (time.monotonic_ns() - start_ns) / 1e9)
    pct = 100.0 * samples / total if total else 100.0
    print(f"  [{elapsed:6.2f}s] {packets:7d} pkts  {samples:9d}/{total} samples "
          f"({pct:5.1f}%)  {bytes_sent*8/elapsed/1e6:6.2f} Mbit/s")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Emit AAF or AM824 PCM AVTP streams containing a sine wave.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-i", "--interface", default="eno1",
                   help="Network interface for transmission (default: eno1).")
    p.add_argument("--format", choices=["aaf", "am824"], default="aaf",
                   help="AVTP audio subtype (default: aaf).")
    p.add_argument("--stream-id", type=parse_stream_id, required=True,
                   help="8-byte AVTP StreamID (colon-hex or 16 hex chars).")
    p.add_argument("--dest-mac", type=parse_mac, default=DEFAULT_DEST_MAC,
                   help=f"Stream destination MAC "
                        f"(default: {format_mac(DEFAULT_DEST_MAC)}).")

    p.add_argument("--freq", type=float, default=1000.0,
                   help="Sine wave frequency in Hz (default: 1000).")
    p.add_argument("--duration", type=float, default=5.0,
                   help="Stream duration in seconds (default: 5).")
    p.add_argument("--amplitude", type=float, default=0.5,
                   help="Amplitude as 0..1 fraction of full scale (default: 0.5).")

    p.add_argument("--sample-rate", type=int, default=48000,
                   help="Audio sample rate in Hz (default: 48000).")
    p.add_argument("--bit-depth", type=int, choices=[16, 24, 32], default=24,
                   help="AAF bit depth (default: 24). AM824 is always 24.")
    p.add_argument("--channels", type=int, default=8,
                   help="Total channels per frame, N (default: 8).")
    p.add_argument("--active-channels", type=int, default=2,
                   help="First M channels filled with sine, rest silent (default: 2).")

    p.add_argument("--sr-class", choices=["A", "B"], default="A",
                   help="SR class: A=8000pps, B=4000pps (default: A).")
    p.add_argument("--vlan", type=int, default=None,
                   help="If set, prepend an 802.1Q tag with this VID.")
    p.add_argument("--pcp", type=int, default=None,
                   help="802.1Q priority (default: 3 for class A, 2 for class B). "
                        "Only used when --vlan is set.")
    p.add_argument("--presentation-offset", type=float, default=2.0,
                   help="Milliseconds added to avtp_timestamp (default: 2.0).")
    return p


def validate(args) -> None:
    if args.channels < 1 or args.channels > 1024:
        die(f"--channels must be 1..1024, got {args.channels}")
    if args.active_channels < 0 or args.active_channels > args.channels:
        die(f"--active-channels must be 0..{args.channels}, got {args.active_channels}")
    if args.freq <= 0:
        die(f"--freq must be > 0, got {args.freq}")
    if args.duration <= 0:
        die(f"--duration must be > 0, got {args.duration}")
    if not (0 < args.amplitude <= 1.0):
        die(f"--amplitude must be in (0, 1], got {args.amplitude}")
    if args.freq > args.sample_rate / 2:
        die(f"--freq {args.freq} exceeds Nyquist ({args.sample_rate/2}) for "
            f"--sample-rate {args.sample_rate}")

    if args.format == "aaf":
        if args.sample_rate not in AAF_NSR:
            die(f"AAF does not support sample rate {args.sample_rate}; "
                f"supported: {sorted(AAF_NSR)}")
    elif args.format == "am824":
        if args.sample_rate not in IEC61883_SFC:
            die(f"AM824 does not support sample rate {args.sample_rate}; "
                f"supported: {sorted(IEC61883_SFC)}")
        if args.bit_depth != 24:
            print(f"Note: AM824 quadlets are 24-bit; --bit-depth {args.bit_depth} "
                  f"will be quantized to 24-bit.", file=sys.stderr)
            args.bit_depth = 24

    if args.pcp is None:
        args.pcp = SR_CLASS_PCP[args.sr_class]


def die(msg: str) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    validate(args)

    try:
        src_mac = get_interface_mac(args.interface)
    except OSError as e:
        die(f"cannot read MAC of interface {args.interface!r}: {e}")
    if src_mac == b"\x00" * 6:
        die(f"interface {args.interface!r} has no MAC address")

    sock = open_tx_socket(args.interface)
    try:
        return stream(sock, args.interface, args, src_mac)
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
