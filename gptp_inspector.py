#!/usr/bin/env python3
"""
gPTP snoop — live inspector for IEEE 802.1AS traffic (ethertype 0x88F7)
on a macOS interface, with direction tagging.

Captures via BPF (bpf_shim.py must sit in the same directory) with
own-transmission visibility enabled, so frames this machine SENDS are
captured too — the default view is exactly those outbound frames, which
is the part no remote capture can attribute cleanly. Requires root
(/dev/bpf).

Per-packet lines show direction, message type, sequence, source port
identity and the interesting body fields (Announce: BTC priority vector;
FollowUp: correction + origin timestamp; Pdelay_Resp: requesting port).
A periodic summary reports per-type counts, measured outbound Sync and
Announce cadence, and the most recent outbound Announce contents.

Usage:
  sudo python3 gptp_inspector.py                     # outbound on en0, Ctrl-C to stop
  sudo python3 gptp_inspector.py -d 30               # 30 s then summary
  sudo python3 gptp_inspector.py --direction both -v # everything, verbose bodies
  sudo python3 gptp_inspector.py -q -d 60            # summary only
"""

import argparse
import signal
import struct
import sys
import time

from bpf_shim import MacBpfSocket, get_mac_address, recv_raw_ts

ETH_P_PTP = 0x88F7

MSG_NAMES = {
    0x0: "Sync",
    0x1: "Delay_Req",
    0x2: "Pdelay_Req",
    0x3: "Pdelay_Resp",
    0x8: "Follow_Up",
    0x9: "Delay_Resp",
    0xA: "Pdelay_Resp_FUp",
    0xB: "Announce",
    0xC: "Signaling",
    0xD: "Management",
}

TIME_SOURCES = {0x10: "ATOMIC", 0x20: "GNSS", 0x30: "TERRESTRIAL",
                0x40: "PTP", 0x50: "NTP", 0x60: "HANDSET",
                0x90: "OTHER", 0xA0: "INTERNAL_OSC"}


def fmt_id(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def fmt_port_identity(b: bytes) -> str:
    return f"{fmt_id(b[0:8])}.{struct.unpack('!H', b[8:10])[0]}"


def fmt_ptp_timestamp(b: bytes) -> str:
    sec = int.from_bytes(b[0:6], "big")
    ns = struct.unpack("!I", b[6:10])[0]
    return f"{sec}.{ns:09d}"


def decode(payload: bytes):
    """Decode a PTPv2 header (+ selected bodies). Returns dict or None."""
    if len(payload) < 34:
        return None
    msg_type = payload[0] & 0x0F
    info = {
        "type": msg_type,
        "name": MSG_NAMES.get(msg_type, f"type{msg_type:#x}"),
        "version": payload[1] & 0x0F,
        "domain": payload[4],
        "flags": struct.unpack("!H", payload[6:8])[0],
        "correction_ns": struct.unpack("!q", payload[8:16])[0] / 65536.0,
        "src_port": fmt_port_identity(payload[20:30]),
        "seq": struct.unpack("!H", payload[30:32])[0],
        "log_interval": struct.unpack("!b", payload[33:34])[0],
    }
    body = payload[34:]
    if msg_type in (0x0, 0x8) and len(body) >= 10:  # Sync / Follow_Up
        info["origin_ts"] = fmt_ptp_timestamp(body[0:10])
    elif msg_type == 0xB and len(body) >= 30:  # Announce
        info["utc_offset"] = struct.unpack("!h", body[10:12])[0]
        info["priority1"] = body[13]
        info["clock_class"] = body[14]
        info["accuracy"] = body[15]
        info["variance"] = struct.unpack("!H", body[16:18])[0]
        info["priority2"] = body[18]
        info["btc_id"] = fmt_id(body[19:27])
        info["steps_removed"] = struct.unpack("!H", body[27:29])[0]
        info["time_source"] = TIME_SOURCES.get(body[29], f"{body[29]:#x}")
    elif msg_type in (0x3, 0xA) and len(body) >= 20:  # Pdelay_Resp (+FUp)
        info["receipt_ts"] = fmt_ptp_timestamp(body[0:10])
        info["req_port"] = fmt_port_identity(body[10:20])
    elif msg_type == 0xC and len(body) >= 10:  # Signaling
        info["target_port"] = fmt_port_identity(body[0:10])
    return info


def brief(info: dict, verbose: bool) -> str:
    extra = ""
    t = info["type"]
    if t == 0xB:
        extra = (f" p1={info['priority1']} class={info['clock_class']}"
                 f" p2={info['priority2']} BTC={info['btc_id']}"
                 f" steps={info['steps_removed']}")
        if verbose:
            extra += (f" acc={info['accuracy']:#x} var={info['variance']}"
                      f" src={info['time_source']}")
    elif t == 0x8:
        extra = f" origin={info['origin_ts']} corr={info['correction_ns']:.0f}ns"
    elif t == 0x0 and verbose:
        extra = f" corr={info['correction_ns']:.0f}ns"
    elif t in (0x3, 0xA):
        extra = f" req={info['req_port']}"
        if verbose and t == 0x3:
            extra += f" receipt={info['receipt_ts']}"
    elif t == 0xC:
        extra = f" target={info['target_port']}"
    if verbose:
        extra += f" logIntv={info['log_interval']}"
    return extra


class Stats:
    def __init__(self):
        self.start = time.time()
        self.counts = {}          # (direction, type name) -> count
        self.sync_out_times = []
        self.ann_out_times = []
        self.last_announce_out = None

    def note(self, direction, info, ts):
        key = (direction, info["name"])
        self.counts[key] = self.counts.get(key, 0) + 1
        if direction == "OUT":
            if info["type"] == 0x0:
                self.sync_out_times.append(ts)
            elif info["type"] == 0xB:
                self.ann_out_times.append(ts)
                self.last_announce_out = info

    @staticmethod
    def _cadence(times):
        if len(times) < 3:
            return None
        gaps = [b - a for a, b in zip(times, times[1:])]
        return sum(gaps) / len(gaps)

    def dump(self):
        dur = time.time() - self.start
        print(f"\n--- summary ({dur:.1f}s) ---")
        for (direction, name), n in sorted(self.counts.items()):
            print(f"  {direction:3s} {name:16s} {n:6d}  ({n / dur:6.2f}/s)")
        sc = self._cadence(self.sync_out_times[-64:])
        if sc:
            print(f"  outbound Sync cadence: {sc * 1000:.1f} ms")
        ac = self._cadence(self.ann_out_times[-16:])
        if ac:
            print(f"  outbound Announce cadence: {ac * 1000:.0f} ms")
        a = self.last_announce_out
        if a:
            print(f"  last outbound Announce: p1={a['priority1']}"
                  f" class={a['clock_class']} acc={a['accuracy']:#x}"
                  f" var={a['variance']} p2={a['priority2']}"
                  f" BTC={a['btc_id']} steps={a['steps_removed']}"
                  f" src={a['time_source']}")
        sys.stdout.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("-i", "--interface", default="en0")
    ap.add_argument("-d", "--duration", type=float, default=None,
                    help="stop after N seconds (default: run until Ctrl-C)")
    ap.add_argument("-n", "--count", type=int, default=None,
                    help="stop after N matching packets")
    ap.add_argument("--direction", choices=["out", "in", "both"],
                    default="out",
                    help="which frames to show (default: out = sent by "
                         "this machine)")
    ap.add_argument("-t", "--type", action="append", default=None,
                    metavar="NAME",
                    help="only show these message types (repeatable), "
                         "e.g. -t Sync -t Announce")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="no per-packet lines, just the summary")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--summary-interval", type=float, default=None,
                    help="print a rolling summary every N seconds")
    args = ap.parse_args()

    my_mac = get_mac_address(args.interface)
    sock = MacBpfSocket(args.interface, ethertype=ETH_P_PTP)
    stats = Stats()
    wanted = set(t.lower() for t in args.type) if args.type else None

    stop = []
    signal.signal(signal.SIGINT, lambda *a: stop.append(1))

    print(f"gPTP snoop on {args.interface} (mac {fmt_id(my_mac)}), "
          f"direction={args.direction}", flush=True)

    deadline = time.time() + args.duration if args.duration else None
    next_summary = (time.time() + args.summary_interval
                    if args.summary_interval else None)
    shown = 0
    while not stop:
        if deadline and time.time() >= deadline:
            break
        if next_summary and time.time() >= next_summary:
            stats.dump()
            next_summary += args.summary_interval
        r = recv_raw_ts(sock, timeout=0.2)
        if r is None:
            continue
        ts, dst, src, ethertype, payload = r
        if ethertype != ETH_P_PTP:
            continue
        direction = "OUT" if src == my_mac else "IN"
        if args.direction == "out" and direction != "OUT":
            continue
        if args.direction == "in" and direction != "IN":
            continue
        info = decode(payload)
        if info is None:
            continue
        stats.note(direction, info, ts)
        if wanted and info["name"].lower() not in wanted:
            continue
        shown += 1
        if not args.quiet:
            wall = time.strftime("%H:%M:%S", time.localtime(ts))
            frac = f"{ts % 1:.6f}"[1:]
            print(f"{wall}{frac} {direction:3s} {info['name']:16s}"
                  f" seq={info['seq']:5d} src={info['src_port']}"
                  f"{brief(info, args.verbose)}", flush=True)
        if args.count and shown >= args.count:
            break

    stats.dump()
    sock.close()


if __name__ == "__main__":
    main()
