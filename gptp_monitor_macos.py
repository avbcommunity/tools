#!/usr/bin/env python3
"""
gPTP transmit monitor for macOS — reports the Mac's OUTBOUND gPTP activity.

macOS generates 802.1AS frames inside IOgPTPPlugin.kext and hands them to
the NIC driver's realtime transmit queue, BELOW every packet-capture tap the
system offers (BPF, pktap) — which is why Wireshark on a Mac shows only
inbound PTP. The kext, however, publishes per-port counters and state in the
IORegistry (IOTimeSyncEthernetPort). This tool polls those and reports:

- outbound rates: Sync, Announce, Pdelay_Req, Pdelay_Resp(+FollowUp),
  computed from counter deltas (attempted vs transmitted where available)
- port state: asCapable, link propagation delay, sync/announce intervals,
  inferred role (transmitting Sync = timeTransmitter for the link)
- clock identity and priority vector, local and received
- RX-discard reason counters, flagged whenever they move

No root required (the IORegistry is world-readable).

Usage:
  python3 gptp_monitor_macos.py                 # all timesync ports, 2 s cadence
  python3 gptp_monitor_macos.py -i 5 -n 12      # 5 s cadence, 12 samples
  python3 gptp_monitor_macos.py --once          # one full property dump per port
  python3 gptp_monitor_macos.py --mac d0:11     # only ports whose MAC matches
"""

import argparse
import plistlib
import subprocess
import sys
import time

TX_COUNTERS = [
    ("AttemptedSyncCounter", "sync"),
    ("AttemptedAnnounceCounter", "announce"),
    ("AttemptedDelayRequestCounter", "delay_req"),
    ("AttemptedPDelayRequestCounter", "pdelay_req"),
    ("AttemptedPDelayResponseCounter", "pdelay_resp"),
    ("AttemptedPDelayResponseFollowUpCounter", "pdelay_rfup"),
    ("TransmittedSyncCounter", "sync_tx_ok"),
    ("TransmittedDelayResponseCounter", "delay_resp"),
]

RX_COUNTERS = [
    ("ReceivedSyncCounter", "sync"),
    ("ReceivedPDelayRequestCounter", "pdelay_req"),
    ("ReceivedPDelayResponseCounter", "pdelay_resp"),
    ("ProcessedAnnounceCounter", "announce"),
    ("ProcessedSyncCounter", "sync_used"),
]


def read_ports():
    out = subprocess.run(
        ["ioreg", "-a", "-r", "-d1", "-c", "IOTimeSyncEthernetPort"],
        capture_output=True).stdout
    if not out.strip():
        return []
    data = plistlib.loads(out)
    return data if isinstance(data, list) else [data]


def eui64(v):
    if not isinstance(v, int):
        return str(v)
    b = (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
    return ":".join(f"{x:02x}" for x in b)


def mac_str(v):
    if isinstance(v, bytes):
        return ":".join(f"{x:02x}" for x in v)
    return str(v)


def log_interval(v):
    """uint8-encoded signed log2 interval -> human period."""
    if not isinstance(v, int):
        return "?"
    if v > 127:
        v -= 256
    period = 2.0 ** v
    return f"{period * 1000:.0f}ms" if period < 1 else f"{period:.0f}s"


def discard_counters(props):
    return {k: v for k, v in props.items()
            if k.startswith("RxPacketDiscard") and isinstance(v, int)}


def port_header(p):
    mac = mac_str(p.get("SourceMACAddress", b""))
    asc = "Y" if p.get("ASCapable") else "N"
    pdel = p.get("LinkPropagationDelay", "?")
    sync_i = log_interval(p.get("LocalSyncLogMeanInterval", 0))
    return (f"port {mac} asCapable={asc} propDelay={pdel}ns "
            f"syncInterval={sync_i} "
            f"clockId={eui64(p.get('ClockIdentifier', 0))}")


def priority_vector(p):
    local = (f"local p1={p.get('ClockPriority1')} "
             f"class={p.get('ClockClass', p.get('ReceivedClockClass'))} "
             f"acc={p.get('ClockAccuracy')} "
             f"var={p.get('OffsetScaledLogVariance')}")
    rx = (f"received BTC={eui64(p.get('ReceivedGrandmasterID', 0))} "
          f"p1={p.get('ReceivedClockPriority1')} "
          f"class={p.get('ReceivedClockClass')} "
          f"steps={p.get('StepsRemoved')}")
    return local, rx


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("-i", "--interval", type=float, default=2.0)
    ap.add_argument("-n", "--samples", type=int, default=None)
    ap.add_argument("--mac", default=None,
                    help="only ports whose MAC contains this substring")
    ap.add_argument("--once", action="store_true",
                    help="dump every property of each port once and exit")
    args = ap.parse_args()

    ports = read_ports()
    if args.mac:
        ports = [p for p in ports
                 if args.mac.lower().replace(":", "") in
                 mac_str(p.get("SourceMACAddress", b"")).replace(":", "")]
    if not ports:
        print("no IOTimeSyncEthernetPort objects found", file=sys.stderr)
        sys.exit(1)

    if args.once:
        for p in ports:
            print(port_header(p))
            for k in sorted(p):
                if k == "IOGeneralInterest":
                    continue
                print(f"  {k} = {p[k]}")
        return

    prev = {}
    prev_disc = {}
    sample = 0
    while args.samples is None or sample < args.samples:
        t0 = time.time()
        for idx, p in enumerate(read_ports()):
            mac = mac_str(p.get("SourceMACAddress", b""))
            if args.mac and (args.mac.lower().replace(":", "")
                             not in mac.replace(":", "")):
                continue
            key = (mac, idx)
            now = {name: p.get(k, 0) for k, name in TX_COUNTERS}
            now_rx = {name: p.get(k, 0) for k, name in RX_COUNTERS}
            disc = discard_counters(p)
            if key in prev:
                dt = args.interval
                last, last_rx = prev[key]
                tx_parts = []
                for _, name in TX_COUNTERS:
                    d = now[name] - last[name]
                    if d:
                        tx_parts.append(f"{name} {d / dt:.1f}/s")
                rx_parts = []
                for _, name in RX_COUNTERS:
                    d = now_rx[name] - last_rx[name]
                    if d:
                        rx_parts.append(f"{name} {d / dt:.1f}/s")
                role = ("timeTransmitter" if now["sync"] > last["sync"]
                        else "timeReceiver" if now_rx["sync"] > last_rx["sync"]
                        else "quiet")
                stamp = time.strftime("%H:%M:%S")
                print(f"{stamp} [{idx}] {port_header(p)} role={role}")
                print(f"   TX: {'  '.join(tx_parts) if tx_parts else '(none)'}")
                if rx_parts:
                    print(f"   RX: {'  '.join(rx_parts)}")
                moved = {k: v - prev_disc.get(key, {}).get(k, v)
                         for k, v in disc.items()}
                moved = {k: d for k, d in moved.items() if d}
                if moved:
                    print(f"   DISCARDS: " + "  ".join(
                        f"{k.replace('RxPacketDiscard', '')} +{d}"
                        for k, d in moved.items()))
                if sample % 10 == 1:
                    local, rx = priority_vector(p)
                    print(f"   {local}")
                    print(f"   {rx}")
                sys.stdout.flush()
            prev[key] = (now, now_rx)
            prev_disc[key] = disc
        sample += 1
        time.sleep(max(0.0, args.interval - (time.time() - t0)))


if __name__ == "__main__":
    main()
