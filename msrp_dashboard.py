#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["rich>=13"]
# ///
"""
msrp_dashboard.py - live TUI dashboard of MSRP / SRP stream reservations.

Sniffs MSRP (MRP, EtherType 0x22ea) with tshark and shows, per Stream ID, the
current Talker declaration (Advertise / Failed) and Listener declaration
(Ready / Asking Failed / Ready Failed), whether the reservation is complete,
how fresh each declaration is, and a rolling event log so you can watch
reservations *flap* in real time.

Why: a Milan Talker only transmits while a matching Listener Ready is
registered (IEEE 1722.1 / Milan 5.5). Intermittent audio with a "connected"
controller is usually the SRP reservation flapping underneath ACMP - this
tool makes that visible.

Data model per Stream ID (8 bytes = talker MAC + 2-byte unique id):
  Talker:   ADV (green) | FAIL:<code> (red)   + SR class, dest MAC, latency
  Listener: RDY (green) | ASK-FAIL / RDY-FAIL (red) | IGN
  Rsv:      YES  = Talker Advertise + Listener Ready, both seen within one
                   guaranteed MRP re-declaration cycle (leaveall-max).
            YES? = still held but not re-seen recently (between leaveall-max and
                   leaveall-max + LeaveTime) -- likely a tap / re-declaration
                   gap, not a real dropout.
            no   = torn down: an explicit MRP Leave (debounced ~2 s so a
                   transient Mt/re-Join isn't misread; per Milan 4.2.7.2.2), a
                   Talker Failed, a non-Ready listener, or no refresh past the
                   leaveall-max + LeaveTime ceiling.
  Reservation lifetime follows Milan v1.3 Table 4.3 (LeaveTime 5 s, leavealltimer
  10-15 s), which overrides 802.1Q Table 10-7 defaults (LeaveTime 0.6-1 s).

Usage:
  # live on one tap (dumpcap caps let the wireshark group run without sudo):
  uv run msrp_dashboard.py -i enp2s0f2

  # watch several taps at once to see where a reservation dies:
  uv run msrp_dashboard.py -i enp2s0f2 -i enp2s0f0 -i enp2s0f3

  # replay / analyse a saved capture:
  uv run msrp_dashboard.py -r some_msrp.pcap

Options:
  -i/--interface IFACE  capture interface (repeatable). Required unless -r.
  -r/--read FILE        read from a pcap/pcapng instead of live capture.
  --confirm SECONDS     freshness window for "confirmed" (default = leaveall-max,
                        one guaranteed re-declaration cycle).
  --leavetime SECONDS   MSRP LeaveTime (default 5, Milan).
  --leaveall-max SECONDS  max leavealltimer (default 15.5, Milan). Lost ceiling
                        = leaveall-max + leavetime.
  --forget SECONDS      drop a stream row this long after its last update
                        (default 60).
  --filter BPF          override the capture filter (default: MSRP only).
  --no-color            plain output.

Keys: Ctrl-C to quit.
"""
import argparse
import os
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import deque

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    sys.exit("This tool needs 'rich'. Run it with:  uv run msrp_dashboard.py ...")

MSRP_BPF = "ether proto 0x22ea"

ATTR_TALKER_ADVERTISE = 1
ATTR_TALKER_FAILED = 2
ATTR_LISTENER = 3
ATTR_DOMAIN = 4
ATTR_LEAVEALL = "leaveall"  # sentinel yielded once per packet carrying a LeaveAll

# IEEE 802.1Q-2018 Table 35-6 (abbreviated)
FAILURE_CODES = {
    1: "Insufficient bandwidth",
    2: "Insufficient bridge resources",
    3: "Insufficient bandwidth for Traffic Class",
    4: "StreamID in use by another Talker",
    5: "Stream dest address in use",
    6: "Pre-empted by higher rank",
    7: "Reported latency changed",
    8: "Egress port not AVB-capable",
    9: "Use a different dest address",
    10: "Out of MSRP resources",
    11: "Out of MMRP resources",
    12: "Cannot store dest address",
    13: "Priority is not an SR Class",
    14: "MaxFrameSize too large",
    15: "MaxFanInPorts exceeded",
    16: "FirstValue/dest changed",
    17: "VLAN blocked on egress",
    18: "VLAN tagging disabled on egress",
    19: "SR class priority mismatch",
}

# Listener FourPackedEvent
LISTENER_DECL = {0: "IGN", 1: "ASK-FAIL", 2: "RDY", 3: "RDY-FAIL"}
# MRP three-packed AttributeEvent (applicant)
ATTR_EVENT = {0: "New", 1: "JoinIn", 2: "In", 3: "JoinMt", 4: "Mt", 5: "Leave"}
# MRP three-packed applicant event 5 = Leave = the attribute is explicitly
# withdrawn. Mt (4, "empty") is deliberately NOT treated as a withdrawal: it
# appears transiently in normal operation (e.g. around LeaveAlls), interspersed
# with JoinMt/JoinIn, so counting it as a teardown produced false "explicit
# Leave" events. Even a real Leave is debounced by LEAVE_GRACE_S so a transient
# one that is immediately re-Joined does not count.
MRP_LEAVE_EVENT = 5
LEAVE_GRACE_S = 2.0

# Reservation lifetime per Milan v1.3 Table 4.3 (overrides 802.1Q Table 10-7):
#   LeaveTime default 5 s (registrar holds a registration this long after a
#   LeaveAll before removing it); leavealltimer 10-15 s (tolerance to 15.5 s).
# So a registration survives at most (leaveAll_max + LeaveTime) after its last
# refresh -- UNLESS an explicit Leave (MRP Mt/Leave) removes it immediately
# (Milan 4.2.7.2.2 changes the registrar SM to IN/rLv! -> MT). We therefore hold
# a reservation as valid for that whole window (shown "unconfirmed" once past the
# confirm window) so a tap/re-declaration gap is not misread as a dropout.
MILAN_LEAVETIME_S = 5.0
MILAN_LEAVEALL_MAX_S = 15.5


def sr_class(priority):
    # SR class A uses priority 3, class B priority 2 (802.1Q default mapping).
    return {3: "A", 2: "B"}.get(priority, "?")


def stream_key(hex_id):
    """0xe8f60ae097210000 -> 'e8:f6:0a:e0:97:21/0000' (talker MAC / unique id)."""
    h = (hex_id or "").lower().replace("0x", "").rjust(16, "0")
    mac = ":".join(h[i:i + 2] for i in range(0, 12, 2))
    return f"{mac}/{h[12:16]}"


def _int(v, base=10, default=None):
    try:
        return int(v, base)
    except (TypeError, ValueError):
        return default


class Model:
    def __init__(self, confirm, lost, forget):
        self.confirm = confirm  # within this, a re-seen declaration is "confirmed"
        self.lost = lost        # past this with no refresh, the reservation is gone
        self.forget = forget
        self.lock = threading.Lock()
        self.streams = {}  # key -> dict(talker=..., listener=..., ...)
        self._leaveall_seen = {}  # src -> last-logged time (dedupe multi-tap)
        self.events = deque(maxlen=300)
        self.packets = 0
        self.started = time.monotonic()

    def _log(self, kind, key, msg):
        self.events.append((time.strftime("%H:%M:%S"), kind, key, msg))

    def apply(self, attr_type, rec, src, src_name, iface, now):
        if attr_type == ATTR_LEAVEALL:
            # A LeaveAll is a real event (the periodic re-declaration trigger)
            # but not a stream. Tag it with the attribute it came from so the
            # log says whether it was in a talker or listener message. Rate-limit
            # per (source, scope) so the same one seen on several taps -- or a
            # talker and listener LeaveAll in one burst -- log cleanly.
            scope = {ATTR_TALKER_ADVERTISE: "talker", ATTR_TALKER_FAILED: "talker",
                     ATTR_LISTENER: "listener", ATTR_DOMAIN: "domain"}.get(
                         rec.get("scope"), "?")
            gate = (src, scope)
            if now - self._leaveall_seen.get(gate, 0) >= 2.0:
                self._leaveall_seen[gate] = now
                self._log("leaveall", src or "?",
                          f"LeaveAll ({scope})  [{iface}]")
            return
        key = stream_key(rec.get("stream_id"))
        s = self.streams.get(key)
        if s is None:
            s = {"talker": None, "listeners": {}, "first": now}
            self.streams[key] = s

        if attr_type in (ATTR_TALKER_ADVERTISE, ATTR_TALKER_FAILED):
            failed = attr_type == ATTR_TALKER_FAILED
            new = {
                "src": src, "src_name": src_name, "iface": iface, "seen": now,
                "failed": failed,
                "cls": sr_class(rec.get("priority")),
                "dest": rec.get("dest"),
                "latency": rec.get("latency"),
                "failure": rec.get("failure"),
                "bridge": rec.get("bridge"),
                "event": rec.get("tevent"),
                "leave_at": now if rec.get("tevent") == MRP_LEAVE_EVENT else None,
            }
            old = s["talker"]
            was = _talker_str(old) if old else "none"
            s["talker"] = new
            now_s = _talker_str(new)
            if was != now_s:
                self._log("talker", key, f"{was} -> {now_s}  [{iface}]")
        elif attr_type == ATTR_LISTENER:
            # A stream can have many listeners; key them by declaring MAC so each
            # gets its own row and its own reservation state, rather than the
            # newest declaration overwriting the previous listener.
            decl = rec.get("ldecl")
            lmac = src or "?"
            l = s["listeners"].get(lmac)
            was = LISTENER_DECL.get(l["decl"], "?") if l else "none"
            if l is None:
                l = {"_state": None}
                s["listeners"][lmac] = l
            l.update({
                "src": src, "src_name": src_name, "iface": iface, "seen": now,
                "decl": decl, "event": rec.get("tevent"),
                "leave_at": now if rec.get("tevent") == MRP_LEAVE_EVENT else None,
            })
            now_s = LISTENER_DECL.get(decl, "?")
            if was != now_s:
                self._log("listener", key,
                          f"L:{was} -> L:{now_s}  {src or '?'}  [{iface}]")
        else:
            return
        self._check_state(key, s, now)

    def _check_state(self, key, s, now):
        # Reservation state is per (talker, listener) pair: evaluate each listener
        # of the stream independently and log its own UP/LOST transitions.
        for l in s["listeners"].values():
            state, reason = _rsv_state(s["talker"], l, self.confirm, self.lost, now)
            prev = l.get("_state")
            if state == prev:
                continue
            l["_state"] = state
            l["_reserved"] = state in ("confirmed", "unconfirmed")
            who = l["src"] or "?"
            if state == "confirmed":
                self._log("reserve", key, f"RESERVATION UP (confirmed)  {who}")
            elif state == "unconfirmed":
                self._log("reserve", key, f"unconfirmed - {reason}  {who}")
            elif state == "lost":
                self._log("reserve", key, f"RESERVATION LOST - {reason}  {who}")
            # state == "none": nothing to report

    def prune(self, now):
        with self.lock:
            for key, s in list(self.streams.items()):
                # drop listeners we haven't heard from in a while
                for lmac, l in list(s["listeners"].items()):
                    if now - l["seen"] > self.forget:
                        del s["listeners"][lmac]
                last = max(
                    [s["talker"]["seen"] if s["talker"] else 0]
                    + [l["seen"] for l in s["listeners"].values()]
                    + [0])
                if now - last > self.forget:
                    del self.streams[key]
                    continue
                # re-evaluate state even without a new packet (ages/timeouts)
                self._check_state(key, s, now)


def _talker_str(t):
    if not t:
        return "none"
    if t["failed"]:
        fc = t.get("failure")
        return f"FAIL:{fc if fc is not None else '?'}"
    return f"ADV/{t.get('cls', '?')}"


def _rsv_state(t, l, confirm, lost, now):
    """Reservation state for one (talker, listener) pair: 'confirmed' |
    'unconfirmed' | 'lost' | 'none'.

    'unconfirmed' = a Talker-Advertise + Listener-Ready pair not re-seen within
    `confirm`, but still within the leaveAll+LeaveTime ceiling `lost`, so the
    switch almost certainly still holds it (likely just a tap/re-declaration
    gap). An explicit MRP Leave/Mt, a Talker Failed, or a non-Ready listener
    drops straight to 'lost'."""
    if not t or not l:
        return ("none", "no talker+listener pair")
    if t["failed"]:
        return ("lost", "talker Failed")
    if l.get("decl") != 2:  # not Ready
        return ("lost", "listener " + LISTENER_DECL.get(l.get("decl"), "?"))
    if t.get("leave_at") and now - t["leave_at"] >= LEAVE_GRACE_S:
        return ("lost", "talker Leave (explicit)")
    if l.get("leave_at") and now - l["leave_at"] >= LEAVE_GRACE_S:
        return ("lost", "listener Leave (explicit)")
    age = now - min(t["seen"], l["seen"])
    if age <= confirm:
        return ("confirmed", "")
    if age <= lost:
        return ("unconfirmed", f"no refresh {int(age)}s")
    return ("lost", f"no refresh {int(age)}s > {lost:.0f}s ceiling")


def parse_packet(pkt):
    """Yield (attr_type, rec, src, src_name, iface) for each MSRP declaration."""
    src = src_name = iface = None
    for f in pkt.iter("field"):
        n = f.get("name")
        if n == "eth.src":
            src = f.get("show")
        elif n == "eth.src_resolved":
            src_name = f.get("show")
        elif n == "frame.interface_name":
            iface = f.get("show")
    if iface is None:
        iface = "-"

    leaveall_scopes = set()  # attribute types that carried a LeaveAll this pkt
    for msg in pkt.iter("field"):
        if msg.get("name") != "mrp-msrp.message":
            continue
        attr_type = None
        for a in msg.iter("field"):
            if a.get("name") == "mrp-msrp.attribute_type":
                attr_type = _int(a.get("show"))
                break
        if attr_type is None:
            continue
        for va in msg.iter("field"):
            if va.get("name") != "mrp-msrp.vector_attribute":
                continue
            rec = {}
            for f in va.iter("field"):
                n = f.get("name")
                sh = f.get("show")
                if n == "mrp-msrp.stream_id":
                    rec["stream_id"] = sh
                elif n == "mrp-msrp.number_of_values":
                    rec["nvals"] = _int(sh)
                elif n == "mrp-msrp.leave_all_event":
                    rec["leaveall"] = _int(sh)
                elif n == "mrp-msrp.stream_da":
                    rec["dest"] = sh
                elif n == "mrp-msrp.vlan_id":
                    rec["vlan"] = _int(sh, 16)
                elif n == "mrp-msrp.priority":
                    rec["priority"] = _int(sh)
                elif n == "mrp-msrp.accumulated_latency":
                    rec["latency"] = _int(sh)
                elif n == "mrp-msrp.failure_code":
                    rec["failure"] = _int(sh)
                elif n == "mrp-msrp.failure_bridge_id":
                    rec["bridge"] = sh
                elif n == "mrp-msrp.four_packed_event":
                    rec["ldecl"] = _int(sh)
                elif n == "mrp-msrp.three_packed_event":
                    rec["tevent"] = _int(sh)
            # Skip phantom streams. A LeaveAll (NumberOfValues=0) and any other
            # empty/padding vector get an all-zero First Value from tshark. A
            # real Stream ID always embeds the talker's MAC, so an all-zero (or
            # missing) Stream ID is never a real stream -- reject it outright,
            # which also covers LeaveAll markers regardless of how tshark renders
            # them.
            if rec.get("leaveall"):
                leaveall_scopes.add(attr_type)
            sid = rec.get("stream_id")
            zero_id = not sid or set(sid.lower().replace("0x", "")) <= {"0"}
            if "stream_id" in rec and rec.get("nvals") != 0 and not zero_id:
                yield attr_type, rec, src, src_name, iface

    # A LeaveAll is a real, useful MRP event (the periodic re-declaration
    # trigger) but NOT a stream. Its bit lives in one attribute's vector header,
    # so surface a marker per attribute type that carried it, tagged with that
    # scope (talker / listener) so the event log says which message it was in.
    for at in sorted(leaveall_scopes):
        yield ATTR_LEAVEALL, {"scope": at}, src, src_name, iface


def pdml_packets(stream):
    buf, in_pkt = [], False
    for line in stream:
        if "<packet>" in line:
            in_pkt, buf = True, [line]
        elif in_pkt:
            buf.append(line)
            if "</packet>" in line:
                in_pkt = False
                try:
                    yield ET.fromstring("".join(buf))
                except ET.ParseError:
                    pass
                buf = []


def reader(proc, model, stop):
    for pkt in pdml_packets(proc.stdout):
        if stop.is_set():
            break
        now = time.monotonic()
        with model.lock:
            model.packets += 1
            for attr_type, rec, src, src_name, iface in parse_packet(pkt):
                model.apply(attr_type, rec, src, src_name, iface, now)


def render(model, ifaces, source_desc, confirm):
    now = time.monotonic()
    with model.lock:
        streams = sorted(model.streams.items())
        packets = model.packets
        events = list(model.events)[-14:]
        up = int(now - model.started)

    confirmed = sum(1 for _, s in streams for l in s["listeners"].values()
                    if l.get("_state") == "confirmed")
    unconfirmed = sum(1 for _, s in streams for l in s["listeners"].values()
                      if l.get("_state") == "unconfirmed")
    failed = sum(1 for _, s in streams if s["talker"] and s["talker"]["failed"])

    tbl = Table(expand=True, pad_edge=False, box=None, header_style="bold")
    tbl.add_column("Stream ID (talker/uid) / listener", no_wrap=True)
    tbl.add_column("State", justify="center")
    tbl.add_column("Rsv", justify="center")
    tbl.add_column("Dest MAC", no_wrap=True)
    tbl.add_column("Lat(ns)", justify="right")
    tbl.add_column("age", justify="right", no_wrap=True)
    tbl.add_column("if", no_wrap=True)

    for key, s in streams:
        t = s["talker"]
        listeners = s["listeners"]
        # --- stream header row: the talker's advertise for this Stream ID ---
        if t:
            t_fresh = now - t["seen"] <= confirm
            if t["failed"]:
                fc = FAILURE_CODES.get(t.get("failure"), f"code {t.get('failure')}")
                t_cell = Text(f"FAIL/{t.get('cls','?')}", style="bold red")
                fail_note = fc
            else:
                t_cell = Text(f"ADV/{t.get('cls','?')}",
                              style="green" if t_fresh else "yellow")
                fail_note = ""
            dest = t.get("dest") or "-"
            lat = str(t.get("latency") if t.get("latency") is not None else "-")
            t_age = f"{int(now - t['seen'])}s"
            t_iface = t["iface"]
        else:
            t_cell, dest, lat, t_age, t_iface, fail_note = (
                Text("-"), "-", "-", "-", "-", "")

        any_rsv = any(l.get("_reserved") for l in listeners.values())
        id_txt = Text(key, style="bold" if any_rsv else "")
        if fail_note:
            id_txt = id_txt + Text(f"  ({fail_note})", style="red")
        tbl.add_row(id_txt, t_cell, Text(""), dest, lat, t_age, t_iface)

        # --- one indented sub-row per listener of this stream ---
        if not listeners:
            tbl.add_row(Text("  └ (no listener)", style="dim"),
                        "", "", "", "", "", "")
        for lmac, l in sorted(listeners.items()):
            l_fresh = now - l["seen"] <= confirm
            d = LISTENER_DECL.get(l.get("decl"), "?")
            l_cell = Text(d, style="green" if (d == "RDY" and l_fresh) else (
                "yellow" if not l_fresh else "bold red"))
            lstate = l.get("_state")
            if lstate == "confirmed":
                rsv = Text("YES", style="bold green")
            elif lstate == "unconfirmed":
                rsv = Text("YES?", style="bold yellow")
            elif lstate == "lost":
                rsv = Text("no", style="red")
            else:  # "none": listener seen but no matching talker advertise yet
                rsv = Text("-", style="dim")
            name = Text(f"  └ {l['src'] or '?'}", style="" if l_fresh else "dim")
            tbl.add_row(name, l_cell, rsv, "", "",
                        f"{int(now - l['seen'])}s", l["iface"])

    if not streams:
        tbl.add_row(Text("(waiting for MSRP traffic...)", style="dim"),
                    "", "", "", "", "", "")

    hdr = Text.assemble(
        ("MSRP / SRP reservation monitor  ", "bold cyan"),
        (f"src={source_desc}  ", "white"),
        (f"pkts={packets}  ", "white"),
        (f"streams={len(streams)}  ", "white"),
        ("reserved=", "white"), (f"{confirmed}", "bold green"),
        ("+", "dim"), (f"{unconfirmed}?  ", "bold yellow"),
        ("talker-failed=", "white"), (f"{failed}  ", "bold red"),
        (f"up={up}s", "dim"),
    )
    legend = Text("  State: ADV=talker advertising  FAIL=bridge rejected  "
                  "RDY=listener ready  ASK-FAIL/RDY-FAIL=listener refused     "
                  "Rsv (per listener): YES=confirmed  YES?=held, not re-seen  "
                  "no=lost / explicit Leave",
                  style="dim")

    ev = Table(expand=True, pad_edge=False, box=None, header_style="bold")
    ev.add_column("Time", no_wrap=True)
    ev.add_column("Event", no_wrap=True)
    ev.add_column("Stream ID / MAC", no_wrap=True)
    ev.add_column("Detail")
    color = {"reserve": "cyan", "talker": "green", "listener": "magenta",
             "leaveall": "blue"}
    for ts, kind, key, msg in events:
        stylemsg = ("bold red" if "LOST" in msg or "FAIL" in msg else
                    "bold green" if "UP" in msg else
                    "yellow" if "unconfirmed" in msg else "")
        ev.add_row(Text(ts, style="dim"),
                   Text(kind, style=color.get(kind, "white")),
                   Text(key, style="white"),
                   Text(msg, style=stylemsg))
    if not events:
        ev.add_row(Text("(no state changes yet)", style="dim"), "", "", "")

    return Group(
        Panel(Group(hdr, legend), border_style="cyan"),
        tbl,
        Panel(ev, title="events (newest last) - watch for RESERVATION LOST/UP flaps",
              border_style="grey37"),
    )


def build_cmd(args):
    if args.read:
        cmd = ["tshark", "-r", args.read, "-T", "pdml"]
        desc = os.path.basename(args.read)
    else:
        cmd = ["tshark"]
        for i in args.interface:
            # -f is a PER-INTERFACE capture filter: it binds to the interface
            # named by the immediately preceding -i. It must be repeated after
            # every -i, or only the last interface gets filtered and the rest
            # capture all traffic (e.g. the VLAN-tagged audio stream).
            cmd += ["-i", i, "-f", args.filter]
        cmd += ["-T", "pdml", "-l"]
        desc = ",".join(args.interface)
    return cmd, desc


def main():
    ap = argparse.ArgumentParser(
        description="Live TUI dashboard of MSRP/SRP talker & listener reservations.")
    ap.add_argument("-i", "--interface", action="append", default=[],
                    help="capture interface (repeatable)")
    ap.add_argument("-r", "--read", help="read from a pcap/pcapng instead of live")
    ap.add_argument("--confirm", type=float, default=None,
                    help="seconds within which a re-seen declaration counts as "
                         "freshly confirmed (default = --leaveall-max, i.e. one "
                         "guaranteed MRP re-declaration cycle). Between this and "
                         "leaveall-max+leavetime a reservation shows 'unconfirmed' "
                         "(YES?) rather than lost.")
    ap.add_argument("--leavetime", type=float, default=MILAN_LEAVETIME_S,
                    help=f"MSRP LeaveTime in seconds (Milan default {MILAN_LEAVETIME_S})")
    ap.add_argument("--leaveall-max", type=float, default=MILAN_LEAVEALL_MAX_S,
                    dest="leaveall_max",
                    help=f"max leavealltimer in seconds (Milan tolerance {MILAN_LEAVEALL_MAX_S})")
    ap.add_argument("--forget", type=float, default=60.0,
                    help="seconds until an idle stream row is dropped (default 60)")
    ap.add_argument("--filter", default=MSRP_BPF, help="capture BPF filter")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if not args.read and not args.interface:
        ap.error("give at least one -i/--interface, or -r/--read FILE")

    cmd, desc = build_cmd(args)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except FileNotFoundError:
        sys.exit("tshark not found - install wireshark/tshark.")

    # "Confirmed" = seen within one guaranteed re-declaration cycle (a healthy
    # applicant re-sends at least every LeaveAll). A registration then survives
    # at most one LeaveAll plus the LeaveTime after its last refresh, unless an
    # explicit Leave tears it down sooner.
    confirm = args.confirm if args.confirm is not None else args.leaveall_max
    lost = args.leaveall_max + args.leavetime
    model = Model(confirm, lost, args.forget)
    stop = threading.Event()
    rt = threading.Thread(target=reader, args=(proc, model, stop), daemon=True)
    rt.start()

    console = Console(no_color=args.no_color)
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        with Live(console=console, screen=console.is_terminal,
                  refresh_per_second=4, auto_refresh=False) as live:
            while not stop.is_set():
                model.prune(time.monotonic())
                live.update(render(model, args.interface, desc, confirm),
                            refresh=True)
                if args.read and proc.poll() is not None and not rt.is_alive():
                    time.sleep(1.0)  # let final frame show for pcap replay
                    break
                time.sleep(0.25)
    finally:
        stop.set()
        try:
            proc.terminate()
        except Exception:
            pass
    # brief summary on exit
    with model.lock:
        rsv = sum(1 for s in model.streams.values()
                  for l in s["listeners"].values()
                  if l.get("_state") in ("confirmed", "unconfirmed"))
        console.print(f"\n{len(model.streams)} streams seen, {rsv} reserved, "
                      f"{model.packets} MSRP packets.")


if __name__ == "__main__":
    main()
