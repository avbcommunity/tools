#!/usr/bin/env python3
"""
MRP Applicant - MSRP/MVRP test applicant for AVB networks.

Acts as an MRP applicant that declares Talker, Listener, Domain, and VLAN
attributes to a connected switch via MSRP (IEEE 802.1Qat) and MVRP
(IEEE 802.1ak), decodes received MRPDUs, and reports registration outcomes
back to the user.

Protocol references:
  - IEEE 802.1Q-2022 Clause 10 (MRP / MRPDU encoding)
  - IEEE 802.1Q-2022 Clause 11 (MVRP)
  - IEEE 802.1Q-2022 Clause 35 (MSRP)

Usage:
  sudo python3 mrp_applicant.py -i eno1 monitor --duration 10
  sudo python3 mrp_applicant.py -i eno1 mvrp 2 --duration 5
  sudo python3 mrp_applicant.py -i eno1 talker 00:1b:21:01:02:03:00:01 --duration 5
  sudo python3 mrp_applicant.py -i eno1 listener 00:1b:21:01:02:03:00:01 --duration 5
  sudo python3 mrp_applicant.py -i eno1 domain --sr-class A --duration 5
"""

import argparse
import errno
import fcntl
import select
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ETH_P_ALL = 0x0003
ETH_P_VLAN = 0x8100
ETH_P_MVRP = 0x88F5
ETH_P_MSRP = 0x22EA

# Reserved nearest-customer-bridge multicast addresses.
MVRP_DEST_MAC = b"\x01\x80\xc2\x00\x00\x21"
MSRP_DEST_MAC = b"\x01\x80\xc2\x00\x00\x0e"

ETH_HLEN = 14
SIOCGIFHWADDR = 0x8927

# AF_PACKET multicast membership constants.
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0

# MRP AttributeEvent codes (10.8.1.7).
MRP_EVENT_NEW = 0
MRP_EVENT_JOININ = 1
MRP_EVENT_IN = 2
MRP_EVENT_JOINMT = 3
MRP_EVENT_MT = 4
MRP_EVENT_LV = 5

MRP_EVENT_NAMES = {
    0: "New", 1: "JoinIn", 2: "In", 3: "JoinMt", 4: "Mt", 5: "Lv",
}

# LeaveAllEvent (3 bits of VectorHeader).
MRP_LEAVE_ALL_NULL = 0
MRP_LEAVE_ALL = 1

# MVRP attribute type (Clause 11.2.3.1.2).
MVRP_ATTR_VID = 1
MVRP_ATTR_LEN_VID = 2

# MSRP attribute types (Clause 35.2.2.4).
MSRP_ATTR_TALKER_ADVERTISE = 1
MSRP_ATTR_TALKER_FAILED = 2
MSRP_ATTR_LISTENER = 3
MSRP_ATTR_DOMAIN = 4

MSRP_ATTR_NAMES = {
    1: "TalkerAdvertise",
    2: "TalkerFailed",
    3: "Listener",
    4: "Domain",
}

MSRP_ATTR_LEN = {
    MSRP_ATTR_TALKER_ADVERTISE: 25,
    MSRP_ATTR_TALKER_FAILED: 34,
    MSRP_ATTR_LISTENER: 8,
    MSRP_ATTR_DOMAIN: 4,
}

# Listener FourPackedType (Clause 35.2.2.8.5.4).
LISTENER_TYPE_IGNORE = 0
LISTENER_TYPE_ASKING_FAILED = 1
LISTENER_TYPE_READY = 2
LISTENER_TYPE_READY_FAILED = 3

LISTENER_TYPE_NAMES = {
    0: "Ignore",
    1: "AskingFailed",
    2: "Ready",
    3: "ReadyFailed",
}

# MSRP TalkerFailed failure codes (Table 35-6).
MSRP_FAILURE_CODE_NAMES = {
    0: "No failure",
    1: "Insufficient bandwidth",
    2: "Insufficient Bridge resources",
    3: "Insufficient bandwidth for Traffic Class",
    4: "StreamID in use by another Talker",
    5: "Stream destination address in use",
    6: "Stream pre-empted by higher rank",
    7: "Reported latency has changed",
    8: "Egress port is not AVB-capable",
    9: "Use a different destination address",
    10: "Out of MSRP resources",
    11: "Out of MMRP resources",
    12: "Cannot store destination address",
    13: "Requested priority is not an SR class",
    14: "MaxFrameSize too large",
    15: "MaxFanIn ports limit reached",
    16: "FirstValue changed for registered StreamID",
    17: "VLAN is blocked on this egress port",
    18: "VLAN tagging is disabled",
    19: "SR class priority mismatch",
}

# SR class defaults (Table 35-7 / 35-8).
SR_CLASS_DEFAULTS = {
    "A": {"id": 6, "priority": 3, "vid": 2, "max_frames_per_interval": 1},
    "B": {"id": 5, "priority": 2, "vid": 2, "max_frames_per_interval": 1},
}

# Default stream destination MAC (locally-administered AVTP multicast range).
DEFAULT_STREAM_DEST_MAC = b"\x91\xe0\xf0\x00\xfe\x00"


# ---------------------------------------------------------------------------
# Argument helpers
# ---------------------------------------------------------------------------

def parse_mac(s: str) -> bytes:
    """Parse a MAC address from 'aa:bb:cc:dd:ee:ff' or 'aabbccddeeff'."""
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
    """Parse an 8-byte MSRP StreamID. Accept colon-hex or plain hex."""
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
# Socket helpers
# ---------------------------------------------------------------------------

def get_interface_mac(interface: str) -> bytes:
    """Read the MAC address of `interface` via SIOCGIFHWADDR."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(
            s.fileno(),
            SIOCGIFHWADDR,
            struct.pack("256s", interface.encode("utf-8")[:15]),
        )
        return info[18:24]
    finally:
        s.close()


def open_raw_socket(interface: str) -> socket.socket:
    """Open an AF_PACKET socket bound to `interface` for all ethertypes.

    Subscribes to the MVRP and MSRP reserved multicast MACs so the kernel
    delivers them to us regardless of the NIC's unicast filter.
    """
    try:
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        print("Error: raw sockets require root privileges (sudo) or CAP_NET_RAW.",
              file=sys.stderr)
        sys.exit(1)
    sock.bind((interface, 0))
    ifindex = socket.if_nametoindex(interface)
    for dest_mac in (MVRP_DEST_MAC, MSRP_DEST_MAC):
        mreq = struct.pack("IHH8s", ifindex, PACKET_MR_MULTICAST, 6,
                           dest_mac + b"\x00\x00")
        try:
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
        except OSError as e:
            if e.errno != errno.EADDRINUSE:
                print(f"Warning: could not join multicast {format_mac(dest_mac)}: {e}",
                      file=sys.stderr)
    sock.setblocking(False)
    return sock


def send_frame(sock: socket.socket, interface: str, dest_mac: bytes,
               src_mac: bytes, ethertype: int, payload: bytes) -> None:
    """Send an L2 frame, padding payload to the 60-byte Ethernet minimum."""
    eth_header = struct.pack("!6s6sH", dest_mac, src_mac, ethertype)
    frame = eth_header + payload
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    sock.sendto(frame, (interface, 0))


def recv_frame(sock: socket.socket, timeout: float):
    """Wait up to `timeout` seconds for one frame. Returns (src, dst, ethertype, payload) or None."""
    ready, _, _ = select.select([sock], [], [], timeout)
    if not ready:
        return None
    try:
        data = sock.recv(4096)
    except BlockingIOError:
        return None
    if len(data) < ETH_HLEN:
        return None
    dst = data[0:6]
    src = data[6:12]
    ethertype = struct.unpack("!H", data[12:14])[0]
    offset = ETH_HLEN
    # Strip a single 802.1Q tag if present so the upper layer doesn't have to.
    if ethertype == ETH_P_VLAN and len(data) >= ETH_HLEN + 4:
        ethertype = struct.unpack("!H", data[16:18])[0]
        offset += 4
    return src, dst, ethertype, data[offset:]


if sys.platform == "darwin":
    # macOS has no AF_PACKET; use the BPF backend (bpf_shim.py, same
    # directory) with a kernel filter on the MRP ethertypes.
    import os as _os
    from bpf_shim import MacBpfSocket, recv_raw_ts  # noqa: F811
    from bpf_shim import get_mac_address as get_interface_mac  # noqa: F811

    def open_raw_socket(interface):  # noqa: F811
        return MacBpfSocket(interface, ethertype=(ETH_P_MSRP, ETH_P_MVRP))

    def send_frame(sock, interface, dest_mac, src_mac, ethertype,
                   payload):  # noqa: F811
        frame = struct.pack("!6s6sH", dest_mac, src_mac, ethertype) + payload
        if len(frame) < 60:
            frame += b"\x00" * (60 - len(frame))
        _os.write(sock.fd, frame)

    def recv_frame(sock, timeout):  # noqa: F811
        r = recv_raw_ts(sock, timeout)
        if r is None:
            return None
        _ts, dst, src, ethertype, payload = r
        if ethertype == ETH_P_VLAN and len(payload) >= 4:
            ethertype = struct.unpack("!H", payload[2:4])[0]
            payload = payload[4:]
        return src, dst, ethertype, payload


# ---------------------------------------------------------------------------
# MRPDU encoding
# ---------------------------------------------------------------------------

def encode_three_packed(events) -> bytes:
    """Pack three AttributeEvent values per byte: b = e1*36 + e2*6 + e3."""
    out = bytearray()
    for i in range(0, len(events), 3):
        e1 = events[i] if i < len(events) else 0
        e2 = events[i + 1] if i + 1 < len(events) else 0
        e3 = events[i + 2] if i + 2 < len(events) else 0
        out.append(e1 * 36 + e2 * 6 + e3)
    return bytes(out)


def decode_three_packed(data: bytes, n: int):
    """Unpack the first `n` AttributeEvent values from a packed byte string."""
    events = []
    for b in data:
        e1, rem = divmod(b, 36)
        e2, e3 = divmod(rem, 6)
        events.extend([e1, e2, e3])
    return events[:n]


def encode_four_packed(events) -> bytes:
    """Pack four 2-bit FourPackedType values per byte: b = (e1<<6)|(e2<<4)|(e3<<2)|e4."""
    out = bytearray()
    for i in range(0, len(events), 4):
        e = [events[i + j] if i + j < len(events) else 0 for j in range(4)]
        out.append((e[0] << 6) | (e[1] << 4) | (e[2] << 2) | e[3])
    return bytes(out)


def decode_four_packed(data: bytes, n: int):
    events = []
    for b in data:
        events.append((b >> 6) & 0x3)
        events.append((b >> 4) & 0x3)
        events.append((b >> 2) & 0x3)
        events.append(b & 0x3)
    return events[:n]


def encode_vector(leave_all: int, first_value: bytes, three_packed: bytes,
                  n_values: int, four_packed: bytes = b"") -> bytes:
    """Encode a single VectorAttribute."""
    header = struct.pack(">H", ((leave_all & 0x7) << 13) | (n_values & 0x1FFF))
    return header + first_value + three_packed + four_packed


def encode_message(attr_type: int, attr_len: int, vector: bytes) -> bytes:
    """Wrap one VectorAttribute as an MRP Message (with trailing AttributeList EndMark)."""
    attribute_list = vector + b"\x00\x00"
    return struct.pack(">BBH", attr_type, attr_len, len(attribute_list)) + attribute_list


def encode_mrpdu(messages) -> bytes:
    """Build a complete MRPDU: ProtocolVersion + Messages + EndMark."""
    return b"\x00" + b"".join(messages) + b"\x00\x00"


# ---------------------------------------------------------------------------
# Attribute FirstValue encoders
# ---------------------------------------------------------------------------

def encode_vid(vid: int) -> bytes:
    return struct.pack(">H", vid & 0xFFF)


def encode_talker_advertise(stream_id: bytes, dest_mac: bytes, vid: int,
                            max_frame_size: int, max_interval_frames: int,
                            pcp: int, rank: int, accum_latency: int) -> bytes:
    """Encode a 25-byte MSRP TalkerAdvertise FirstValue (Clause 35.2.2.8.2)."""
    par = ((pcp & 0x07) << 5) | ((rank & 0x01) << 4)
    return (stream_id +
            dest_mac +
            struct.pack(">H", vid & 0xFFF) +
            struct.pack(">HH", max_frame_size, max_interval_frames) +
            struct.pack(">B", par) +
            struct.pack(">I", accum_latency))


def encode_talker_failed(advertise_value: bytes, bridge_id: bytes,
                         failure_code: int) -> bytes:
    """Encode a 34-byte TalkerFailed value = TalkerAdvertise(25) + BridgeID(8) + FailureCode(1)."""
    if len(bridge_id) != 8:
        raise ValueError("bridge_id must be 8 bytes")
    return advertise_value + bridge_id + struct.pack(">B", failure_code & 0xFF)


def encode_listener_first_value(stream_id: bytes) -> bytes:
    if len(stream_id) != 8:
        raise ValueError("stream_id must be 8 bytes")
    return stream_id


def encode_domain(sr_class_id: int, sr_class_priority: int,
                  sr_class_vid: int) -> bytes:
    return struct.pack(">BBH", sr_class_id & 0xFF, sr_class_priority & 0xFF,
                       sr_class_vid & 0xFFFF)


# ---------------------------------------------------------------------------
# MRPDU decoding
# ---------------------------------------------------------------------------

@dataclass
class DecodedAttribute:
    attr_type: int
    leave_all: bool
    events: list = field(default_factory=list)  # list of (AttributeEvent, decoded_value, listener_type or None)


@dataclass
class DecodedMrpdu:
    protocol: str  # "MSRP" or "MVRP"
    protocol_version: int
    messages: list = field(default_factory=list)  # list of DecodedAttribute


def _increment_first_value(protocol: str, attr_type: int, value: bytes,
                           step: int) -> bytes:
    """Per 802.1Q, subsequent values in a Vector are derived by adding `step`.

    For MVRP VID and MSRP Listener/Talker StreamIDs, the value is treated as a
    big-endian integer and incremented; for MSRP Domain values, the SR class
    fields don't have a natural ordering -- we just return the same bytes,
    which is a degenerate case (Domain vectors normally have NumberOfValues=1).
    """
    if step == 0:
        return value
    if protocol == "MVRP":
        v = struct.unpack(">H", value)[0] + step
        return struct.pack(">H", v & 0xFFFF)
    if protocol == "MSRP" and attr_type in (MSRP_ATTR_TALKER_ADVERTISE,
                                            MSRP_ATTR_TALKER_FAILED,
                                            MSRP_ATTR_LISTENER):
        # First 8 bytes are the StreamID; increment as a 64-bit integer.
        sid = int.from_bytes(value[:8], "big") + step
        return sid.to_bytes(8, "big") + value[8:]
    return value


def _decode_first_value(protocol: str, attr_type: int, value: bytes) -> dict:
    """Decode an MRP FirstValue into a dict for reporting."""
    if protocol == "MVRP":
        return {"vid": struct.unpack(">H", value)[0]}
    if protocol == "MSRP":
        if attr_type == MSRP_ATTR_TALKER_ADVERTISE:
            sid = value[0:8]
            dmac = value[8:14]
            vid = struct.unpack(">H", value[14:16])[0] & 0x0FFF
            mfs, mif = struct.unpack(">HH", value[16:20])
            par = value[20]
            pcp = (par >> 5) & 0x07
            rank = (par >> 4) & 0x01
            lat = struct.unpack(">I", value[21:25])[0]
            return {
                "stream_id": sid,
                "dest_mac": dmac,
                "vid": vid,
                "max_frame_size": mfs,
                "max_interval_frames": mif,
                "pcp": pcp,
                "rank": rank,
                "accumulated_latency_ns": lat,
            }
        if attr_type == MSRP_ATTR_TALKER_FAILED:
            base = _decode_first_value(protocol, MSRP_ATTR_TALKER_ADVERTISE,
                                       value[:25])
            base["bridge_id"] = value[25:33]
            base["failure_code"] = value[33]
            return base
        if attr_type == MSRP_ATTR_LISTENER:
            return {"stream_id": value[:8]}
        if attr_type == MSRP_ATTR_DOMAIN:
            return {
                "sr_class_id": value[0],
                "sr_class_priority": value[1],
                "sr_class_vid": struct.unpack(">H", value[2:4])[0] & 0x0FFF,
            }
    return {"raw": value.hex()}


def decode_mrpdu(protocol: str, payload: bytes) -> Optional[DecodedMrpdu]:
    """Decode an MRPDU body (the bytes after the Ethernet header)."""
    if len(payload) < 1:
        return None
    pdu = DecodedMrpdu(protocol=protocol, protocol_version=payload[0])
    p = 1
    while p < len(payload):
        # Message EndMark.
        if payload[p:p + 2] == b"\x00\x00":
            break
        if p + 4 > len(payload):
            return None
        attr_type = payload[p]
        attr_len = payload[p + 1]
        list_len = struct.unpack(">H", payload[p + 2:p + 4])[0]
        p += 4
        list_end = p + list_len
        if list_end > len(payload):
            return None
        attr = DecodedAttribute(attr_type=attr_type, leave_all=False)

        q = p
        while q < list_end:
            # AttributeList EndMark.
            if payload[q:q + 2] == b"\x00\x00":
                q += 2
                break
            if q + 2 > list_end:
                return None
            vh = struct.unpack(">H", payload[q:q + 2])[0]
            q += 2
            leave_all = (vh >> 13) & 0x07
            n_values = vh & 0x1FFF
            if leave_all:
                attr.leave_all = True
            if attr_len == 0 or n_values == 0:
                # Pure LeaveAll vector with no values.
                continue
            if q + attr_len > list_end:
                return None
            first_value = payload[q:q + attr_len]
            q += attr_len
            n_three = (n_values + 2) // 3
            if q + n_three > list_end:
                return None
            three_bytes = payload[q:q + n_three]
            q += n_three
            events = decode_three_packed(three_bytes, n_values)

            four_events = None
            if protocol == "MSRP" and attr_type == MSRP_ATTR_LISTENER:
                n_four = (n_values + 3) // 4
                if q + n_four > list_end:
                    return None
                four_events = decode_four_packed(payload[q:q + n_four],
                                                 n_values)
                q += n_four

            for i in range(n_values):
                value_i = _increment_first_value(protocol, attr_type,
                                                 first_value, i)
                decoded = _decode_first_value(protocol, attr_type, value_i)
                ltype = four_events[i] if four_events else None
                attr.events.append((events[i], decoded, ltype))

        p = list_end
        pdu.messages.append(attr)
    return pdu


# ---------------------------------------------------------------------------
# Pretty-printers
# ---------------------------------------------------------------------------

def format_attribute(protocol: str, attr_type: int, decoded: dict,
                     listener_type: Optional[int]) -> str:
    if protocol == "MVRP":
        return f"VID={decoded['vid']}"
    if protocol == "MSRP":
        if attr_type == MSRP_ATTR_TALKER_ADVERTISE:
            return (f"StreamID={format_stream_id(decoded['stream_id'])} "
                    f"dest={format_mac(decoded['dest_mac'])} "
                    f"vid={decoded['vid']} pcp={decoded['pcp']} "
                    f"frame={decoded['max_frame_size']}B "
                    f"max_interval_frames={decoded['max_interval_frames']} "
                    f"latency={decoded['accumulated_latency_ns']}ns")
        if attr_type == MSRP_ATTR_TALKER_FAILED:
            fc = decoded['failure_code']
            fcn = MSRP_FAILURE_CODE_NAMES.get(fc, f"failure_{fc}")
            return (f"StreamID={format_stream_id(decoded['stream_id'])} "
                    f"bridge={format_stream_id(decoded['bridge_id'])} "
                    f"failure={fc} ({fcn})")
        if attr_type == MSRP_ATTR_LISTENER:
            lname = LISTENER_TYPE_NAMES.get(listener_type, str(listener_type))
            return (f"StreamID={format_stream_id(decoded['stream_id'])} "
                    f"type={lname}")
        if attr_type == MSRP_ATTR_DOMAIN:
            return (f"sr_class_id={decoded['sr_class_id']} "
                    f"priority={decoded['sr_class_priority']} "
                    f"vid={decoded['sr_class_vid']}")
    return repr(decoded)


def print_decoded(pdu: DecodedMrpdu, src_mac: bytes, prefix: str = "  ") -> None:
    print(f"{prefix}{pdu.protocol} from {format_mac(src_mac)} "
          f"(version={pdu.protocol_version})")
    for attr in pdu.messages:
        name = (MSRP_ATTR_NAMES.get(attr.attr_type, f"type{attr.attr_type}")
                if pdu.protocol == "MSRP"
                else f"VID(type{attr.attr_type})")
        la = " LeaveAll" if attr.leave_all else ""
        if not attr.events:
            print(f"{prefix}  {name}{la}")
            continue
        print(f"{prefix}  {name}{la}:")
        for ev, value, ltype in attr.events:
            evn = MRP_EVENT_NAMES.get(ev, str(ev))
            print(f"{prefix}    [{evn}] "
                  f"{format_attribute(pdu.protocol, attr.attr_type, value, ltype)}")


# ---------------------------------------------------------------------------
# Tracker — accumulates observations and produces a final report
# ---------------------------------------------------------------------------

@dataclass
class Tracker:
    """Accumulates MRPDU observations for the run summary."""
    mvrp_rx: int = 0
    msrp_rx: int = 0
    mvrp_tx: int = 0
    msrp_tx: int = 0
    # vid -> set of event names observed
    vids_observed: dict = field(default_factory=dict)
    # stream_id (bytes) -> dict with last talker_advertise, last talker_failed, listener_status
    streams: dict = field(default_factory=dict)
    # SR class id -> dict
    domains: dict = field(default_factory=dict)

    def note_mvrp(self, pdu: DecodedMrpdu, src_mac: bytes) -> None:
        self.mvrp_rx += 1
        for attr in pdu.messages:
            for ev, value, _ in attr.events:
                vid = value.get("vid")
                if vid is None:
                    continue
                entry = self.vids_observed.setdefault(
                    vid, {"events": set(), "sources": set()})
                entry["events"].add(MRP_EVENT_NAMES.get(ev, str(ev)))
                entry["sources"].add(format_mac(src_mac))

    def note_msrp(self, pdu: DecodedMrpdu, src_mac: bytes) -> None:
        self.msrp_rx += 1
        for attr in pdu.messages:
            for ev, value, ltype in attr.events:
                src = format_mac(src_mac)
                evn = MRP_EVENT_NAMES.get(ev, str(ev))
                if attr.attr_type == MSRP_ATTR_TALKER_ADVERTISE:
                    sid = value["stream_id"]
                    s = self.streams.setdefault(sid, {"sources": set()})
                    s["talker_advertise"] = value
                    s["talker_event"] = evn
                    s["sources"].add(src)
                elif attr.attr_type == MSRP_ATTR_TALKER_FAILED:
                    sid = value["stream_id"]
                    s = self.streams.setdefault(sid, {"sources": set()})
                    s["talker_failed"] = value
                    s["talker_event"] = evn
                    s["sources"].add(src)
                elif attr.attr_type == MSRP_ATTR_LISTENER:
                    sid = value["stream_id"]
                    s = self.streams.setdefault(sid, {"sources": set()})
                    s["listener_type"] = LISTENER_TYPE_NAMES.get(
                        ltype, str(ltype))
                    s["listener_event"] = evn
                    s["sources"].add(src)
                elif attr.attr_type == MSRP_ATTR_DOMAIN:
                    cls_id = value["sr_class_id"]
                    d = self.domains.setdefault(
                        cls_id, {"sources": set()})
                    d["priority"] = value["sr_class_priority"]
                    d["vid"] = value["sr_class_vid"]
                    d["event"] = evn
                    d["sources"].add(src)

    def print_summary(self, expected: dict) -> int:
        """Print the run summary. Returns a process exit code (0 = all expectations met)."""
        print()
        print("=" * 72)
        print("MRP Applicant Summary")
        print("=" * 72)
        print(f"  MRPDU TX: MVRP={self.mvrp_tx}  MSRP={self.msrp_tx}")
        print(f"  MRPDU RX: MVRP={self.mvrp_rx}  MSRP={self.msrp_rx}")
        print()

        if self.vids_observed:
            print("VLANs observed (MVRP):")
            for vid in sorted(self.vids_observed):
                e = self.vids_observed[vid]
                print(f"  VID {vid}: events={sorted(e['events'])}  "
                      f"from {sorted(e['sources'])}")
            print()

        if self.streams:
            print("Streams observed (MSRP):")
            for sid in sorted(self.streams, key=lambda b: b.hex()):
                s = self.streams[sid]
                print(f"  {format_stream_id(sid)}:")
                if "talker_advertise" in s:
                    ta = s["talker_advertise"]
                    print(f"    TalkerAdvertise [{s.get('talker_event','?')}] "
                          f"dest={format_mac(ta['dest_mac'])} vid={ta['vid']} "
                          f"pcp={ta['pcp']} frame={ta['max_frame_size']}B "
                          f"interval_frames={ta['max_interval_frames']} "
                          f"latency={ta['accumulated_latency_ns']}ns")
                if "talker_failed" in s:
                    tf = s["talker_failed"]
                    fc = tf["failure_code"]
                    fcn = MSRP_FAILURE_CODE_NAMES.get(fc, "unknown")
                    print(f"    TalkerFailed [{s.get('talker_event','?')}] "
                          f"bridge={format_stream_id(tf['bridge_id'])} "
                          f"code={fc} ({fcn})")
                if "listener_type" in s:
                    print(f"    Listener [{s.get('listener_event','?')}] "
                          f"declaration={s['listener_type']}")
                print(f"    seen from {sorted(s['sources'])}")
            print()

        if self.domains:
            print("Domains observed (MSRP):")
            for cls_id in sorted(self.domains):
                d = self.domains[cls_id]
                print(f"  SRclassID={cls_id} priority={d.get('priority')} "
                      f"vid={d.get('vid')} event={d.get('event')} "
                      f"from {sorted(d['sources'])}")
            print()

        # Apply caller-provided expectations and compute a pass/fail line.
        rc = 0
        if expected:
            print("Expectations:")
            for desc, ok, detail in expected:
                marker = "PASS" if ok else "FAIL"
                print(f"  [{marker}] {desc}: {detail}")
                if not ok:
                    rc = 2
            print()
        return rc


# ---------------------------------------------------------------------------
# Receive loop
# ---------------------------------------------------------------------------

def run_for(sock: socket.socket, duration: float, on_frame, on_tick=None,
            tick_interval: float = 1.0) -> None:
    """Pump received frames into `on_frame(src, dst, ethertype, payload)` for
    `duration` seconds, calling `on_tick()` every `tick_interval` seconds.
    """
    deadline = time.monotonic() + duration
    next_tick = time.monotonic() + tick_interval
    while True:
        now = time.monotonic()
        remaining = deadline - now
        if remaining <= 0:
            break
        wait = min(remaining, max(0.0, next_tick - now))
        f = recv_frame(sock, timeout=wait)
        if f is not None:
            src, dst, ethertype, payload = f
            on_frame(src, dst, ethertype, payload)
        if on_tick is not None and time.monotonic() >= next_tick:
            on_tick()
            next_tick = time.monotonic() + tick_interval


def dispatch_mrp(payload_ethertype: int, payload: bytes, src_mac: bytes,
                 tracker: Tracker, verbose: bool) -> Optional[DecodedMrpdu]:
    """Top-level MRPDU dispatcher: routes to MVRP or MSRP decoder, prints, and
    updates the tracker. Returns the decoded PDU or None."""
    if payload_ethertype == ETH_P_MVRP:
        pdu = decode_mrpdu("MVRP", payload)
        if pdu is None:
            return None
        tracker.note_mvrp(pdu, src_mac)
        if verbose:
            print_decoded(pdu, src_mac)
        return pdu
    if payload_ethertype == ETH_P_MSRP:
        pdu = decode_mrpdu("MSRP", payload)
        if pdu is None:
            return None
        tracker.note_msrp(pdu, src_mac)
        if verbose:
            print_decoded(pdu, src_mac)
        return pdu
    return None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_monitor(args, sock, src_mac) -> int:
    tracker = Tracker()
    print(f"Monitoring MSRP+MVRP on {args.interface} for {args.duration:.1f}s "
          f"(our MAC: {format_mac(src_mac)})")

    def on_frame(src, dst, ethertype, payload):
        if src == src_mac:
            return  # ignore loopback of our own frames
        dispatch_mrp(ethertype, payload, src, tracker, verbose=args.verbose)

    run_for(sock, args.duration, on_frame)
    return tracker.print_summary(expected=[])


def cmd_mvrp(args, sock, src_mac) -> int:
    tracker = Tracker()
    vid = args.vid
    if not (1 <= vid <= 4094):
        print(f"Error: VID must be 1..4094, got {vid}", file=sys.stderr)
        return 1

    print(f"MVRP applicant: registering VID {vid} on {args.interface} "
          f"for {args.duration:.1f}s")
    first_value = encode_vid(vid)
    vector = encode_vector(MRP_LEAVE_ALL_NULL, first_value,
                           encode_three_packed([MRP_EVENT_JOININ]),
                           n_values=1)
    join_pdu = encode_mrpdu([
        encode_message(MVRP_ATTR_VID, MVRP_ATTR_LEN_VID, vector)])
    leave_pdu = encode_mrpdu([encode_message(
        MVRP_ATTR_VID, MVRP_ATTR_LEN_VID,
        encode_vector(MRP_LEAVE_ALL_NULL, first_value,
                      encode_three_packed([MRP_EVENT_LV]), n_values=1))])

    def send_join():
        send_frame(sock, args.interface, MVRP_DEST_MAC, src_mac,
                   ETH_P_MVRP, join_pdu)
        tracker.mvrp_tx += 1

    send_join()  # initial declaration
    last_send = time.monotonic()

    def on_frame(src, dst, ethertype, payload):
        if src == src_mac:
            return
        dispatch_mrp(ethertype, payload, src, tracker, verbose=args.verbose)

    def on_tick():
        nonlocal last_send
        if time.monotonic() - last_send >= args.join_interval:
            send_join()
            last_send = time.monotonic()

    run_for(sock, args.duration, on_frame, on_tick=on_tick,
            tick_interval=min(1.0, args.join_interval))

    if not args.no_leave:
        send_frame(sock, args.interface, MVRP_DEST_MAC, src_mac,
                   ETH_P_MVRP, leave_pdu)
        tracker.mvrp_tx += 1

    # Expectations: we should have received either an Echo of our JoinIn
    # (proxy registration by the bridge) or a JoinIn / In for the same VID.
    seen = tracker.vids_observed.get(vid)
    registered = bool(seen) and bool(seen["events"] &
                                     {"JoinIn", "In", "New", "JoinMt"})
    expected = [
        (f"Bridge / peer responded to VID {vid} JoinIn",
         registered,
         f"events seen: {sorted(seen['events'])}" if seen
         else "no MVRP traffic observed for this VID"),
    ]
    return tracker.print_summary(expected=expected)


def _build_talker_pdu(stream_id: bytes, dest_mac: bytes, vid: int,
                      max_frame_size: int, max_interval_frames: int,
                      pcp: int, rank: int, accum_latency: int,
                      event: int) -> bytes:
    fv = encode_talker_advertise(stream_id, dest_mac, vid, max_frame_size,
                                 max_interval_frames, pcp, rank, accum_latency)
    vec = encode_vector(MRP_LEAVE_ALL_NULL, fv,
                        encode_three_packed([event]), n_values=1)
    return encode_mrpdu([encode_message(MSRP_ATTR_TALKER_ADVERTISE,
                                        MSRP_ATTR_LEN[MSRP_ATTR_TALKER_ADVERTISE],
                                        vec)])


def _build_listener_pdu(stream_id: bytes, event: int,
                        listener_type: int) -> bytes:
    fv = encode_listener_first_value(stream_id)
    vec = encode_vector(MRP_LEAVE_ALL_NULL, fv,
                        encode_three_packed([event]),
                        n_values=1,
                        four_packed=encode_four_packed([listener_type]))
    return encode_mrpdu([encode_message(MSRP_ATTR_LISTENER,
                                        MSRP_ATTR_LEN[MSRP_ATTR_LISTENER],
                                        vec)])


def _build_domain_pdu(sr_class_id: int, sr_class_priority: int,
                      sr_class_vid: int, event: int) -> bytes:
    fv = encode_domain(sr_class_id, sr_class_priority, sr_class_vid)
    vec = encode_vector(MRP_LEAVE_ALL_NULL, fv,
                        encode_three_packed([event]), n_values=1)
    return encode_mrpdu([encode_message(MSRP_ATTR_DOMAIN,
                                        MSRP_ATTR_LEN[MSRP_ATTR_DOMAIN],
                                        vec)])


def cmd_talker(args, sock, src_mac) -> int:
    tracker = Tracker()
    stream_id = args.stream_id
    sr = SR_CLASS_DEFAULTS[args.sr_class]
    pcp = args.pcp if args.pcp is not None else sr["priority"]
    vid = args.vid if args.vid is not None else sr["vid"]
    dest = args.dest_mac if args.dest_mac is not None else DEFAULT_STREAM_DEST_MAC

    print(f"MSRP Talker applicant: advertising stream "
          f"{format_stream_id(stream_id)} on {args.interface} "
          f"(class {args.sr_class} pcp={pcp} vid={vid} "
          f"dest={format_mac(dest)} frame={args.max_frame_size}B "
          f"interval_frames={args.max_interval_frames}) "
          f"for {args.duration:.1f}s")

    advertise_pdu = _build_talker_pdu(
        stream_id, dest, vid, args.max_frame_size, args.max_interval_frames,
        pcp, args.rank, args.accumulated_latency, MRP_EVENT_JOININ)
    leave_pdu = _build_talker_pdu(
        stream_id, dest, vid, args.max_frame_size, args.max_interval_frames,
        pcp, args.rank, args.accumulated_latency, MRP_EVENT_LV)
    domain_pdu = _build_domain_pdu(sr["id"], pcp, vid, MRP_EVENT_JOININ)

    def send_advertise():
        send_frame(sock, args.interface, MSRP_DEST_MAC, src_mac,
                   ETH_P_MSRP, advertise_pdu)
        tracker.msrp_tx += 1

    if args.send_domain:
        send_frame(sock, args.interface, MSRP_DEST_MAC, src_mac,
                   ETH_P_MSRP, domain_pdu)
        tracker.msrp_tx += 1

    send_advertise()
    last_send = time.monotonic()

    def on_frame(src, dst, ethertype, payload):
        if src == src_mac:
            return
        dispatch_mrp(ethertype, payload, src, tracker, verbose=args.verbose)

    def on_tick():
        nonlocal last_send
        if time.monotonic() - last_send >= args.join_interval:
            send_advertise()
            last_send = time.monotonic()

    run_for(sock, args.duration, on_frame, on_tick=on_tick,
            tick_interval=min(1.0, args.join_interval))

    if not args.no_leave:
        send_frame(sock, args.interface, MSRP_DEST_MAC, src_mac,
                   ETH_P_MSRP, leave_pdu)
        tracker.msrp_tx += 1

    # Outcome: did the bridge propagate our advertise (returning JoinIn/In) or
    # mark it as TalkerFailed? Did any Listener respond?
    s = tracker.streams.get(stream_id, {})
    failed = "talker_failed" in s
    advertised_back = "talker_advertise" in s and s.get("talker_event") in (
        "JoinIn", "In", "New", "JoinMt")
    listener_seen = "listener_type" in s
    listener_ready = s.get("listener_type") == "Ready"
    listener_failed = s.get("listener_type") in (
        "AskingFailed", "ReadyFailed")

    detail_advertise = "no TalkerAdvertise echo received"
    if failed:
        fc = s["talker_failed"]["failure_code"]
        fcn = MSRP_FAILURE_CODE_NAMES.get(fc, "unknown")
        detail_advertise = f"bridge rejected with TalkerFailed code={fc} ({fcn})"
    elif advertised_back:
        detail_advertise = f"event={s.get('talker_event')}"

    detail_listener = "no Listener attribute received"
    if listener_seen:
        detail_listener = (f"event={s.get('listener_event')} "
                           f"declaration={s.get('listener_type')}")

    expected = [
        ("TalkerAdvertise not rejected by bridge",
         not failed,
         detail_advertise if failed else "no TalkerFailed observed"),
        ("Stream registered at the bridge",
         advertised_back and not failed,
         detail_advertise),
        ("Listener declared Ready",
         listener_ready,
         detail_listener if not listener_failed
         else f"{detail_listener} (negative listener declaration)"),
    ]
    return tracker.print_summary(expected=expected)


def cmd_listener(args, sock, src_mac) -> int:
    tracker = Tracker()
    stream_id = args.stream_id
    declaration_map = {
        "ready": LISTENER_TYPE_READY,
        "asking_failed": LISTENER_TYPE_ASKING_FAILED,
        "ready_failed": LISTENER_TYPE_READY_FAILED,
        "ignore": LISTENER_TYPE_IGNORE,
    }
    listener_type = declaration_map[args.declaration]

    sr = SR_CLASS_DEFAULTS[args.sr_class]
    vid = args.vid if args.vid is not None else sr["vid"]
    pcp = args.pcp if args.pcp is not None else sr["priority"]

    print(f"MSRP Listener applicant: declaring {args.declaration} "
          f"for stream {format_stream_id(stream_id)} on {args.interface} "
          f"for {args.duration:.1f}s")

    listener_pdu = _build_listener_pdu(stream_id, MRP_EVENT_JOININ, listener_type)
    leave_pdu = _build_listener_pdu(stream_id, MRP_EVENT_LV, listener_type)
    domain_pdu = _build_domain_pdu(sr["id"], pcp, vid, MRP_EVENT_JOININ)

    if args.send_domain:
        send_frame(sock, args.interface, MSRP_DEST_MAC, src_mac,
                   ETH_P_MSRP, domain_pdu)
        tracker.msrp_tx += 1

    def send_listener():
        send_frame(sock, args.interface, MSRP_DEST_MAC, src_mac,
                   ETH_P_MSRP, listener_pdu)
        tracker.msrp_tx += 1

    send_listener()
    last_send = time.monotonic()

    def on_frame(src, dst, ethertype, payload):
        if src == src_mac:
            return
        dispatch_mrp(ethertype, payload, src, tracker, verbose=args.verbose)

    def on_tick():
        nonlocal last_send
        if time.monotonic() - last_send >= args.join_interval:
            send_listener()
            last_send = time.monotonic()

    run_for(sock, args.duration, on_frame, on_tick=on_tick,
            tick_interval=min(1.0, args.join_interval))

    if not args.no_leave:
        send_frame(sock, args.interface, MSRP_DEST_MAC, src_mac,
                   ETH_P_MSRP, leave_pdu)
        tracker.msrp_tx += 1

    # Outcome: a corresponding Talker should have been advertised by the bridge.
    s = tracker.streams.get(stream_id, {})
    talker_seen = "talker_advertise" in s
    talker_failed = "talker_failed" in s
    detail_talker = "no Talker attribute received for this StreamID"
    if talker_failed:
        fc = s["talker_failed"]["failure_code"]
        fcn = MSRP_FAILURE_CODE_NAMES.get(fc, "unknown")
        detail_talker = (f"received TalkerFailed event={s.get('talker_event')} "
                         f"code={fc} ({fcn})")
    elif talker_seen:
        ta = s["talker_advertise"]
        detail_talker = (f"event={s.get('talker_event')} "
                         f"dest={format_mac(ta['dest_mac'])} "
                         f"vid={ta['vid']} pcp={ta['pcp']} "
                         f"frame={ta['max_frame_size']}B "
                         f"latency={ta['accumulated_latency_ns']}ns")

    expected = [
        ("Talker is present for this StreamID",
         talker_seen and not talker_failed,
         detail_talker),
    ]
    return tracker.print_summary(expected=expected)


def cmd_domain(args, sock, src_mac) -> int:
    tracker = Tracker()
    sr = SR_CLASS_DEFAULTS[args.sr_class]
    sr_class_id = args.sr_class_id if args.sr_class_id is not None else sr["id"]
    pcp = args.pcp if args.pcp is not None else sr["priority"]
    vid = args.vid if args.vid is not None else sr["vid"]

    print(f"MSRP Domain applicant: declaring SRclassID={sr_class_id} "
          f"priority={pcp} VID={vid} on {args.interface} "
          f"for {args.duration:.1f}s")

    domain_pdu = _build_domain_pdu(sr_class_id, pcp, vid, MRP_EVENT_JOININ)
    leave_pdu = _build_domain_pdu(sr_class_id, pcp, vid, MRP_EVENT_LV)

    def send_domain():
        send_frame(sock, args.interface, MSRP_DEST_MAC, src_mac,
                   ETH_P_MSRP, domain_pdu)
        tracker.msrp_tx += 1

    send_domain()
    last_send = time.monotonic()

    def on_frame(src, dst, ethertype, payload):
        if src == src_mac:
            return
        dispatch_mrp(ethertype, payload, src, tracker, verbose=args.verbose)

    def on_tick():
        nonlocal last_send
        if time.monotonic() - last_send >= args.join_interval:
            send_domain()
            last_send = time.monotonic()

    run_for(sock, args.duration, on_frame, on_tick=on_tick,
            tick_interval=min(1.0, args.join_interval))

    if not args.no_leave:
        send_frame(sock, args.interface, MSRP_DEST_MAC, src_mac,
                   ETH_P_MSRP, leave_pdu)
        tracker.msrp_tx += 1

    # Outcome: we should hear our domain echoed back (or a peer's domain).
    seen = tracker.domains.get(sr_class_id)
    matches = seen is not None and seen.get("priority") == pcp and seen.get("vid") == vid
    detail = "no MSRP Domain attribute received"
    if seen:
        detail = (f"event={seen.get('event')} "
                  f"priority={seen.get('priority')} "
                  f"vid={seen.get('vid')} "
                  f"sources={sorted(seen['sources'])}")
    expected = [
        ("Bridge / peer acknowledged Domain declaration",
         matches,
         detail),
    ]
    return tracker.print_summary(expected=expected)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="MSRP/MVRP test applicant for AVB networks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-i", "--interface", default="eno1",
                   help="Network interface to use (default: eno1)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print every decoded MRPDU as it arrives.")
    sub = p.add_subparsers(dest="command", required=True)

    pl = sub.add_parser("monitor",
                        help="Passively decode MSRP+MVRP frames, then print a summary.")
    pl.add_argument("--duration", type=float, default=10.0,
                    help="Monitor duration in seconds (default: 10).")

    pm = sub.add_parser("mvrp",
                        help="Send MVRP JoinIn for a VID and report bridge response.")
    pm.add_argument("vid", type=int, help="VLAN ID to register (1..4094).")
    pm.add_argument("--duration", type=float, default=5.0,
                    help="Run duration in seconds (default: 5).")
    pm.add_argument("--join-interval", type=float, default=1.0,
                    help="Seconds between repeat JoinIn declarations (default: 1).")
    pm.add_argument("--no-leave", action="store_true",
                    help="Don't send a Lv frame on exit.")

    def _common_msrp(sp):
        sp.add_argument("--duration", type=float, default=5.0,
                        help="Run duration in seconds (default: 5).")
        sp.add_argument("--join-interval", type=float, default=1.0,
                        help="Seconds between repeat declarations (default: 1).")
        sp.add_argument("--no-leave", action="store_true",
                        help="Don't send a Lv frame on exit.")
        sp.add_argument("--sr-class", choices=["A", "B"], default="A",
                        help="SR class for defaults (priority/VID).")
        sp.add_argument("--pcp", type=int, default=None,
                        help="Override 802.1Q PCP / SR class priority.")
        sp.add_argument("--vid", type=int, default=None,
                        help="Override stream VLAN ID.")

    pt = sub.add_parser("talker",
                        help="Send MSRP TalkerAdvertise for a stream and report results.")
    pt.add_argument("stream_id", type=parse_stream_id,
                    help="8-byte StreamID as colon-hex "
                         "(e.g. 00:1b:21:01:02:03:00:01).")
    pt.add_argument("--dest-mac", type=parse_mac, default=None,
                    help="Stream destination MAC "
                         f"(default: {format_mac(DEFAULT_STREAM_DEST_MAC)}).")
    pt.add_argument("--max-frame-size", type=int, default=1500,
                    help="MaxFrameSize in bytes (default: 1500).")
    pt.add_argument("--max-interval-frames", type=int, default=1,
                    help="MaxIntervalFrames per class interval (default: 1).")
    pt.add_argument("--rank", type=int, default=1, choices=[0, 1],
                    help="Rank: 0=emergency, 1=non-emergency (default: 1).")
    pt.add_argument("--accumulated-latency", type=int, default=0,
                    help="Initial accumulated latency in ns (default: 0).")
    pt.add_argument("--send-domain", action="store_true",
                    help="Also send a Domain declaration before advertising.")
    _common_msrp(pt)

    pls = sub.add_parser("listener",
                         help="Send MSRP Listener declaration for a stream and report results.")
    pls.add_argument("stream_id", type=parse_stream_id,
                     help="8-byte StreamID (colon-hex).")
    pls.add_argument("--declaration",
                     choices=["ready", "asking_failed", "ready_failed", "ignore"],
                     default="ready",
                     help="Listener declaration type (default: ready).")
    pls.add_argument("--send-domain", action="store_true",
                     help="Also send a Domain declaration before subscribing.")
    _common_msrp(pls)

    pd = sub.add_parser("domain",
                        help="Send MSRP Domain declaration and report responses.")
    pd.add_argument("--sr-class-id", type=int, default=None,
                    help="Override SR class ID (default: from --sr-class).")
    _common_msrp(pd)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        src_mac = get_interface_mac(args.interface)
    except OSError as e:
        print(f"Error: cannot read MAC of interface {args.interface!r}: {e}",
              file=sys.stderr)
        return 1
    if src_mac == b"\x00" * 6:
        print(f"Error: interface {args.interface!r} has no MAC address",
              file=sys.stderr)
        return 1

    sock = open_raw_socket(args.interface)

    try:
        if args.command == "monitor":
            return cmd_monitor(args, sock, src_mac)
        if args.command == "mvrp":
            return cmd_mvrp(args, sock, src_mac)
        if args.command == "talker":
            return cmd_talker(args, sock, src_mac)
        if args.command == "listener":
            return cmd_listener(args, sock, src_mac)
        if args.command == "domain":
            return cmd_domain(args, sock, src_mac)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    finally:
        sock.close()

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
