#!/usr/bin/env python3
"""
AVB Controller - ATDECC controller for managing AVB stream connections.

Communicates using raw AF_PACKET sockets with ethertype 0x22F0 (AVTP/ATDECC).
Requires root privileges or CAP_NET_RAW capability.

Protocol references:
  - IEEE 1722-2016 (AVTP)
  - IEEE 1722.1-2021 (ATDECC: ADP, ACMP, AECP)

Usage:
  sudo python3 atdecc_controller.py discover
  sudo python3 atdecc_controller.py connect <talker_entity_id> <listener_entity_id>
  sudo python3 atdecc_controller.py disconnect <talker_entity_id> <listener_entity_id>
  sudo python3 atdecc_controller.py --interface eno1 discover
"""

import argparse
import fcntl
import os
import select
import socket
import struct
import sys
import time
import uuid

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ETH_P_AVTP = 0x22F0
ETH_ADDR_LEN = 6
UNIQUE_ID_LEN = 8
ETH_HLEN = 14

# Multicast destination for ADP / ACMP
ACMP_MULTICAST = b"\x91\xe0\xf0\x01\x00\x00"

# AVTP subtypes
AVTP_SUBTYPE_ADP = 0xFA
AVTP_SUBTYPE_AECP = 0xFB
AVTP_SUBTYPE_ACMP = 0xFC

# ADP message types
ADP_MSG_ENTITY_AVAILABLE = 0
ADP_MSG_ENTITY_DEPARTING = 1
ADP_MSG_ENTITY_DISCOVER = 2

# ACMP message types
ACMP_MSG_CONNECT_TX_COMMAND = 0
ACMP_MSG_CONNECT_TX_RESPONSE = 1
ACMP_MSG_DISCONNECT_TX_COMMAND = 2
ACMP_MSG_DISCONNECT_TX_RESPONSE = 3
ACMP_MSG_GET_TX_STATE_COMMAND = 4
ACMP_MSG_GET_TX_STATE_RESPONSE = 5
ACMP_MSG_CONNECT_RX_COMMAND = 6
ACMP_MSG_CONNECT_RX_RESPONSE = 7
ACMP_MSG_DISCONNECT_RX_COMMAND = 8
ACMP_MSG_DISCONNECT_RX_RESPONSE = 9
ACMP_MSG_GET_RX_STATE_COMMAND = 10
ACMP_MSG_GET_RX_STATE_RESPONSE = 11

# AECP message types
AECP_MSG_AEM_COMMAND = 0
AECP_MSG_AEM_RESPONSE = 1

# AECP command codes
AECP_CMD_READ_DESCRIPTOR = 0x0004
AECP_CMD_SET_STREAM_FORMAT = 0x0008
AECP_CMD_GET_STREAM_INFO = 0x000F
AECP_CMD_SET_CLOCK_SOURCE = 0x0016
AECP_CMD_GET_CLOCK_SOURCE = 0x0017
AECP_CMD_SET_CONTROL = 0x0018
AECP_CMD_GET_CONTROL = 0x0019
AECP_CMD_GET_AVB_INFO = 0x0027

# AEM descriptor types (IEEE 1722.1-2021 Table 7-1)
AEM_DESC_TYPE_ENTITY = 0x0000
AEM_DESC_TYPE_CONFIGURATION = 0x0001
AEM_DESC_TYPE_AUDIO_UNIT = 0x0002
AEM_DESC_TYPE_STREAM_INPUT = 0x0005
AEM_DESC_TYPE_STREAM_OUTPUT = 0x0006
AEM_DESC_TYPE_STRINGS = 0x000D
# NB: AEM_DESC_TYPE_CONTROL was historically 0x0009 in this tool;
# the IEEE-1722.1 value for CONTROL is 0x001A and 0x0009 is
# AVB_INTERFACE. Keeping 0x0009 here to match existing callers
# until they are migrated.
AEM_DESC_TYPE_CONTROL = 0x0009
AEM_DESC_TYPE_AVB_INTERFACE = 0x0009  # alias
AEM_DESC_TYPE_CLOCK_SOURCE = 0x000A
AEM_DESC_TYPE_MEMORY_OBJECT = 0x000B
AEM_DESC_TYPE_LOCALE = 0x000C
AEM_DESC_TYPE_STREAM_PORT_INPUT = 0x000E
AEM_DESC_TYPE_STREAM_PORT_OUTPUT = 0x000F
AEM_DESC_TYPE_AUDIO_CLUSTER = 0x0014
AEM_DESC_TYPE_AUDIO_MAP = 0x0017
AEM_DESC_TYPE_CLOCK_DOMAIN = 0x0024

# Name → type lookup for the read-descriptor CLI. Keep keys lowercase.
AEM_DESC_TYPE_BY_NAME = {
    "entity": AEM_DESC_TYPE_ENTITY,
    "configuration": AEM_DESC_TYPE_CONFIGURATION,
    "audio_unit": AEM_DESC_TYPE_AUDIO_UNIT,
    "stream_input": AEM_DESC_TYPE_STREAM_INPUT,
    "stream_output": AEM_DESC_TYPE_STREAM_OUTPUT,
    "strings": AEM_DESC_TYPE_STRINGS,
    "control": AEM_DESC_TYPE_CONTROL,
    "avb_interface": AEM_DESC_TYPE_AVB_INTERFACE,
    "clock_source": AEM_DESC_TYPE_CLOCK_SOURCE,
    "memory_object": AEM_DESC_TYPE_MEMORY_OBJECT,
    "locale": AEM_DESC_TYPE_LOCALE,
    "stream_port_input": AEM_DESC_TYPE_STREAM_PORT_INPUT,
    "stream_port_output": AEM_DESC_TYPE_STREAM_PORT_OUTPUT,
    "audio_cluster": AEM_DESC_TYPE_AUDIO_CLUSTER,
    "audio_map": AEM_DESC_TYPE_AUDIO_MAP,
    "clock_domain": AEM_DESC_TYPE_CLOCK_DOMAIN,
}
AEM_DESC_NAME_BY_TYPE = {v: k for k, v in AEM_DESC_TYPE_BY_NAME.items()}

# Well-known stream format presets (8 bytes each)
# IEC 61883-6 AM824: subtype=0, vendor=0, format=0x10, sf=1, fdf_sfc, fdf_evt=0, dbs=8, ...
# AAF PCM: subtype=2, vendor=0, sample_rate, format=0x02, bit_depth=24, channels=8
# Well-known stream format presets (8 bytes, matching C bitfield layout on LE)
STREAM_FORMATS = {
    "am824-44.1k":  bytes([0x00, 0xa0, 0x01, 0x08, 0x40, 0x00, 0x08, 0x00]),
    "am824-48k":    bytes([0x00, 0xa0, 0x02, 0x08, 0x40, 0x00, 0x08, 0x00]),
    "am824-96k":    bytes([0x00, 0xa0, 0x04, 0x08, 0x40, 0x00, 0x08, 0x00]),
    "am824-176.4k": bytes([0x00, 0xa0, 0x05, 0x08, 0x40, 0x00, 0x08, 0x00]),
    "am824-192k":   bytes([0x00, 0xa0, 0x06, 0x08, 0x40, 0x00, 0x08, 0x00]),
    "aaf-44.1k":    bytes([0x02, 0x04, 0x02, 0x18, 0x02, 0x00, 0x60, 0x00]),
    "aaf-48k":      bytes([0x02, 0x05, 0x02, 0x18, 0x02, 0x00, 0x60, 0x00]),
    # samples_per_frame follows the Milan-canonical Class A packetization
    # (rate/8000: 12 @96k, 24 @176.4/192k) — matches what macOS uses natively.
    "aaf-96k":      bytes([0x02, 0x07, 0x02, 0x18, 0x02, 0x00, 0xc0, 0x00]),
    "aaf-176.4k":   bytes([0x02, 0x08, 0x02, 0x18, 0x02, 0x01, 0x80, 0x00]),
    "aaf-192k":     bytes([0x02, 0x09, 0x02, 0x18, 0x02, 0x01, 0x80, 0x00]),
}
FORMAT_ALIASES = {"am824": "am824-48k", "aaf": "aaf-48k", "61883": "am824-48k"}

# ACMP control_data_len per IEEE 1722.1-2021
ACMP_CONTROL_DATA_LEN = 84

# SIOCGIFHWADDR ioctl number
SIOCGIFHWADDR = 0x8927

# ACMP status names
ACMP_STATUS_NAMES = {
    0: "SUCCESS",
    1: "LISTENER_UNKNOWN_ID",
    2: "TALKER_UNKNOWN_ID",
    3: "TALKER_DEST_MAC_FAIL",
    4: "TALKER_NO_STREAM_INDEX",
    5: "TALKER_NO_BANDWIDTH",
    6: "TALKER_EXCLUSIVE",
    7: "LISTENER_TALKER_TIMEOUT",
    8: "LISTENER_EXCLUSIVE",
    9: "STATE_UNAVAILABLE",
    10: "NOT_CONNECTED",
    11: "NO_SUCH_CONNECTION",
    12: "COULD_NOT_SEND_MESSAGE",
    13: "TALKER_MISBEHAVING",
    14: "LISTENER_MISBEHAVING",
    15: "RESERVED",
    16: "CONTROLLER_NOT_AUTHORIZED",
    17: "INCOMPATIBLE_REQUEST",
    31: "NOT_SUPPORTED",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def format_entity_id(eid: bytes) -> str:
    """Format an 8-byte entity ID as colon-separated hex."""
    return ":".join(f"{b:02x}" for b in eid)


def parse_entity_id(s: str) -> bytes:
    """Parse a colon-separated hex entity ID string to 8 bytes."""
    parts = s.split(":")
    if len(parts) != 8:
        raise ValueError(f"Entity ID must be 8 colon-separated hex bytes, got: {s}")
    return bytes(int(p, 16) for p in parts)


def get_mac_address(interface: str) -> bytes:
    """Get the MAC address of a network interface."""
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


def mac_to_entity_id(mac: bytes) -> bytes:
    """Derive an 8-byte entity ID from a 6-byte MAC address.

    Inserts 0xFF 0xFE in the middle (EUI-48 to EUI-64 conversion).
    """
    return mac[:3] + b"\xff\xfe" + mac[3:6]


def format_mac(mac: bytes) -> str:
    """Format a MAC address as colon-separated hex."""
    return ":".join(f"{b:02x}" for b in mac)


# ---------------------------------------------------------------------------
# ATDECC header encoding / decoding
# ---------------------------------------------------------------------------
# The ATDECC common header is 4 bytes:
#   byte 0: subtype (8 bits)
#   byte 1: sv(1) | version(3) | msg_type(4)    -- note bit ordering in C struct
#   byte 2: status_valtime(5) | control_data_len_h(3)
#   byte 3: control_data_len (low 8 bits)
#
# C struct uses bitfields with LSB-first ordering within each byte on
# little-endian (ESP32 / x86), so the wire layout from the code is:
#   byte 1 bits [7..4] = msg_type, [3..1] = version, [0] = sv
#     but on the wire (big-endian network order) it is:
#       bit7 = sv, bit6..4 = version, bit3..0 = msg_type
#   byte 2 bits [7..3] = status_valtime, [2..0] = control_data_len_h
#
# Looking at the C bitfield layout and how ESP-IDF (little-endian target)
# lays this out on the wire (the struct is memcpy'd directly):
#   byte 1: msg_type(4 high bits) | version(3 bits) | sv(1 low bit)
#           i.e. (msg_type << 4) | (version << 1) | sv
#   byte 2: control_data_len_h(3 high bits) | status_valtime(5 low bits)
#           i.e. (cdl_h << 5) | status_valtime
#
# Actually, C bitfield ordering on little-endian:
#   struct { uint8_t msg_type:4; uint8_t version:3; uint8_t sv:1; }
#   means msg_type is in bits 0-3, version in bits 3-5, sv in bit 7
#   So byte = (sv << 7) | (version << 4) | msg_type
#
#   struct { uint8_t control_data_len_h:3; uint8_t status_valtime:5; }
#   means cdl_h is in bits 0-2, status_valtime in bits 3-7
#   So byte = (status_valtime << 3) | cdl_h


def encode_atdecc_header(subtype: int, msg_type: int, sv: int, version: int,
                         status_valtime: int, control_data_len: int) -> bytes:
    """Encode a 4-byte ATDECC header."""
    cdl_h = (control_data_len >> 8) & 0x07
    cdl_l = control_data_len & 0xFF
    byte1 = (sv << 7) | (version << 4) | (msg_type & 0x0F)
    byte2 = (status_valtime << 3) | cdl_h
    return struct.pack("BBBB", subtype, byte1, byte2, cdl_l)


def decode_atdecc_header(data: bytes):
    """Decode a 4-byte ATDECC header.

    Returns (subtype, msg_type, sv, version, status_valtime, control_data_len).
    """
    subtype = data[0]
    byte1 = data[1]
    byte2 = data[2]
    cdl_l = data[3]

    sv = (byte1 >> 7) & 0x01
    version = (byte1 >> 4) & 0x07
    msg_type = byte1 & 0x0F

    status_valtime = (byte2 >> 3) & 0x1F
    cdl_h = byte2 & 0x07
    control_data_len = (cdl_h << 8) | cdl_l

    return subtype, msg_type, sv, version, status_valtime, control_data_len


# ---------------------------------------------------------------------------
# AECP AEM header encoding
# ---------------------------------------------------------------------------
# aecp_common_aem_s is 2 bytes:
#   byte 0: command_type_h(6 high bits) | unsolicited(1) | cr(1 low bit)
#   byte 1: command_type (low 8 bits)
#
# C bitfield: { uint8_t cr:1; uint8_t unsolicited:1; uint8_t command_type_h:6; }
# On little-endian: cr in bit 0, unsolicited in bit 1, command_type_h in bits 2-7
# So byte0 = (command_type_h << 2) | (unsolicited << 1) | cr

def encode_aecp_aem_header(command_type: int, cr: int = 0, unsolicited: int = 0) -> bytes:
    """Encode a 2-byte AECP AEM command header."""
    command_type_h = (command_type >> 8) & 0x3F
    command_type_l = command_type & 0xFF
    byte0 = (command_type_h << 2) | (unsolicited << 1) | cr
    return struct.pack("BB", byte0, command_type_l)


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def open_raw_socket(interface: str) -> socket.socket:
    """Open a raw AF_PACKET socket bound to the given interface for AVTP."""
    try:
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_AVTP)
        )
    except PermissionError:
        print("Error: raw sockets require root privileges (sudo) or CAP_NET_RAW.",
              file=sys.stderr)
        sys.exit(1)
    sock.bind((interface, ETH_P_AVTP))
    # Join the ATDECC multicast group
    # Use PACKET_ADD_MEMBERSHIP with struct packet_mreq
    ifindex = socket.if_nametoindex(interface)
    # struct packet_mreq: int ifindex, unsigned short type, unsigned short alen, unsigned char address[8]
    PACKET_MR_MULTICAST = 0
    SOL_PACKET = 263  # Linux constant, not always in Python's socket module
    PACKET_ADD_MEMBERSHIP = 1
    mreq = struct.pack("IHH8s", ifindex, PACKET_MR_MULTICAST, 6,
                        ACMP_MULTICAST + b"\x00\x00")
    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
    sock.setblocking(False)
    return sock


def send_frame(sock: socket.socket, interface: str, dest_mac: bytes,
               src_mac: bytes, payload: bytes) -> None:
    """Send an Ethernet frame with AVTP ethertype."""
    eth_header = struct.pack("!6s6sH", dest_mac, src_mac, ETH_P_AVTP)
    frame = eth_header + payload
    sock.sendto(frame, (interface, ETH_P_AVTP))


def recv_frame(sock: socket.socket, timeout: float = 0.1):
    """Receive an Ethernet frame. Returns (src_mac, payload) or None."""
    ready, _, _ = select.select([sock], [], [], timeout)
    if not ready:
        return None
    try:
        data = sock.recv(2048)
    except BlockingIOError:
        return None
    if len(data) < ETH_HLEN + 4:
        return None
    dst_mac = data[0:6]
    src_mac = data[6:12]
    ethertype = struct.unpack("!H", data[12:14])[0]
    if ethertype != ETH_P_AVTP:
        return None
    payload = data[ETH_HLEN:]
    return src_mac, payload


if sys.platform == "darwin":
    # macOS has no AF_PACKET; use the BPF backend (see bpf_shim.py and
    # "macOS support and limitations" in the README).
    from bpf_shim import (open_raw_socket, get_mac_address, send_frame,
                          recv_frame)  # noqa: F811


# ---------------------------------------------------------------------------
# ADP parsing
# ---------------------------------------------------------------------------

def parse_adp_entity(payload: bytes) -> dict:
    """Parse an ADP ENTITY_AVAILABLE message payload.

    ADP message layout (after ATDECC 4-byte header):
      bytes 0-7:   entity_id (8)
      bytes 8-15:  entity_model_id (8)
      bytes 16-19: entity_capabilities (4)
      bytes 20-21: talker_stream_sources (2)
      bytes 22-23: talker_capabilities (2)
      bytes 24-25: listener_stream_sinks (2)
      bytes 26-27: listener_capabilities (2)
      bytes 28-31: controller_capabilities (4)
      bytes 32-35: available_index (4)
      bytes 36-43: gptp_gm_id (8)
      byte  44:    gptp_domain_num
      byte  45:    reserved
      bytes 46-47: current_config_index (2)
      bytes 48-49: identify_control_index (2)
      bytes 50-51: interface_index (2)
      bytes 52-59: association_id (8)
      bytes 60-63: reserved (4)
    Total body: 64 bytes (header.control_data_len = 56 for entity summary part)
    """
    if len(payload) < 4:
        return None

    subtype, msg_type, sv, version, status_valtime, cdl = decode_atdecc_header(payload[:4])

    if subtype != AVTP_SUBTYPE_ADP:
        return None
    if msg_type != ADP_MSG_ENTITY_AVAILABLE:
        return None

    body = payload[4:]
    if len(body) < 56:
        return None

    entity_id = body[0:8]
    model_id = body[8:16]
    entity_caps = body[16:20]
    talker_stream_sources = struct.unpack("!H", body[20:22])[0]
    talker_caps = body[22:24]
    listener_stream_sinks = struct.unpack("!H", body[24:26])[0]
    listener_caps = body[26:28]
    controller_caps = body[28:32]
    available_index = struct.unpack("!I", body[32:36])[0]

    # Parse capability flags
    # talker_capabilities byte 0 (C bitfield on LE):
    #   bit 0: reserved, bit 1: other_source, bit 2: control_source,
    #   bit 3: media_clock_source, bit 4: smpte_source, bit 5: midi_source,
    #   bit 6: audio_source, bit 7: video_source
    # talker_capabilities byte 1:
    #   bit 0: implemented, bits 1-7: reserved
    talker_implemented = bool(talker_caps[1] & 0x01)
    talker_audio = bool(talker_caps[0] & 0x40)

    listener_implemented = bool(listener_caps[1] & 0x01)
    listener_audio = bool(listener_caps[0] & 0x40)

    # Controller implemented is in byte 3 bit 0 of controller_caps
    controller_implemented = bool(controller_caps[3] & 0x01)

    valid_time = status_valtime * 2  # seconds

    roles = []
    if talker_implemented:
        roles.append("Talker")
    if listener_implemented:
        roles.append("Listener")
    if controller_implemented:
        roles.append("Controller")

    return {
        "entity_id": entity_id,
        "model_id": model_id,
        "entity_id_str": format_entity_id(entity_id),
        "model_id_str": format_entity_id(model_id),
        "talker_implemented": talker_implemented,
        "talker_audio": talker_audio,
        "talker_stream_sources": talker_stream_sources,
        "listener_implemented": listener_implemented,
        "listener_audio": listener_audio,
        "listener_stream_sinks": listener_stream_sinks,
        "controller_implemented": controller_implemented,
        "roles": ", ".join(roles) if roles else "None",
        "available_index": available_index,
        "valid_time": valid_time,
        "gptp_gm_id": body[36:44],
        "gptp_gm_id_str": format_entity_id(body[36:44]),
        "gptp_domain": body[44],
    }


# ---------------------------------------------------------------------------
# AECP: READ_DESCRIPTOR for entity name
# ---------------------------------------------------------------------------

def build_aecp_read_descriptor(controller_id: bytes, target_id: bytes,
                               seq_id: int, descriptor_type: int,
                               descriptor_index: int = 0) -> bytes:
    """Build an AECP READ_DESCRIPTOR command message."""
    # AECP common: header(4) + target_entity_id(8) + controller_entity_id(8) + seq_id(2) = 22
    # AEM header: 2 bytes
    # configuration_index(2) + reserved(2) + descriptor_type(2) + descriptor_index(2) = 8
    # Total body (control_data_len) = 22 - 4 + 2 + 8 = 28
    # control_data_len = total after header = 18 + 2 + 8 = 28
    control_data_len = 28  # bytes after the 4-byte header

    header = encode_atdecc_header(AVTP_SUBTYPE_AECP, AECP_MSG_AEM_COMMAND,
                                  0, 0, 0, control_data_len)
    aem = encode_aecp_aem_header(AECP_CMD_READ_DESCRIPTOR)
    msg = (header
           + target_id
           + controller_id
           + struct.pack("!H", seq_id)
           + aem
           + struct.pack("!HH", 0, 0)  # configuration_index, reserved
           + struct.pack("!HH", descriptor_type, descriptor_index))
    return msg


_AM824_SFC_NAMES = {0: "32k", 1: "44.1k", 2: "48k", 3: "88.2k", 4: "96k", 5: "176.4k", 6: "192k"}
_AM824_SFC_HZ = {0: 32000, 1: 44100, 2: 48000, 3: 88200, 4: 96000, 5: 176400, 6: 192000}
_AAF_SR_NAMES = {1: "8k", 2: "16k", 3: "32k", 4: "44.1k", 5: "48k", 6: "88.2k", 7: "96k", 8: "176.4k", 9: "192k"}
_AAF_SR_HZ = {1: 8000, 2: 16000, 3: 32000, 4: 44100, 5: 48000, 6: 88200, 7: 96000, 8: 176400, 9: 192000}


def _format_stream_format(stream_format: bytes) -> str:
    """Format an 8-byte stream format into a human-readable string."""
    if len(stream_format) < 8:
        return "unknown"
    fmt_subtype = stream_format[0] & 0x7F
    if fmt_subtype == 0x00:
        sfc = stream_format[2] & 0x07
        dbs = stream_format[3]
        return f"AM824 {_AM824_SFC_NAMES.get(sfc, '?')} DBS={dbs}"
    elif fmt_subtype == 0x02:
        sr_code = stream_format[1] & 0x0F
        bit_depth = stream_format[3]
        if bit_depth == 32:
            bit_depth = 24
        ch_h = stream_format[4]
        ch_l = (stream_format[5] >> 6) & 0x03
        channels = (ch_h << 2) | ch_l
        return f"AAF {_AAF_SR_NAMES.get(sr_code, '?')} {bit_depth}bit {channels}ch"
    else:
        return f"unknown (subtype=0x{fmt_subtype:02x})"


def _format_rate_hz(hz: int) -> str:
    """Format a sample rate in Hz to a compact string like '48k' or '88.2k'."""
    if hz % 1000 == 0:
        return f"{hz // 1000}k"
    return f"{hz / 1000:.1f}k"


def _extract_format_info(stream_format: bytes) -> dict:
    """Extract sample rate (Hz), bit depth, and channels from an 8-byte stream format."""
    if len(stream_format) < 8:
        return {}
    fmt_subtype = stream_format[0] & 0x7F
    if fmt_subtype == 0x00:
        sfc = stream_format[2] & 0x07
        dbs = stream_format[3]
        sr = _AM824_SFC_HZ.get(sfc)
        # AM824 uses fixed 24-bit audio within 32-bit data blocks
        return {"base_format": "AM824", "sample_rate": sr, "bit_depth": 24, "channels": dbs}
    elif fmt_subtype == 0x02:
        sr_code = stream_format[1] & 0x0F
        # byte 3 is bit_depth; some devices set this to the container size (32)
        # rather than the significant audio bits (24)
        bit_depth = stream_format[3]
        if bit_depth == 32:
            bit_depth = 24
        ch_h = stream_format[4]
        ch_l = (stream_format[5] >> 6) & 0x03
        channels = (ch_h << 2) | ch_l
        sr = _AAF_SR_HZ.get(sr_code)
        return {"base_format": "AAF", "sample_rate": sr, "bit_depth": bit_depth, "channels": channels}
    return {}


def parse_aecp_read_descriptor_response(payload: bytes) -> dict:
    """Parse an AECP READ_DESCRIPTOR response to extract entity name."""
    if len(payload) < 4:
        return None

    subtype, msg_type, sv, version, status_valtime, cdl = decode_atdecc_header(payload[:4])
    if subtype != AVTP_SUBTYPE_AECP:
        return None
    if msg_type != AECP_MSG_AEM_RESPONSE:
        return None

    # AECP common after header: target(8) + controller(8) + seq(2) = 18
    # AEM header: 2
    # config_index(2) + reserved(2) + desc_type(2) + desc_index(2) = 8
    # Total to descriptor_data start: 4 + 18 + 2 + 8 = 32
    if len(payload) < 32:
        return None

    target_id = payload[4:12]
    seq_id = struct.unpack("!H", payload[20:22])[0]
    desc_type = struct.unpack("!H", payload[28:30])[0]
    desc_index = struct.unpack("!H", payload[30:32])[0]

    result = {
        "target_id": target_id,
        "seq_id": seq_id,
        "descriptor_type": desc_type,
        "descriptor_index": desc_index,
    }

    # For entity descriptor, the descriptor_data starts at offset 32.
    # Entity descriptor layout:
    #   entity_id(8) + entity_model_id(8) + entity_capabilities(4) +
    #   talker_stream_sources(2) + talker_capabilities(2) +
    #   listener_stream_sinks(2) + listener_capabilities(2) +
    #   controller_capabilities(4) + available_index(4) = 36 bytes
    #   then: association_id(8) + entity_name(64) ...
    # entity_name starts at offset 32 + 36 + 8 = 76
    if desc_type == AEM_DESC_TYPE_ENTITY and len(payload) >= 76 + 64:
        name_bytes = payload[76:140]
        entity_name = name_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        result["entity_name"] = entity_name

    # For stream input/output descriptors (IEEE 1722.1-2021 Section 7.2.6):
    # descriptor_data starts at offset 32:
    #   descriptor_type(2) + descriptor_index(2) + object_name(64) +
    #   localized_description(2) + clock_domain_index(2) + stream_flags(2) +
    #   current_format(8) + formats_offset(2) + number_of_formats(2)
    if desc_type in (AEM_DESC_TYPE_STREAM_INPUT, AEM_DESC_TYPE_STREAM_OUTPUT):
        # descriptor_type and descriptor_index are already at payload[28:32],
        # so desc_data at payload[32:] starts directly with the descriptor body:
        #   object_name(64) + localized_description(2) + clock_domain_index(2) +
        #   stream_flags(2) + current_format(8) + formats_offset(2) + number_of_formats(2)
        desc_data = payload[32:]
        if len(desc_data) >= 82:
            # object_name at body offset 0, 64 bytes
            name_bytes = desc_data[0:64]
            stream_name = name_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            result["stream_name"] = stream_name

            # localized_description at body offset 64 (2 bytes)
            # Upper 13 bits = STRINGS descriptor index, lower 3 bits = string offset
            result["localized_description"] = struct.unpack("!H", desc_data[64:66])[0]

            # clock_domain_index at body offset 66
            result["clock_domain_index"] = struct.unpack("!H", desc_data[66:68])[0]

            # stream_flags at body offset 68 (2 bytes)
            flags_raw = struct.unpack("!H", desc_data[68:70])[0]
            result["stream_flags"] = flags_raw

            # current_format at body offset 70, 8 bytes
            current_format = desc_data[70:78]
            result["current_format"] = current_format
            result["current_format_str"] = _format_stream_format(current_format)

            # formats_offset at body offset 78 (relative to start of descriptor)
            formats_offset = struct.unpack("!H", desc_data[78:80])[0]

            # number_of_formats at body offset 80
            num_formats = struct.unpack("!H", desc_data[80:82])[0]
            result["number_of_formats"] = num_formats

            # Parse supported format entries (each 8 bytes)
            # formats_offset is relative to the descriptor start (payload[28]),
            # so offset within desc_data is formats_offset - 4 (skip desc_type+desc_index)
            fmt_start = formats_offset - 4
            supported_formats = []
            for i in range(num_formats):
                off = fmt_start + i * 8
                if off + 8 <= len(desc_data):
                    supported_formats.append(desc_data[off:off + 8])
            result["supported_formats"] = supported_formats

    # For STRINGS descriptors (IEEE 1722.1-2021 Section 7.2.12):
    # descriptor_data after descriptor_type(2) + descriptor_index(2):
    #   string_0(64) + string_1(64) + ... + string_6(64) = 7 strings of 64 bytes
    if desc_type == AEM_DESC_TYPE_STRINGS:
        desc_data = payload[32:]
        strings = []
        for i in range(7):
            off = i * 64
            if off + 64 <= len(desc_data):
                s = desc_data[off:off + 64].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                strings.append(s)
        result["strings"] = strings

    return result


# ---------------------------------------------------------------------------
# AECP: SET_STREAM_FORMAT
# ---------------------------------------------------------------------------

def build_aecp_set_stream_format(controller_id: bytes, target_id: bytes,
                                  seq_id: int, descriptor_type: int,
                                  descriptor_index: int,
                                  stream_format: bytes) -> bytes:
    """Build an AECP SET_STREAM_FORMAT command.

    Wire layout (aecp_stream_format_s = 36 bytes):
      header(4) + target_entity_id(8) + controller_entity_id(8) + seq_id(2)
      + aem_header(2) + descriptor_type(2) + descriptor_index(2) + stream_format(8)
    control_data_len = 36 - 4 = 32
    """
    control_data_len = 32

    header = encode_atdecc_header(AVTP_SUBTYPE_AECP, AECP_MSG_AEM_COMMAND,
                                  0, 0, 0, control_data_len)
    aem = encode_aecp_aem_header(AECP_CMD_SET_STREAM_FORMAT)
    msg = (header
           + target_id
           + controller_id
           + struct.pack("!H", seq_id)
           + aem
           + struct.pack("!HH", descriptor_type, descriptor_index)
           + stream_format[:8])
    return msg


def _resolve_mac(sock, interface: str, mac: bytes, entity_id: bytes,
                 duration: float = 2.0) -> bytes:
    """Resolve entity ID to MAC address via ADP, fall back to EUI-64 derivation."""
    start = time.monotonic()
    while time.monotonic() - start < duration:
        result = recv_frame(sock, timeout=0.2)
        if result is None:
            continue
        src_mac, payload = result
        if len(payload) >= 12 and payload[0] == AVTP_SUBTYPE_ADP:
            adp_eid = payload[4:12]
            if adp_eid == entity_id:
                return src_mac
    # Fallback: standard EUI-64 to EUI-48 (remove FF:FE at bytes 3-4)
    if entity_id[3:5] == b'\xff\xfe':
        return entity_id[:3] + entity_id[5:8]
    # Non-standard entity ID — use first 6 bytes as best guess
    return entity_id[:6]


def send_set_stream_format(sock, interface: str, mac: bytes, controller_id: bytes,
                           target_id: bytes, target_mac: bytes,
                           descriptor_type: int, descriptor_index: int,
                           stream_format: bytes, seq_id: int) -> bool:
    """Send SET_STREAM_FORMAT and wait for response. Returns True on success."""
    msg = build_aecp_set_stream_format(
        controller_id, target_id, seq_id,
        descriptor_type, descriptor_index, stream_format)
    send_frame(sock, interface, target_mac, mac, msg)

    # Wait for response
    start = time.monotonic()
    while time.monotonic() - start < 3.0:
        result = recv_frame(sock, timeout=0.2)
        if result is None:
            continue
        src_mac_rx, payload = result
        if len(payload) < 4:
            continue
        subtype, msg_type, sv, version, status_valtime, cdl = decode_atdecc_header(payload[:4])
        if subtype == AVTP_SUBTYPE_AECP and msg_type == AECP_MSG_AEM_RESPONSE:
            # Check it's a SET_STREAM_FORMAT response for our target
            if len(payload) >= 22 and payload[4:12] == target_id:
                status = status_valtime
                # Per IEEE 1722.1-2021 Table 9.1:
                status_name = {0: "SUCCESS", 1: "NOT_IMPLEMENTED",
                               2: "NO_SUCH_DESCRIPTOR", 3: "ENTITY_LOCKED",
                               4: "ENTITY_ACQUIRED", 5: "NOT_AUTHENTICATED",
                               6: "AUTHENTICATION_DISABLED", 7: "BAD_ARGUMENTS",
                               8: "NO_RESOURCES", 9: "IN_PROGRESS",
                               10: "ENTITY_MISBEHAVING", 11: "NOT_SUPPORTED",
                               12: "STREAM_IS_RUNNING"}.get(status, f"ERROR({status})")
                print(f"  SET_STREAM_FORMAT response from {format_entity_id(target_id)}: {status_name}")
                return status == 0

    print(f"  SET_STREAM_FORMAT timeout for {format_entity_id(target_id)}")
    return False


def query_supported_formats(sock, interface: str, mac: bytes,
                            controller_id: bytes, target_id: bytes,
                            target_mac: bytes, descriptor_type: int,
                            descriptor_index: int, seq_id: int,
                            timeout: float = 2.0) -> list:
    """Send AECP READ_DESCRIPTOR for a stream descriptor and return its
    supported_formats list (each entry is 8 bytes). Returns [] on timeout."""
    msg = build_aecp_read_descriptor(controller_id, target_id, seq_id,
                                     descriptor_type, descriptor_index)
    send_frame(sock, interface, target_mac, mac, msg)

    start = time.monotonic()
    while time.monotonic() - start < timeout:
        result = recv_frame(sock, timeout=0.2)
        if result is None:
            continue
        _, payload = result
        if len(payload) < 12 or payload[4:12] != target_id:
            continue
        resp = parse_aecp_read_descriptor_response(payload)
        if resp is None:
            continue
        if resp.get("descriptor_type") != descriptor_type:
            continue
        if resp.get("descriptor_index") != descriptor_index:
            continue
        return resp.get("supported_formats", [])
    return []


def pick_closest_format(target: bytes, candidates: list) -> tuple:
    """Score each candidate format against the target and return
    (best_bytes, best_info, score). Score key (higher is better):
        same subtype  : +1000
        same SR       : +200, else −|ΔSR|/1000
        same channels : +100, else −|Δch|*5
        same bit_depth: +10,  else −|Δbd|

    Returns (None, None, -inf) if candidates is empty."""
    if not candidates:
        return (None, None, float("-inf"))
    targ = _extract_format_info(target) or {}
    best = None
    best_score = float("-inf")
    best_info = None
    for cand in candidates:
        info = _extract_format_info(cand) or {}
        score = 0.0
        if info.get("base_format") and info["base_format"] == targ.get("base_format"):
            score += 1000
        if info.get("sample_rate") and targ.get("sample_rate"):
            if info["sample_rate"] == targ["sample_rate"]:
                score += 200
            else:
                score -= abs(info["sample_rate"] - targ["sample_rate"]) / 1000.0
        if info.get("channels") and targ.get("channels"):
            if info["channels"] == targ["channels"]:
                score += 100
            else:
                score -= abs(info["channels"] - targ["channels"]) * 5
        if info.get("bit_depth") and targ.get("bit_depth"):
            if info["bit_depth"] == targ["bit_depth"]:
                score += 10
            else:
                score -= abs(info["bit_depth"] - targ["bit_depth"])
        if score > best_score:
            best_score = score
            best = cand
            best_info = info
    return (best, best_info, best_score)


# ---------------------------------------------------------------------------
# AECP: GET/SET_CLOCK_SOURCE
# ---------------------------------------------------------------------------

def build_aecp_clock_source(controller_id: bytes, target_id: bytes,
                            seq_id: int, command_type: int,
                            clock_domain_index: int = 0,
                            clock_source_index: int = 0) -> bytes:
    """Build AECP GET_CLOCK_SOURCE or SET_CLOCK_SOURCE.

    Both commands act on a CLOCK_DOMAIN descriptor. GET carries
    descriptor_type/index; SET additionally carries clock_source_index and a
    reserved uint16. Responses mirror the command family.
    """
    is_set = command_type == AECP_CMD_SET_CLOCK_SOURCE
    control_data_len = 28 if is_set else 24
    header = encode_atdecc_header(AVTP_SUBTYPE_AECP, AECP_MSG_AEM_COMMAND,
                                  0, 0, 0, control_data_len)
    aem = encode_aecp_aem_header(command_type)
    msg = (header
           + target_id
           + controller_id
           + struct.pack("!H", seq_id)
           + aem
           + struct.pack("!HH", AEM_DESC_TYPE_CLOCK_DOMAIN,
                         clock_domain_index))
    if is_set:
        msg += struct.pack("!HH", clock_source_index, 0)
    return msg


def parse_aecp_clock_source_response(payload: bytes) -> dict:
    """Parse AECP GET/SET_CLOCK_SOURCE response."""
    if len(payload) < 30:
        return None
    subtype, msg_type, sv, version, status_valtime, cdl = decode_atdecc_header(payload[:4])
    if subtype != AVTP_SUBTYPE_AECP or msg_type != AECP_MSG_AEM_RESPONSE:
        return None
    command_type = (((payload[22] >> 2) & 0x3F) << 8) | payload[23]
    if command_type not in (AECP_CMD_GET_CLOCK_SOURCE, AECP_CMD_SET_CLOCK_SOURCE):
        return None
    result = {
        "target_id": payload[4:12],
        "seq_id": struct.unpack("!H", payload[20:22])[0],
        "status": status_valtime,
        "command_type": command_type,
        "descriptor_type": struct.unpack("!H", payload[24:26])[0],
        "descriptor_index": struct.unpack("!H", payload[26:28])[0],
        "clock_source_index": struct.unpack("!H", payload[28:30])[0],
    }
    return result


def send_clock_source(sock, interface: str, mac: bytes, controller_id: bytes,
                      target_id: bytes, target_mac: bytes, seq_id: int,
                      clock_domain_index: int = 0,
                      clock_source_index: int = None) -> dict:
    command_type = (AECP_CMD_GET_CLOCK_SOURCE if clock_source_index is None
                    else AECP_CMD_SET_CLOCK_SOURCE)
    msg = build_aecp_clock_source(
        controller_id, target_id, seq_id, command_type, clock_domain_index,
        0 if clock_source_index is None else clock_source_index)
    send_frame(sock, interface, target_mac, mac, msg)

    start = time.monotonic()
    while time.monotonic() - start < 3.0:
        result = recv_frame(sock, timeout=0.2)
        if result is None:
            continue
        src_mac_rx, payload = result
        resp = parse_aecp_clock_source_response(payload)
        if (resp and resp["target_id"] == target_id and
                resp["seq_id"] == seq_id and resp["command_type"] == command_type):
            return resp
    return None


def _encode_control_value(control_index: int, value: int = None,
                          value_type: str = None) -> bytes:
    if value is None:
        return b""
    if value_type is None:
        value_type = "uint8" if control_index == 0 else "int16"
    if value_type == "uint8":
        return struct.pack("!B", value & 0xFF)
    if value_type == "int16":
        return struct.pack("!h", value)
    raise ValueError(f"unsupported control value type: {value_type}")


def _decode_control_value(control_index: int, values: bytes):
    if control_index == 0:
        return values[0] if len(values) >= 1 else None
    return struct.unpack("!h", values[:2])[0] if len(values) >= 2 else None


def build_aecp_control(controller_id: bytes, target_id: bytes,
                       seq_id: int, command_type: int, control_index: int,
                       value: int = None, value_type: str = None) -> bytes:
    """Build AECP GET_CONTROL or SET_CONTROL for CONTROL descriptor.

    The ESP example uses CONTROL[0] IDENTIFY as a one-byte uint8 and
    CONTROL[1]/[2] volume/gain as signed int16 tenths of dB.
    """
    values = _encode_control_value(control_index, value, value_type)
    control_data_len = 18 + 2 + 4 + len(values)
    header = encode_atdecc_header(AVTP_SUBTYPE_AECP, AECP_MSG_AEM_COMMAND,
                                  0, 0, 0, control_data_len)
    aem = encode_aecp_aem_header(command_type)
    return (header
            + target_id
            + controller_id
            + struct.pack("!H", seq_id)
            + aem
            + struct.pack("!HH", AEM_DESC_TYPE_CONTROL, control_index)
            + values)


def parse_aecp_control_response(payload: bytes) -> dict:
    """Parse AECP GET_CONTROL or SET_CONTROL response."""
    if len(payload) < 28:
        return None
    subtype, msg_type, sv, version, status_valtime, cdl = decode_atdecc_header(payload[:4])
    if subtype != AVTP_SUBTYPE_AECP or msg_type != AECP_MSG_AEM_RESPONSE:
        return None
    command_type = (((payload[22] >> 2) & 0x3F) << 8) | payload[23]
    if command_type not in (AECP_CMD_SET_CONTROL, AECP_CMD_GET_CONTROL):
        return None
    desc_type, desc_index = struct.unpack("!HH", payload[24:28])
    return {
        "target_id": payload[4:12],
        "controller_id": payload[12:20],
        "seq_id": struct.unpack("!H", payload[20:22])[0],
        "status": status_valtime,
        "command_type": command_type,
        "descriptor_type": desc_type,
        "descriptor_index": desc_index,
        "values": payload[28:],
    }


def send_control(sock, interface: str, mac: bytes, controller_id: bytes,
                 target_id: bytes, target_mac: bytes, seq_id: int,
                 control_index: int, value: int = None,
                 value_type: str = None) -> dict:
    command_type = AECP_CMD_GET_CONTROL if value is None else AECP_CMD_SET_CONTROL
    msg = build_aecp_control(controller_id, target_id, seq_id, command_type,
                             control_index, value, value_type)
    send_frame(sock, interface, target_mac, mac, msg)

    start = time.monotonic()
    while time.monotonic() - start < 3.0:
        result = recv_frame(sock, timeout=0.2)
        if result is None:
            continue
        src_mac_rx, payload = result
        resp = parse_aecp_control_response(payload)
        if (resp and resp["target_id"] == target_id and
                resp["controller_id"] == controller_id and
                resp["seq_id"] == seq_id and
                resp["descriptor_index"] == control_index and
                resp["command_type"] == command_type):
            return resp
    return None


# ---------------------------------------------------------------------------
# ACMP message building
# ---------------------------------------------------------------------------

def build_acmp_message(msg_type: int, controller_id: bytes,
                       talker_id: bytes, listener_id: bytes,
                       talker_uid: int = 0, listener_uid: int = 0,
                       connection_count: int = 0, seq_id: int = 0,
                       stream_id: bytes = None, flags: int = 0) -> bytes:
    """Build an ACMP message.

    ACMP layout:
      header(4) + stream_id(8) + controller_entity_id(8) +
      talker_entity_id(8) + listener_entity_id(8) +
      talker_uid(2) + listener_uid(2) + stream_dest_addr(6) +
      connection_count(2) + seq_id(2) + flags(2) +
      stream_vlan_id(2) + conn_listeners_entries(2)
    Total body: 52 bytes, but IEEE 1722.1-2021 specifies control_data_len = 84
    """
    if stream_id is None:
        stream_id = b"\x00" * 8

    header = encode_atdecc_header(AVTP_SUBTYPE_ACMP, msg_type, 0, 0, 0,
                                  ACMP_CONTROL_DATA_LEN)
    msg = (header
           + stream_id                          # stream_id (8)
           + controller_id                      # controller_entity_id (8)
           + talker_id                          # talker_entity_id (8)
           + listener_id                        # listener_entity_id (8)
           + struct.pack("!H", talker_uid)      # talker_uid (2)
           + struct.pack("!H", listener_uid)    # listener_uid (2)
           + b"\x00" * 6                        # stream_dest_addr (6)
           + struct.pack("!H", connection_count) # connection_count (2)
           + struct.pack("!H", seq_id)          # seq_id (2)
           + struct.pack("!H", flags)           # flags (2)
           + struct.pack("!H", 0)               # stream_vlan_id (2)
           + struct.pack("!H", 0))              # conn_listeners_entries (2)

    # Pad to full ACMP size: header(4) + control_data_len(84) = 88 bytes total
    # But our ACMP wire size should be 4 (header) + 84 = 88
    # What we built: 4 + 8+8+8+8+2+2+6+2+2+2+2+2 = 4 + 52 = 56
    # Pad remaining 32 bytes (extended ACMP fields or padding)
    if len(msg) < 4 + ACMP_CONTROL_DATA_LEN:
        msg += b"\x00" * (4 + ACMP_CONTROL_DATA_LEN - len(msg))

    return msg


def parse_acmp_response(payload: bytes) -> dict:
    """Parse an ACMP response message."""
    if len(payload) < 56:
        return None

    subtype, msg_type, sv, version, status_valtime, cdl = decode_atdecc_header(payload[:4])
    if subtype != AVTP_SUBTYPE_ACMP:
        return None

    body = payload[4:]
    stream_id = body[0:8]
    controller_id = body[8:16]
    talker_id = body[16:24]
    listener_id = body[24:32]
    talker_uid = struct.unpack("!H", body[32:34])[0]
    listener_uid = struct.unpack("!H", body[34:36])[0]
    stream_dest_addr = body[36:42]
    connection_count = struct.unpack("!H", body[42:44])[0]
    seq_id = struct.unpack("!H", body[44:46])[0]
    flags = struct.unpack("!H", body[46:48])[0]
    stream_vlan_id = struct.unpack("!H", body[48:50])[0]

    status_name = ACMP_STATUS_NAMES.get(status_valtime, f"UNKNOWN({status_valtime})")

    return {
        "msg_type": msg_type,
        "status": status_valtime,
        "status_name": status_name,
        "stream_id": format_entity_id(stream_id),
        "controller_id": format_entity_id(controller_id),
        "talker_id": format_entity_id(talker_id),
        "listener_id": format_entity_id(listener_id),
        "talker_uid": talker_uid,
        "listener_uid": listener_uid,
        "stream_dest_addr": format_mac(stream_dest_addr),
        "connection_count": connection_count,
        "seq_id": seq_id,
        "flags": flags,
        "stream_vlan_id": stream_vlan_id,
    }


# ---------------------------------------------------------------------------
# AECP: GET_STREAM_INFO
# ---------------------------------------------------------------------------

def build_aecp_get_stream_info(controller_id: bytes, target_id: bytes,
                               seq_id: int, descriptor_type: int,
                               descriptor_index: int = 0) -> bytes:
    """Build an AECP GET_STREAM_INFO command."""
    # Uses aecp_aem_short_s format: common(22) + aem(2) + desc_type(2) + desc_index(2) = 28
    # control_data_len = 28 - 4 = 24
    control_data_len = 24

    header = encode_atdecc_header(AVTP_SUBTYPE_AECP, AECP_MSG_AEM_COMMAND,
                                  0, 0, 0, control_data_len)
    aem = encode_aecp_aem_header(AECP_CMD_GET_STREAM_INFO)
    msg = (header
           + target_id
           + controller_id
           + struct.pack("!H", seq_id)
           + aem
           + struct.pack("!HH", descriptor_type, descriptor_index))
    return msg


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_discover(interface: str, duration: float = 5.0, show_streams: bool = False) -> None:
    """Discover AVB entities on the network via ADP."""
    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    print(f"Interface:     {interface}")
    print(f"MAC address:   {format_mac(mac)}")
    print(f"Controller ID: {format_entity_id(controller_id)}")
    print(f"Discovering entities for {duration:.0f} seconds...\n")

    sock = open_raw_socket(interface)
    entities = {}  # entity_id_str -> entity info dict
    entity_names = {}  # entity_id_str -> name
    entity_streams = {}  # entity_id_str -> list of stream descriptor dicts
    aecp_seq_id = 1
    name_requests_sent = set()  # entity_id_str
    stream_requests_sent = set()  # (entity_id_str, desc_type, index) tuples
    strings_requests_sent = set()  # (entity_id_str, strings_desc_index)
    # Pending localized name lookups: list of (stream_dict_ref, string_offset)
    # keyed by (entity_id_str, strings_desc_index)
    strings_pending = {}  # (eid_str, strings_idx) -> [(stream_dict, string_offset), ...]

    start = time.monotonic()
    try:
        while time.monotonic() - start < duration:
            result = recv_frame(sock, timeout=0.1)
            if result is None:
                continue

            src_mac, payload = result
            if len(payload) < 4:
                continue

            subtype = payload[0]

            # Handle ADP
            if subtype == AVTP_SUBTYPE_ADP:
                entity = parse_adp_entity(payload)
                if entity is not None:
                    eid_str = entity["entity_id_str"]
                    entity["src_mac"] = format_mac(src_mac)
                    entity["src_mac_raw"] = src_mac
                    entities[eid_str] = entity

                    # Request entity name if not already done
                    if eid_str not in name_requests_sent:
                        name_requests_sent.add(eid_str)
                        msg = build_aecp_read_descriptor(
                            controller_id, entity["entity_id"],
                            aecp_seq_id, AEM_DESC_TYPE_ENTITY, 0
                        )
                        send_frame(sock, interface, src_mac, mac, msg)
                        aecp_seq_id += 1

                        # Request stream output descriptors
                        for idx in range(entity["talker_stream_sources"]):
                            key = (eid_str, AEM_DESC_TYPE_STREAM_OUTPUT, idx)
                            if key not in stream_requests_sent:
                                stream_requests_sent.add(key)
                                msg = build_aecp_read_descriptor(
                                    controller_id, entity["entity_id"],
                                    aecp_seq_id, AEM_DESC_TYPE_STREAM_OUTPUT, idx
                                )
                                send_frame(sock, interface, src_mac, mac, msg)
                                aecp_seq_id += 1

                        # Request stream input descriptors
                        for idx in range(entity["listener_stream_sinks"]):
                            key = (eid_str, AEM_DESC_TYPE_STREAM_INPUT, idx)
                            if key not in stream_requests_sent:
                                stream_requests_sent.add(key)
                                msg = build_aecp_read_descriptor(
                                    controller_id, entity["entity_id"],
                                    aecp_seq_id, AEM_DESC_TYPE_STREAM_INPUT, idx
                                )
                                send_frame(sock, interface, src_mac, mac, msg)
                                aecp_seq_id += 1

            # Handle AECP responses
            elif subtype == AVTP_SUBTYPE_AECP:
                resp = parse_aecp_read_descriptor_response(payload)
                if resp is None:
                    continue
                tid_str = format_entity_id(resp["target_id"])

                if "entity_name" in resp:
                    entity_names[tid_str] = resp["entity_name"]

                if "stream_name" in resp:
                    if tid_str not in entity_streams:
                        entity_streams[tid_str] = []
                    direction = "Output" if resp["descriptor_type"] == AEM_DESC_TYPE_STREAM_OUTPUT else "Input"

                    # Compute sample rate, bit depth, channel ranges, and base formats
                    sample_rates = []
                    bit_depths = []
                    channels = []
                    base_formats = []
                    for fmt_bytes in resp.get("supported_formats", []):
                        info = _extract_format_info(fmt_bytes)
                        if info.get("base_format"):
                            base_formats.append(info["base_format"])
                        if info.get("sample_rate"):
                            sample_rates.append(info["sample_rate"])
                        if info.get("bit_depth"):
                            bit_depths.append(info["bit_depth"])
                        if info.get("channels"):
                            channels.append(info["channels"])

                    stream_entry = {
                        "direction": direction,
                        "index": resp["descriptor_index"],
                        "name": resp.get("stream_name", ""),
                        "format": resp.get("current_format_str", "unknown"),
                        "num_formats": resp.get("number_of_formats", 0),
                        "base_formats": sorted(set(base_formats)),
                        "sample_rates": sorted(set(sample_rates)),
                        "bit_depths": sorted(set(bit_depths)),
                        "max_channels": max(channels) if channels else None,
                    }
                    entity_streams[tid_str].append(stream_entry)

                    # If object_name is empty, request localized name via STRINGS descriptor
                    if not stream_entry["name"]:
                        loc_desc = resp.get("localized_description", 0xFFFF)
                        if loc_desc != 0xFFFF:
                            strings_idx = loc_desc >> 3
                            string_offset = loc_desc & 0x07
                            key = (tid_str, strings_idx)
                            # Track which stream entry needs this string
                            strings_pending.setdefault(key, []).append(
                                (stream_entry, string_offset))
                            if key not in strings_requests_sent:
                                strings_requests_sent.add(key)
                                msg = build_aecp_read_descriptor(
                                    controller_id, resp["target_id"],
                                    aecp_seq_id, AEM_DESC_TYPE_STRINGS,
                                    strings_idx
                                )
                                send_frame(sock, interface, src_mac, mac, msg)
                                aecp_seq_id += 1

                # Handle STRINGS descriptor responses
                if "strings" in resp:
                    key = (tid_str, resp["descriptor_index"])
                    if key in strings_pending:
                        for stream_entry, string_offset in strings_pending[key]:
                            if string_offset < len(resp["strings"]):
                                stream_entry["name"] = resp["strings"][string_offset]
                        del strings_pending[key]

    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    if not entities:
        print("No entities discovered.")
        return

    # Merge names
    for eid_str, info in entities.items():
        info["entity_name"] = entity_names.get(eid_str, "")

    # Print table
    print(f"{'Entity ID':<26} {'Name':<20} {'Model ID':<26} {'Roles':<22} {'MAC':<18} {'Streams'}")
    print("-" * 136)
    for eid_str, info in sorted(entities.items()):
        streams = []
        if info["talker_stream_sources"] > 0:
            streams.append(f"TX:{info['talker_stream_sources']}")
        if info["listener_stream_sinks"] > 0:
            streams.append(f"RX:{info['listener_stream_sinks']}")
        streams_str = ", ".join(streams) if streams else "-"

        print(f"{eid_str:<26} {info['entity_name'][:20]:<20} {info['model_id_str']:<26} "
              f"{info['roles']:<22} {info['src_mac']:<18} {streams_str}")

    # gPTP grandmaster (BTC) each entity is locked to (advertised in ADP)
    print(f"\ngPTP grandmaster (BTC) each entity is locked to:")
    by_gm = {}
    for eid_str, info in entities.items():
        gm = info.get("gptp_gm_id_str", "?")
        by_gm.setdefault(gm, []).append(
            (info.get("entity_name") or eid_str, eid_str,
             info.get("gptp_domain", "?")))
    for gm in sorted(by_gm):
        members = by_gm[gm]
        print(f"  BTC {gm} (domain {members[0][2]}):")
        for name, eid, _ in sorted(members):
            print(f"      {name} [{eid}]")

    # Print stream descriptors per entity
    if entity_streams and show_streams:
        print("\n--- Stream Descriptors ---")
        for eid_str in sorted(entities.keys()):
            if eid_str not in entity_streams:
                continue
            name = entity_names.get(eid_str, eid_str)
            label = f"{name} ({eid_str})" if name else eid_str
            print(f"\n  {label}:")
            # Sort by direction (Output first) then index
            sorted_streams = sorted(entity_streams[eid_str],
                                    key=lambda s: (0 if s["direction"] == "Output" else 1, s["index"]))
            for sd in sorted_streams:
                name = sd.get("name", "")
                name_str = f" ({name})" if name else ""
                print(f"    Stream {sd['direction']}[{sd['index']}]{name_str}: "
                      f"Cur Set Format: {sd['format']:<28} "
                      f"Supported Formats: {sd['num_formats']}")

            # Print supported format ranges
            has_ranges = any(sd["sample_rates"] or sd["bit_depths"] or sd["base_formats"]
                            for sd in sorted_streams)
            if has_ranges:
                print(f"\n    Supported Format Ranges:")
                for sd in sorted_streams:
                    sr = sd["sample_rates"]
                    bd = sd["bit_depths"]
                    mc = sd["max_channels"]
                    bf = sd["base_formats"]
                    if not sr and not bd and mc is None and not bf:
                        continue
                    parts = []
                    if bf:
                        parts.append(f"Formats: {', '.join(bf)}")
                    if sr:
                        lo = _format_rate_hz(sr[0])
                        hi = _format_rate_hz(sr[-1])
                        parts.append(f"Sample Rate: {lo}-{hi}" if lo != hi else f"Sample Rate: {lo}")
                    if bd:
                        parts.append(f"Bit Depth: {bd[0]}-{bd[-1]}bit" if bd[0] != bd[-1] else f"Bit Depth: {bd[0]}bit")
                    if mc is not None:
                        parts.append(f"Max Channels: {mc}")
                    print(f"      Stream {sd['direction']}[{sd['index']}]: {'  '.join(parts)}")

    print(f"\nTotal: {len(entities)} entity(ies) discovered.")


def cmd_stream_info(interface: str, entity_id_str: str) -> None:
    """Query stream info for all input and output streams of an entity."""
    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    entity_id = parse_entity_id(entity_id_str)

    print(f"Interface:     {interface}")
    print(f"Entity ID:     {entity_id_str}")

    sock = open_raw_socket(interface)

    # Resolve MAC
    entity_mac = _resolve_mac(sock, interface, mac, entity_id, duration=3.0)
    print(f"Entity MAC:    {format_mac(entity_mac)}")

    seq_id = int(time.monotonic() * 1000) & 0xFFFF

    # Query output streams 0-3 and input streams 0-3
    for desc_type, desc_name in [(AEM_DESC_TYPE_STREAM_OUTPUT, "OUTPUT"),
                                  (AEM_DESC_TYPE_STREAM_INPUT, "INPUT")]:
        for idx in range(4):
            msg = build_aecp_get_stream_info(
                controller_id, entity_id, seq_id, desc_type, idx)
            send_frame(sock, interface, entity_mac, mac, msg)
            seq_id += 1

            # Wait for response
            start = time.monotonic()
            got_response = False
            while time.monotonic() - start < 2.0:
                result = recv_frame(sock, timeout=0.2)
                if result is None:
                    continue
                src_mac_rx, payload = result
                if len(payload) < 4:
                    continue
                subtype, msg_type, sv, version, status, cdl = decode_atdecc_header(payload[:4])
                if subtype != AVTP_SUBTYPE_AECP or msg_type != AECP_MSG_AEM_RESPONSE:
                    continue
                # Check target matches
                if len(payload) < 12 or payload[4:12] != entity_id:
                    continue

                got_response = True
                if status != 0:
                    # Non-zero status means no such descriptor — stop querying this type
                    break

                # Parse GET_STREAM_INFO response
                # After header(4) + target(8) + controller(8) + seq(2) + aem(2) = 24
                # descriptor_type(2) + descriptor_index(2) = 4
                # stream_info_flags(4) + stream_format(8) + stream_id(8) +
                # msrp_acc_lat(4) + dest_addr(6) + msrp_failure_code(1) + reserved(1) +
                # msrp_failure_bridge_id(8) + vlan_id(2)
                body = payload[28:]  # after header+aecp_common+aem+desc_type+desc_index
                if len(body) < 42:
                    print(f"\n  STREAM {desc_name}[{idx}]: response too short ({len(body)} bytes)")
                    break

                # Parse flags as a 32-bit network-order field per IEEE
                # 1722.1-2021 Table 7-145.
                flags_raw = body[0:4]
                flags = struct.unpack("!I", flags_raw)[0]
                fmt_valid = bool(flags & 0x80000000)
                stream_id_valid = bool(flags & 0x40000000)
                acc_lat_valid = bool(flags & 0x20000000)
                dest_mac_valid = bool(flags & 0x10000000)
                msrp_fail_valid = bool(flags & 0x08000000)
                connected = bool(flags & 0x04000000)
                vlan_valid = bool(flags & 0x02000000)
                no_srp = bool(flags & 0x00000100)
                talker_failed = bool(flags & 0x00000040)
                streaming_wait = bool(flags & 0x00000008)
                class_b = bool(flags & 0x00000001)

                stream_format = body[4:12]
                stream_id = body[12:20]
                acc_latency = struct.unpack("!I", body[20:24])[0]
                dest_addr = body[24:30]
                msrp_fail_code = body[30]
                vlan_id = struct.unpack("!H", body[40:42])[0] if len(body) >= 42 else 0

                fmt_str = _format_stream_format(stream_format)

                print(f"\n  STREAM {desc_name}[{idx}]:")
                print(f"    Format:        {fmt_str} {'(valid)' if fmt_valid else '(invalid)'}")
                print(f"    Stream ID:     {format_entity_id(stream_id)} {'(valid)' if stream_id_valid else ''}")
                print(f"    Connected:     {connected}")
                print(f"    Dest MAC:      {format_mac(dest_addr)} {'(valid)' if dest_mac_valid else ''}")
                print(f"    VLAN ID:       {vlan_id} {'(valid)' if vlan_valid else ''}")
                print(f"    Class:         {'B' if class_b else 'A'}")
                print(f"    Talker Failed: {talker_failed}")
                print(f"    Streaming Wait:{streaming_wait}")
                print(f"    MSRP Fail:     code={msrp_fail_code} {'(valid)' if msrp_fail_valid else ''}")
                print(f"    Acc Latency:   {acc_latency}ns {'(valid)' if acc_lat_valid else ''}")
                print(f"    Raw format:    {stream_format.hex()}")
                break

            if not got_response:
                break  # no more streams of this type
            if status != 0:
                break

    sock.close()


def cmd_connect(interface: str, talker_id_str: str, listener_id_str: str,
                format_name: str = None, talker_uid: int = 0,
                listener_uid: int = 0, match_supported: bool = False,
                class_b: bool = False) -> None:
    """Connect a talker to a listener via ACMP CONNECT_RX_COMMAND.

    If format_name is given, sets stream format on both talker (output) and
    listener (input) before connecting. With match_supported=True, query each
    endpoint's supported_formats list first and pick the closest match — useful
    when the desired format's exact byte encoding isn't in the device's list
    (e.g. AAF PCM32 vs PCM24 byte-3 differences).

    With class_b=True the ACMP flags field is sent with bit 15 (CLASS_B) set
    per IEEE 1722.1-2021 §8.2.1.16 Table 8-4, selecting SR Class B
    (priority 2, 250 µs observation interval) for this connection. Default
    (False) requests Class A (priority 3, 125 µs).
    """
    if format_name:
        # Resolve aliases
        format_name = FORMAT_ALIASES.get(format_name, format_name)
        if format_name not in STREAM_FORMATS:
            avail = ", ".join(sorted(list(STREAM_FORMATS.keys()) + list(FORMAT_ALIASES.keys())))
            print(f"Unknown format '{format_name}'. Available: {avail}")
            sys.exit(1)

        requested_format = STREAM_FORMATS[format_name]
        mac = get_mac_address(interface)
        controller_id = mac_to_entity_id(mac)
        talker_id = parse_entity_id(talker_id_str)
        listener_id = parse_entity_id(listener_id_str)

        sock = open_raw_socket(interface)
        seq_id = int(time.monotonic() * 1000) & 0xFFFF

        # We need the MAC addresses of the target devices to send AECP unicast.
        # First try to find them from a quick ADP discovery, fall back to
        # EUI-64 → EUI-48 derivation (remove FF:FE bytes 3-4).
        talker_mac = _resolve_mac(sock, interface, mac, talker_id, duration=2.0)
        listener_mac = _resolve_mac(sock, interface, mac, listener_id, duration=2.0)

        talker_format = requested_format
        listener_format = requested_format
        if match_supported:
            print(f"Querying supported formats (target: '{format_name}')...")
            talker_supported = query_supported_formats(
                sock, interface, mac, controller_id, talker_id, talker_mac,
                AEM_DESC_TYPE_STREAM_OUTPUT, 0, seq_id)
            seq_id += 1
            listener_supported = query_supported_formats(
                sock, interface, mac, controller_id, listener_id, listener_mac,
                AEM_DESC_TYPE_STREAM_INPUT, 0, seq_id)
            seq_id += 1
            if not talker_supported:
                print(f"  Warning: no supported_formats from talker; falling back to '{format_name}' bytes")
            else:
                picked, info, _ = pick_closest_format(requested_format, talker_supported)
                talker_format = picked
                print(f"  Talker pick:   {_format_stream_format(picked)} "
                      f"({picked.hex()})")
            if not listener_supported:
                print(f"  Warning: no supported_formats from listener; falling back to '{format_name}' bytes")
            else:
                picked, info, _ = pick_closest_format(requested_format, listener_supported)
                listener_format = picked
                print(f"  Listener pick: {_format_stream_format(picked)} "
                      f"({picked.hex()})")
        else:
            print(f"Setting stream format to '{format_name}' on both endpoints...")

        # Set format on talker output stream (descriptor_type=STREAM_OUTPUT, index=0)
        ok1 = send_set_stream_format(sock, interface, mac, controller_id,
                                      talker_id, talker_mac,
                                      AEM_DESC_TYPE_STREAM_OUTPUT, 0,
                                      talker_format, seq_id)
        seq_id += 1

        # Set format on listener input stream (descriptor_type=STREAM_INPUT, index=0)
        ok2 = send_set_stream_format(sock, interface, mac, controller_id,
                                      listener_id, listener_mac,
                                      AEM_DESC_TYPE_STREAM_INPUT, 0,
                                      listener_format, seq_id + 1)
        sock.close()

        if not ok1:
            print("Warning: failed to set format on talker")
        if not ok2:
            print("Warning: failed to set format on listener")
        print()

    _acmp_command(interface, talker_id_str, listener_id_str,
                  ACMP_MSG_CONNECT_RX_COMMAND, "CONNECT_RX_COMMAND",
                  ACMP_MSG_CONNECT_RX_RESPONSE, "CONNECT_RX_RESPONSE",
                  talker_uid=talker_uid, listener_uid=listener_uid,
                  flags=(0x8000 if class_b else 0))


def cmd_disconnect(interface: str, talker_id_str: str, listener_id_str: str,
                   talker_uid: int = 0, listener_uid: int = 0) -> None:
    """Disconnect a talker from a listener via ACMP DISCONNECT_RX_COMMAND."""
    _acmp_command(interface, talker_id_str, listener_id_str,
                  ACMP_MSG_DISCONNECT_RX_COMMAND, "DISCONNECT_RX_COMMAND",
                  ACMP_MSG_DISCONNECT_RX_RESPONSE, "DISCONNECT_RX_RESPONSE",
                  talker_uid=talker_uid, listener_uid=listener_uid)


def cmd_get_tx_state(interface: str, talker_id_str: str, talker_uid: int) -> None:
    """Query GET_TX_STATE on a talker to see its ACMP connection_count."""
    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    talker_id = parse_entity_id(talker_id_str)

    print(f"Interface:     {interface}")
    print(f"Controller ID: {format_entity_id(controller_id)}")
    print(f"Target talker: {talker_id_str} (uid={talker_uid})")
    print(f"Sending GET_TX_STATE_COMMAND...")

    sock = open_raw_socket(interface)
    seq_id = int(time.monotonic() * 1000) & 0xFFFF

    msg = build_acmp_message(
        msg_type=ACMP_MSG_GET_TX_STATE_COMMAND,
        controller_id=controller_id,
        talker_id=talker_id,
        listener_id=b"\x00" * 8,
        talker_uid=talker_uid,
        listener_uid=0,
        connection_count=0,
        seq_id=seq_id,
    )
    send_frame(sock, interface, ACMP_MULTICAST, mac, msg)

    start = time.monotonic()
    while time.monotonic() - start < 3.0:
        result = recv_frame(sock, timeout=0.2)
        if result is None:
            continue
        _, payload = result
        if len(payload) < 4 or payload[0] != AVTP_SUBTYPE_ACMP:
            continue
        resp = parse_acmp_response(payload)
        if resp is None or resp["msg_type"] != ACMP_MSG_GET_TX_STATE_RESPONSE:
            continue
        if resp["seq_id"] != seq_id:
            continue
        print(f"\nReceived GET_TX_STATE_RESPONSE:")
        print(f"  Status:            {resp['status_name']}")
        print(f"  Stream ID:         {resp['stream_id']}")
        print(f"  Talker:            {resp['talker_id']} uid={resp['talker_uid']}")
        print(f"  Listener:          {resp['listener_id']} uid={resp['listener_uid']}")
        print(f"  Stream Dest MAC:   {resp['stream_dest_addr']}")
        print(f"  Connection Count:  {resp['connection_count']}  <-- key field")
        print(f"  Flags:             0x{resp['flags']:04x}")
        print(f"  Stream VLAN ID:    {resp['stream_vlan_id']}")
        return
    print("No GET_TX_STATE_RESPONSE received within 3 s.")


def cmd_direct_disconnect_tx(interface: str, talker_id_str: str,
                             listener_id_str: str, talker_uid: int,
                             listener_uid: int) -> None:
    """Send ACMP DISCONNECT_TX_COMMAND directly to a talker (bypassing
    the listener). Useful for probing how the talker's ACMP state
    machine reacts to an explicit disconnect."""
    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    talker_id = parse_entity_id(talker_id_str)
    listener_id = parse_entity_id(listener_id_str)

    print(f"Interface:     {interface}")
    print(f"Controller ID: {format_entity_id(controller_id)}")
    print(f"Talker:        {talker_id_str} uid={talker_uid}")
    print(f"Listener:      {listener_id_str} uid={listener_uid}")
    print(f"Sending DISCONNECT_TX_COMMAND directly to talker...")

    sock = open_raw_socket(interface)
    seq_id = int(time.monotonic() * 1000) & 0xFFFF
    msg = build_acmp_message(
        msg_type=ACMP_MSG_DISCONNECT_TX_COMMAND,
        controller_id=controller_id,
        talker_id=talker_id,
        listener_id=listener_id,
        talker_uid=talker_uid,
        listener_uid=listener_uid,
        connection_count=0,
        seq_id=seq_id,
    )
    send_frame(sock, interface, ACMP_MULTICAST, mac, msg)

    start = time.monotonic()
    while time.monotonic() - start < 3.0:
        result = recv_frame(sock, timeout=0.2)
        if result is None:
            continue
        _, payload = result
        if len(payload) < 4 or payload[0] != AVTP_SUBTYPE_ACMP:
            continue
        resp = parse_acmp_response(payload)
        if resp is None or resp["msg_type"] != ACMP_MSG_DISCONNECT_TX_RESPONSE:
            continue
        if resp["seq_id"] != seq_id:
            continue
        print(f"\nReceived DISCONNECT_TX_RESPONSE:")
        print(f"  Status:            {resp['status_name']}")
        print(f"  Connection Count:  {resp['connection_count']}")
        print(f"  Stream ID:         {resp['stream_id']}")
        return
    print("No DISCONNECT_TX_RESPONSE received within 3 s.")


def _acmp_command(interface: str, talker_id_str: str, listener_id_str: str,
                  cmd_type: int, cmd_name: str,
                  rsp_type: int, rsp_name: str,
                  talker_uid: int = 0, listener_uid: int = 0,
                  flags: int = 0) -> None:
    """Send an ACMP command and wait for a response."""
    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    talker_id = parse_entity_id(talker_id_str)
    listener_id = parse_entity_id(listener_id_str)

    print(f"Interface:     {interface}")
    print(f"Controller ID: {format_entity_id(controller_id)}")
    print(f"Talker ID:     {talker_id_str}")
    print(f"Listener ID:   {listener_id_str}")
    print(f"Sending {cmd_name}...")

    sock = open_raw_socket(interface)
    seq_id = int(time.monotonic() * 1000) & 0xFFFF

    msg = build_acmp_message(
        msg_type=cmd_type,
        controller_id=controller_id,
        talker_id=talker_id,
        listener_id=listener_id,
        talker_uid=talker_uid,
        listener_uid=listener_uid,
        connection_count=1,
        seq_id=seq_id,
        flags=flags,
    )

    send_frame(sock, interface, ACMP_MULTICAST, mac, msg)

    # Wait for response (timeout 5 seconds)
    timeout = 5.0
    start = time.monotonic()
    try:
        while time.monotonic() - start < timeout:
            result = recv_frame(sock, timeout=0.2)
            if result is None:
                continue

            src_mac, payload = result
            if len(payload) < 4:
                continue

            subtype = payload[0]
            if subtype != AVTP_SUBTYPE_ACMP:
                continue

            resp = parse_acmp_response(payload)
            if resp is None:
                continue

            # Accept any ACMP response related to our command
            if resp["msg_type"] in (rsp_type,
                                     ACMP_MSG_CONNECT_TX_RESPONSE,
                                     ACMP_MSG_DISCONNECT_TX_RESPONSE):
                rtype_name = {
                    ACMP_MSG_CONNECT_RX_RESPONSE: "CONNECT_RX_RESPONSE",
                    ACMP_MSG_DISCONNECT_RX_RESPONSE: "DISCONNECT_RX_RESPONSE",
                    ACMP_MSG_CONNECT_TX_RESPONSE: "CONNECT_TX_RESPONSE",
                    ACMP_MSG_DISCONNECT_TX_RESPONSE: "DISCONNECT_TX_RESPONSE",
                }.get(resp["msg_type"], f"type={resp['msg_type']}")

                print(f"\nReceived {rtype_name}:")
                print(f"  Status:           {resp['status_name']}")
                print(f"  Stream ID:        {resp['stream_id']}")
                print(f"  Talker:           {resp['talker_id']}")
                print(f"  Listener:         {resp['listener_id']}")
                print(f"  Stream Dest MAC:  {resp['stream_dest_addr']}")
                print(f"  Connection Count: {resp['connection_count']}")
                print(f"  VLAN ID:          {resp['stream_vlan_id']}")

                if resp["msg_type"] == rsp_type:
                    sock.close()
                    if resp["status"] == 0:
                        print("\nCommand completed successfully.")
                    else:
                        print(f"\nCommand failed: {resp['status_name']}")
                        sys.exit(1)
                    return

        print(f"\nTimeout: no {rsp_name} received within {timeout:.0f} seconds.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
    finally:
        sock.close()


def cmd_clock_source(interface: str, entity_id_str: str,
                     clock_domain_index: int = 0,
                     clock_source_index: int = None) -> None:
    """Get or set CLOCK_DOMAIN current CLOCK_SOURCE via AECP."""
    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    target_id = parse_entity_id(entity_id_str)

    sock = open_raw_socket(interface)
    try:
        target_mac = _resolve_mac(sock, interface, mac, target_id)
        seq_id = int(time.monotonic() * 1000) & 0xFFFF
        op = "GET_CLOCK_SOURCE" if clock_source_index is None else "SET_CLOCK_SOURCE"
        print(f"Interface:     {interface}")
        print(f"Controller ID: {format_entity_id(controller_id)}")
        print(f"Entity ID:     {entity_id_str}")
        print(f"Entity MAC:    {format_mac(target_mac)}")
        print(f"Command:       {op}")
        print(f"Clock Domain:  {clock_domain_index}")
        if clock_source_index is not None:
            print(f"Clock Source:  {clock_source_index}")

        resp = send_clock_source(sock, interface, mac, controller_id,
                                 target_id, target_mac, seq_id,
                                 clock_domain_index, clock_source_index)
        if resp is None:
            print(f"Timeout: no {op}_RESPONSE received within 3 seconds.")
            sys.exit(1)
        status_name = {0: "SUCCESS", 1: "NOT_IMPLEMENTED", 2: "NO_SUCH_DESCRIPTOR",
                       3: "ENTITY_LOCKED", 4: "ENTITY_ACQUIRED",
                       9: "NOT_SUPPORTED", 12: "ENTITY_MISBEHAVING",
                       13: "NOT_AUTHENTICATED", 14: "AUTHENTICATION_DISABLED",
                       15: "BAD_ARGUMENTS", 16: "NO_RESOURCES",
                       17: "IN_PROGRESS", 18: "ENTITY_NOT_READY",
                       19: "STREAM_IS_RUNNING"}.get(resp["status"], f"ERROR({resp['status']})")
        print(f"\nReceived {op}_RESPONSE:")
        print(f"  Status:              {status_name}")
        print(f"  Descriptor Type:     0x{resp['descriptor_type']:04x}")
        print(f"  Clock Domain Index:  {resp['descriptor_index']}")
        print(f"  Clock Source Index:  {resp['clock_source_index']}")
        if resp["status"] != 0:
            sys.exit(1)
    finally:
        sock.close()


AECP_STATUS_NAMES = {0: "SUCCESS", 1: "NOT_IMPLEMENTED", 2: "NO_SUCH_DESCRIPTOR",
                    3: "ENTITY_LOCKED", 4: "ENTITY_ACQUIRED",
                    9: "NOT_SUPPORTED", 12: "ENTITY_MISBEHAVING",
                    13: "NOT_AUTHENTICATED", 14: "AUTHENTICATION_DISABLED",
                    15: "BAD_ARGUMENTS", 16: "NO_RESOURCES",
                    17: "IN_PROGRESS", 18: "ENTITY_NOT_READY"}


def _cmd_control(interface: str, entity_id_str: str, control_index: int,
                 name: str, value: int = None, value_type: str = None) -> None:
    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    target_id = parse_entity_id(entity_id_str)

    sock = open_raw_socket(interface)
    try:
        target_mac = _resolve_mac(sock, interface, mac, target_id)
        seq_id = int(time.monotonic() * 1000) & 0xFFFF
        op = "GET_CONTROL" if value is None else "SET_CONTROL"
        print(f"Interface:     {interface}")
        print(f"Controller ID: {format_entity_id(controller_id)}")
        print(f"Entity ID:     {entity_id_str}")
        print(f"Entity MAC:    {format_mac(target_mac)}")
        print(f"Command:       {op} {name}")
        if value is not None:
            if control_index == 0:
                print(f"Value:         {value}")
            else:
                print(f"Value:         {value / 10.0:.1f} dB ({value} tenths dB)")

        resp = send_control(sock, interface, mac, controller_id,
                            target_id, target_mac, seq_id,
                            control_index=control_index, value=value,
                            value_type=value_type)
        if resp is None:
            print(f"Timeout: no {op}_RESPONSE received within 3 seconds.")
            sys.exit(1)
        status_name = AECP_STATUS_NAMES.get(resp["status"], f"ERROR({resp['status']})")
        echoed = _decode_control_value(control_index, resp["values"])
        print(f"\nReceived {op}_RESPONSE:")
        print(f"  Status:          {status_name}")
        print(f"  Descriptor Type: 0x{resp['descriptor_type']:04x}")
        print(f"  Control Index:   {resp['descriptor_index']}")
        if control_index == 0:
            print(f"  Value:           {echoed}")
        else:
            db = echoed / 10.0 if echoed is not None else None
            print(f"  Value:           {db:.1f} dB ({echoed} tenths dB)" if echoed is not None
                  else "  Value:           <missing>")
        if resp["status"] != 0:
            sys.exit(1)
    finally:
        sock.close()


def cmd_identify(interface: str, entity_id_str: str, value: int = 1) -> None:
    """Set CONTROL[0] IDENTIFY via AECP SET_CONTROL."""
    _cmd_control(interface, entity_id_str, 0, "IDENTIFY", value, "uint8")


def cmd_volume(interface: str, entity_id_str: str, value_tenth_db: int = None) -> None:
    """Get or set CONTROL[1] Speaker Volume."""
    _cmd_control(interface, entity_id_str, 1, "Speaker Volume", value_tenth_db, "int16")


def cmd_mic_gain(interface: str, entity_id_str: str, value_tenth_db: int = None) -> None:
    """Get or set CONTROL[2] Mic Gain."""
    _cmd_control(interface, entity_id_str, 2, "Mic Gain", value_tenth_db, "int16")


def _parse_descriptor_type(s: str) -> int:
    """Accept either a name (e.g. 'configuration') or a numeric value
    (decimal or 0x-prefixed hex)."""
    sl = s.strip().lower()
    if sl in AEM_DESC_TYPE_BY_NAME:
        return AEM_DESC_TYPE_BY_NAME[sl]
    try:
        return int(s, 0) & 0xFFFF
    except ValueError:
        raise SystemExit(
            f"unknown descriptor type '{s}'. "
            f"Names: {', '.join(sorted(AEM_DESC_TYPE_BY_NAME))} "
            f"— or pass a numeric value (decimal or 0x...).")


def build_aecp_get_avb_info(controller_id: bytes, target_id: bytes,
                            seq_id: int, descriptor_index: int = 0) -> bytes:
    """Build an AECP GET_AVB_INFO command for an AVB_INTERFACE descriptor."""
    # body after the 4-byte header: target(8)+controller(8)+seq(2)+aem(2)
    #   + descriptor_type(2) + descriptor_index(2) = 24
    control_data_len = 24
    header = encode_atdecc_header(AVTP_SUBTYPE_AECP, AECP_MSG_AEM_COMMAND,
                                  0, 0, 0, control_data_len)
    aem = encode_aecp_aem_header(AECP_CMD_GET_AVB_INFO)
    return (header
            + target_id
            + controller_id
            + struct.pack("!H", seq_id)
            + aem
            + struct.pack("!HH", AEM_DESC_TYPE_AVB_INTERFACE, descriptor_index))


def cmd_get_avb_info(interface: str, entity_id_str: str,
                     descriptor_index: int = 0) -> None:
    """Query an entity's gPTP/SRP state for an AVB_INTERFACE via AECP
    GET_AVB_INFO: the grandmaster (BTC) it is locked to, gPTP domain,
    AS_CAPABLE, gPTP/SRP enabled, and the measured propagation delay.

    Unlike READ_DESCRIPTOR(AVB_INTERFACE) — which returns the interface's
    OWN clock identity — GET_AVB_INFO reports the runtime gPTP state, i.e.
    which BTC this device is actually synchronized to."""
    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    entity_id = parse_entity_id(entity_id_str)

    print(f"Interface:         {interface}")
    print(f"Entity ID:         {entity_id_str}")
    print(f"AVB interface idx: {descriptor_index}")

    sock = open_raw_socket(interface)
    entity_mac = _resolve_mac(sock, interface, mac, entity_id, duration=3.0)
    print(f"Entity MAC:        {format_mac(entity_mac)}")

    seq_id = int(time.monotonic() * 1000) & 0xFFFF
    msg = build_aecp_get_avb_info(controller_id, entity_id, seq_id,
                                  descriptor_index)
    send_frame(sock, interface, entity_mac, mac, msg)

    start = time.monotonic()
    response = None
    while time.monotonic() - start < 2.0:
        result = recv_frame(sock, timeout=0.2)
        if result is None:
            continue
        _, payload = result
        if len(payload) < 24:
            continue
        subtype, msg_type, _, _, _, _ = decode_atdecc_header(payload[:4])
        if subtype != AVTP_SUBTYPE_AECP or msg_type != AECP_MSG_AEM_RESPONSE:
            continue
        if payload[4:12] != entity_id:
            continue
        cmd_type = (((payload[22] >> 2) & 0x3F) << 8) | payload[23]
        if cmd_type != AECP_CMD_GET_AVB_INFO:
            continue
        if struct.unpack("!H", payload[20:22])[0] != seq_id:
            continue
        response = payload
        break

    if response is None:
        print("\nNo response (timeout).")
        return

    aecp_status = (response[2] >> 3) & 0x1F
    if aecp_status != 0:
        names = {1: "NOT_IMPLEMENTED", 2: "NO_SUCH_DESCRIPTOR",
                 11: "NOT_SUPPORTED"}
        print(f"\nAECP status: {aecp_status} "
              f"({names.get(aecp_status, 'not SUCCESS')}) — entity may not "
              f"implement GET_AVB_INFO; the ADP-advertised grandmaster from "
              f"'discover' is the fallback.")
        return

    # Command-specific data starts at offset 24 (after AEM command_type):
    #   descriptor_type(2) descriptor_index(2) gptp_grandmaster_id(8)
    #   propagation_delay(4) gptp_domain_number(1) flags(1)
    #   msrp_mappings_count(2) ...
    if len(response) < 44:
        print(f"\nResponse too short ({len(response)} bytes).")
        return
    gm = response[28:36]
    propagation_delay = struct.unpack("!I", response[36:40])[0]
    domain = response[40]
    flags = response[41]
    msrp_count = struct.unpack("!H", response[42:44])[0]
    # AVB_INFO flags (IEEE 1722.1): bit0 AS_CAPABLE, bit1 GPTP_ENABLED,
    # bit2 SRP_ENABLED. Raw byte printed too for sanity-checking.
    print(f"\ngPTP grandmaster (BTC): {format_entity_id(gm)}")
    print(f"gPTP domain:            {domain}")
    print(f"AS_CAPABLE:             {bool(flags & 0x01)}")
    print(f"gPTP enabled:           {bool(flags & 0x02)}")
    print(f"SRP enabled:            {bool(flags & 0x04)}")
    print(f"propagation delay:      {propagation_delay} ns")
    print(f"MSRP mappings:          {msrp_count}")
    print(f"(raw flags: 0x{flags:02x})")


def cmd_read_descriptor(interface: str, entity_id_str: str,
                        descriptor: str, descriptor_index: int = 0,
                        configuration_index: int = 0) -> None:
    """Send AECP READ_DESCRIPTOR to an entity and dump the raw response.

    Useful for diagnosing controller-reported model errors (e.g. Hive's
    'a device is required to have at least one configuration descriptor')
    by inspecting exactly what the entity returns. Prints both a hex dump
    and a parsed summary for descriptor types this tool knows about
    (Entity, Configuration, Stream Input/Output, Strings)."""
    desc_type = _parse_descriptor_type(descriptor)
    desc_name = AEM_DESC_NAME_BY_TYPE.get(desc_type, f"0x{desc_type:04x}")

    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    entity_id = parse_entity_id(entity_id_str)

    print(f"Interface:         {interface}")
    print(f"Entity ID:         {entity_id_str}")
    print(f"Descriptor:        {desc_name} (0x{desc_type:04x})")
    print(f"Descriptor index:  {descriptor_index}")
    print(f"Config index:      {configuration_index}")

    sock = open_raw_socket(interface)
    entity_mac = _resolve_mac(sock, interface, mac, entity_id, duration=3.0)
    print(f"Entity MAC:        {format_mac(entity_mac)}")

    seq_id = int(time.monotonic() * 1000) & 0xFFFF
    msg = build_aecp_read_descriptor(controller_id, entity_id, seq_id,
                                     desc_type, descriptor_index)
    # build_aecp_read_descriptor uses configuration_index=0 internally;
    # patch in the requested config index (bytes 0..1 of the AEM body,
    # which lives at offset 22 from start of msg per the encoder layout).
    if configuration_index != 0:
        msg = bytearray(msg)
        struct.pack_into("!H", msg, 24, configuration_index)
        msg = bytes(msg)
    send_frame(sock, interface, entity_mac, mac, msg)

    start = time.monotonic()
    response = None
    while time.monotonic() - start < 2.0:
        result = recv_frame(sock, timeout=0.2)
        if result is None:
            continue
        _, payload = result
        if len(payload) < 22:
            continue
        subtype, msg_type, _, _, status, _ = decode_atdecc_header(payload[:4])
        if subtype != AVTP_SUBTYPE_AECP or msg_type != AECP_MSG_AEM_RESPONSE:
            continue
        if payload[4:12] != entity_id:
            continue
        rseq = struct.unpack("!H", payload[20:22])[0]
        if rseq != seq_id:
            continue
        response = payload
        break

    if response is None:
        print("\nNo response (timeout).")
        return

    # status_valtime byte: low 5 bits are AECP status
    aecp_status = (response[2] >> 3) & 0x1F
    status_names = {
        0: "SUCCESS", 1: "NOT_IMPLEMENTED", 2: "NO_SUCH_DESCRIPTOR",
        3: "ENTITY_LOCKED", 4: "ENTITY_ACQUIRED", 5: "NOT_AUTHENTICATED",
        6: "AUTHENTICATION_DISABLED", 7: "BAD_ARGUMENTS", 8: "NO_RESOURCES",
        9: "IN_PROGRESS", 10: "ENTITY_MISBEHAVING", 11: "NOT_SUPPORTED",
        12: "STREAM_IS_RUNNING",
    }
    status_str = status_names.get(aecp_status, f"status_{aecp_status}")
    print(f"\nAECP status: {aecp_status} ({status_str})")
    print(f"Response length: {len(response)} bytes")

    # Hex dump
    print("\nHex dump:")
    for i in range(0, len(response), 16):
        chunk = response[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}  {hexs:<47s}  {ascii_}")

    # Parsed summary for known descriptor types. The descriptor body
    # starts at payload offset 32 (after AECP common, AEM header,
    # config_index, reserved, descriptor_type, descriptor_index).
    body = response[32:]
    print("\nParsed:")
    if desc_type == AEM_DESC_TYPE_ENTITY and len(body) >= 308:
        # Entity descriptor layout (IEEE 1722.1-2021 §7.2.1):
        #   entity_id(8) entity_model_id(8) entity_capabilities(4)
        #   talker_stream_sources(2) talker_capabilities(2)
        #   listener_stream_sinks(2) listener_capabilities(2)
        #   controller_capabilities(4) available_index(4)
        #   association_id(8) entity_name(64) vendor_name_string(2)
        #   model_name_string(2) firmware_version(64) group_name(64)
        #   serial_number(64) configurations_count(2)
        #   current_configuration(2)
        ent_id = body[0:8].hex(":")
        model_id = body[8:16].hex(":")
        cfgs = struct.unpack("!H", body[304:306])[0]
        cur_cfg = struct.unpack("!H", body[306:308])[0]
        # entity_name follows the 44-byte fixed prefix (id, model_id,
        # capabilities, stream counts, controller_caps, available_index,
        # association_id), then the two localized name string refs, then
        # firmware_version — consistent with configurations_count at 304.
        ent_name = body[44:108].split(b"\x00", 1)[0].decode("utf-8", "replace")
        vendor_ref = struct.unpack("!H", body[108:110])[0]
        model_ref = struct.unpack("!H", body[110:112])[0]
        fw = body[112:176].split(b"\x00", 1)[0].decode("utf-8", "replace")
        print(f"  entity_id:             {ent_id}")
        print(f"  entity_model_id:       {model_id}")
        print(f"  entity_name:           {ent_name!r}")
        print(f"  vendor_name_string:    {vendor_ref}")
        print(f"  model_name_string:     {model_ref}")
        print(f"  firmware_version:      {fw!r}")
        print(f"  configurations_count:  {cfgs}")
        print(f"  current_configuration: {cur_cfg}")
        if cfgs == 0:
            print("  *** WARNING: configurations_count == 0 — "
                  "controllers will reject this entity ***")
    elif desc_type == AEM_DESC_TYPE_CONFIGURATION and len(body) >= 70:
        # Configuration descriptor layout (IEEE 1722.1-2021 §7.2.2):
        #   object_name(64) localized_description(2)
        #   descriptor_counts_count(2) descriptor_counts_offset(2)
        #   descriptor_counts[N*4]
        obj_name = body[0:64].split(b"\x00", 1)[0].decode("utf-8", "replace")
        loc = struct.unpack("!H", body[64:66])[0]
        cc = struct.unpack("!H", body[66:68])[0]
        co = struct.unpack("!H", body[68:70])[0]
        print(f"  object_name:                {obj_name!r}")
        print(f"  localized_description:      0x{loc:04x}")
        print(f"  descriptor_counts_count:    {cc}")
        print(f"  descriptor_counts_offset:   {co}")
        # The counts array is at body offset (co - 4) — co is relative
        # to the descriptor start (which includes the 4-byte
        # descriptor_type+descriptor_index that lives just before
        # the body in the response payload).
        counts_off = co - 4
        if counts_off >= 0 and counts_off + cc * 4 <= len(body):
            print("  descriptor_counts:")
            for i in range(cc):
                off = counts_off + i * 4
                dt = struct.unpack("!H", body[off:off + 2])[0]
                cnt = struct.unpack("!H", body[off + 2:off + 4])[0]
                dt_name = AEM_DESC_NAME_BY_TYPE.get(dt, f"0x{dt:04x}")
                print(f"    [{i}] descriptor_type=0x{dt:04x} "
                      f"({dt_name}) count={cnt}")
        if cc == 0:
            print("  *** WARNING: descriptor_counts_count == 0 — "
                  "configuration is empty ***")
    else:
        parsed = parse_aecp_read_descriptor_response(response)
        if parsed:
            for k, v in parsed.items():
                if isinstance(v, (bytes, bytearray)):
                    print(f"  {k}: {bytes(v).hex(':')}")
                else:
                    print(f"  {k}: {v}")
        else:
            print("  (no specific parser for this descriptor type — "
                  "use the hex dump above)")


# ---------------------------------------------------------------------------
# Descriptor harvest with per-request timing
# ---------------------------------------------------------------------------

# Well-known AEM descriptor types worth probing on a single endpoint
HARVEST_DEFAULT_TYPES = [
    ("entity",             AEM_DESC_TYPE_ENTITY),
    ("configuration",      AEM_DESC_TYPE_CONFIGURATION),
    ("audio_unit",         AEM_DESC_TYPE_AUDIO_UNIT),
    ("stream_input",       AEM_DESC_TYPE_STREAM_INPUT),
    ("stream_output",      AEM_DESC_TYPE_STREAM_OUTPUT),
    ("avb_interface",      AEM_DESC_TYPE_AVB_INTERFACE),
    ("clock_source",       AEM_DESC_TYPE_CLOCK_SOURCE),
    ("locale",             AEM_DESC_TYPE_LOCALE),
    ("strings",            AEM_DESC_TYPE_STRINGS),
    ("stream_port_input",  AEM_DESC_TYPE_STREAM_PORT_INPUT),
    ("stream_port_output", AEM_DESC_TYPE_STREAM_PORT_OUTPUT),
    ("audio_cluster",      AEM_DESC_TYPE_AUDIO_CLUSTER),
    ("audio_map",          AEM_DESC_TYPE_AUDIO_MAP),
    ("clock_domain",       AEM_DESC_TYPE_CLOCK_DOMAIN),
]


def cmd_harvest(interface: str, entity_id_str: str, descriptor_index: int = 0,
                timeout: float = 2.0, repeat: int = 1) -> None:
    """Send READ_DESCRIPTOR for each well-known descriptor type and time the
    response RTT. Useful for benchmarking AECP responsiveness end-to-end
    (e.g. wired vs Wi-Fi-bridged endpoints) and verifying which descriptors
    an entity actually implements."""
    mac = get_mac_address(interface)
    controller_id = mac_to_entity_id(mac)
    entity_id = parse_entity_id(entity_id_str)

    print(f"Interface:     {interface}")
    print(f"Entity ID:     {entity_id_str}")
    sock = open_raw_socket(interface)
    try:
        entity_mac = _resolve_mac(sock, interface, mac, entity_id, duration=3.0)
        print(f"Entity MAC:    {format_mac(entity_mac)}")
        print(f"Index:         {descriptor_index}   Repeat: {repeat}   "
              f"Timeout: {timeout:.1f}s")
        print()
        print(f"{'descriptor':<22} {'status':<10} {'rtt_ms':>10}  {'resp_bytes':>10}")
        print("-" * 60)
        all_rtts = []
        ok_count = 0
        timeout_count = 0
        seq = int(time.monotonic() * 1000) & 0xFFFF
        for name, type_code in HARVEST_DEFAULT_TYPES:
            for rep in range(repeat):
                seq = (seq + 1) & 0xFFFF
                # Drain any stale frames before timing
                while recv_frame(sock, timeout=0.0) is not None:
                    pass
                msg = build_aecp_read_descriptor(
                    controller_id, entity_id, seq, type_code, descriptor_index)
                t0 = time.monotonic()
                send_frame(sock, interface, entity_mac, mac, msg)
                resp_status = None
                resp_len = 0
                rtt_ms = None
                while time.monotonic() - t0 < timeout:
                    r = recv_frame(sock, timeout=0.05)
                    if r is None:
                        continue
                    _, payload = r
                    if len(payload) < 22:
                        continue
                    subtype, mtype, _, _, st, _ = decode_atdecc_header(payload[:4])
                    if subtype != AVTP_SUBTYPE_AECP or mtype != AECP_MSG_AEM_RESPONSE:
                        continue
                    if payload[4:12] != entity_id:
                        continue
                    rseq = struct.unpack("!H", payload[20:22])[0]
                    if rseq != seq:
                        continue
                    rtt_ms = (time.monotonic() - t0) * 1000.0
                    resp_status = st
                    resp_len = len(payload)
                    break
                if rtt_ms is None:
                    timeout_count += 1
                    status_str = "TIMEOUT"
                    rtt_str = "--"
                else:
                    if resp_status == 0:
                        ok_count += 1
                    status_name = {0: "SUCCESS", 1: "NOT_IMPL",
                                   2: "NO_DESC", 11: "NOT_SUPP"}.get(
                        resp_status, f"st={resp_status}")
                    status_str = status_name
                    rtt_str = f"{rtt_ms:.2f}"
                    all_rtts.append(rtt_ms)
                tag = name if repeat == 1 else f"{name}#{rep}"
                print(f"{tag:<22} {status_str:<10} {rtt_str:>10}  {resp_len:>10}")
        print()
        total = len(HARVEST_DEFAULT_TYPES) * repeat
        print(f"Summary: {ok_count}/{total} SUCCESS, {timeout_count} timeouts")
        if all_rtts:
            mn, mx = min(all_rtts), max(all_rtts)
            avg = sum(all_rtts) / len(all_rtts)
            print(f"RTT (ms): min={mn:.2f}  avg={avg:.2f}  max={mx:.2f}  "
                  f"(over {len(all_rtts)} responses)")
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AVB Controller - manage AVB stream connections via ATDECC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  sudo python3 atdecc_controller.py discover
  sudo python3 atdecc_controller.py connect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06
  sudo python3 atdecc_controller.py disconnect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06
  sudo python3 atdecc_controller.py --interface eno1 discover
""",
    )
    parser.add_argument(
        "--interface", "-i", default="enp5s0f3u4",
        help="Network interface to use (default: enp5s0f3u4)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # discover
    sp_discover = subparsers.add_parser("discover", help="Discover AVB entities on the network")
    sp_discover.add_argument(
        "--duration", "-d", type=float, default=5.0,
        help="Discovery duration in seconds (default: 5)",
    )
    sp_discover.add_argument(
        "--streams", "-s", action="store_true", default=False,
        help="Include stream descriptor summary in the report",
    )

    # connect
    sp_connect = subparsers.add_parser("connect", help="Connect a talker to a listener")
    sp_connect.add_argument("talker_entity_id", help="Talker entity ID (colon-separated hex)")
    sp_connect.add_argument("listener_entity_id", help="Listener entity ID (colon-separated hex)")
    sp_connect.add_argument("--match-supported", "-m", action="store_true",
                           help="Read each endpoint's supported_formats list and pick "
                                "the closest match to --format (subtype/SR/channels/bit-depth). "
                                "Use when the requested byte encoding may not match the device "
                                "exactly (e.g. AAF PCM32 vs PCM24 byte-3 = 32 vs 24).")
    sp_connect.add_argument("--format", "-f", default=None,
                           help="Stream format to set on both endpoints before connecting. "
                                "Options: am824-48k, am824-44.1k, am824-96k, aaf-48k, aaf-44.1k, aaf-96k, "
                                "am824 (alias for am824-48k), aaf (alias for aaf-48k), 61883 (alias for am824-48k)")
    sp_connect.add_argument("--class-b", "-b", action="store_true",
                           help="Set ACMP CLASS_B flag (bit 15) so the talker "
                                "configures this connection as SR Class B "
                                "(priority 2, 250 us observation interval). "
                                "Default = Class A (priority 3, 125 us).")
    sp_connect.add_argument("--talker-uid", type=int, default=0,
                            help="Talker stream output index (default 0)")
    sp_connect.add_argument("--listener-uid", type=int, default=0,
                            help="Listener stream input index (default 0)")

    # disconnect
    sp_disconnect = subparsers.add_parser("disconnect", help="Disconnect a talker from a listener")
    sp_disconnect.add_argument("talker_entity_id", help="Talker entity ID (colon-separated hex)")
    sp_disconnect.add_argument("listener_entity_id", help="Listener entity ID (colon-separated hex)")
    sp_disconnect.add_argument("--talker-uid", type=int, default=0,
                               help="Talker stream output index (default 0)")
    sp_disconnect.add_argument("--listener-uid", type=int, default=0,
                               help="Listener stream input index (default 0)")

    # stream-info
    sp_info = subparsers.add_parser("stream-info", help="Query stream info for an entity")
    sp_info.add_argument("entity_id", help="Entity ID to query (colon-separated hex)")

    # clock-source
    sp_clock = subparsers.add_parser(
        "clock-source", help="Get or set an entity CLOCK_DOMAIN clock source")
    sp_clock.add_argument("entity_id", help="Entity ID to query/control")
    sp_clock.add_argument("--clock-domain", type=int, default=0,
                          help="CLOCK_DOMAIN descriptor index (default 0)")
    sp_clock.add_argument("--set", dest="clock_source", type=int, default=None,
                          help="Set active CLOCK_SOURCE index; omit to get current source")

    # identify
    sp_identify = subparsers.add_parser(
        "identify", help="Trigger an entity's CONTROL[0] IDENTIFY control")
    sp_identify.add_argument("entity_id", help="Entity ID to identify")
    sp_identify.add_argument("--value", type=int, default=1,
                             help="IDENTIFY value to set (default 1)")

    # volume
    sp_volume = subparsers.add_parser(
        "volume", help="Get or set CONTROL[1] Speaker Volume")
    sp_volume.add_argument("entity_id", help="Entity ID to query/control")
    sp_volume.add_argument("--set-db", type=float, default=None,
                           help="Set speaker volume in dB; omit to get current value")

    # mic-gain
    sp_mic = subparsers.add_parser(
        "mic-gain", help="Get or set CONTROL[2] Mic Gain")
    sp_mic.add_argument("entity_id", help="Entity ID to query/control")
    sp_mic.add_argument("--set-db", type=float, default=None,
                        help="Set mic gain in dB; omit to get current value")

    # get-tx-state
    sp_gts = subparsers.add_parser("get-tx-state",
        help="Query ACMP GET_TX_STATE on a talker (shows connection_count)")
    sp_gts.add_argument("talker_id", help="Talker entity ID")
    sp_gts.add_argument("talker_uid", type=int, help="Talker stream output index")

    # direct-disconnect-tx
    sp_ddt = subparsers.add_parser("direct-disconnect-tx",
        help="Send ACMP DISCONNECT_TX_COMMAND directly to a talker")
    sp_ddt.add_argument("talker_id", help="Talker entity ID")
    sp_ddt.add_argument("listener_id", help="Listener entity ID (for the command fields)")
    sp_ddt.add_argument("talker_uid", type=int, help="Talker stream output index")
    sp_ddt.add_argument("listener_uid", type=int, help="Listener stream input index")

    # read-descriptor
    sp_rd = subparsers.add_parser(
        "read-descriptor",
        help="Send AECP READ_DESCRIPTOR and dump the response (hex + parse)")
    sp_rd.add_argument("entity_id", help="Target entity ID (colon-separated hex)")
    sp_rd.add_argument(
        "descriptor",
        help="Descriptor type — name (e.g. 'configuration', 'entity', "
             "'stream_input') or numeric (decimal or 0x-prefixed hex)")
    sp_rd.add_argument(
        "--index", type=int, default=0,
        help="descriptor_index (default 0)")
    sp_rd.add_argument(
        "--config-index", type=int, default=0,
        help="configuration_index field on the command (default 0)")

    # avb-info
    sp_ai = subparsers.add_parser(
        "avb-info",
        help="Query gPTP/SRP state via GET_AVB_INFO (grandmaster/BTC, domain, "
             "AS_CAPABLE, propagation delay)")
    sp_ai.add_argument("entity_id", help="Target entity ID (colon-separated hex)")
    sp_ai.add_argument("--index", type=int, default=0,
                       help="AVB_INTERFACE descriptor_index (default 0)")

    # harvest
    sp_hv = subparsers.add_parser(
        "harvest",
        help="Read each well-known descriptor type and report per-request RTT")
    sp_hv.add_argument("entity_id", help="Target entity ID (colon-separated hex)")
    sp_hv.add_argument("--index", type=int, default=0,
                       help="descriptor_index for each request (default 0)")
    sp_hv.add_argument("--timeout", type=float, default=2.0,
                       help="per-request response timeout in seconds (default 2.0)")
    sp_hv.add_argument("--repeat", type=int, default=1,
                       help="number of times to query each descriptor (default 1)")

    args = parser.parse_args()

    # Check we are running as root
    if os.geteuid() != 0:
        print("Warning: this tool requires root privileges for raw socket access.",
              file=sys.stderr)
        print("Run with: sudo python3 atdecc_controller.py ...", file=sys.stderr)

    if args.command == "discover":
        cmd_discover(args.interface, args.duration, show_streams=args.streams)
    elif args.command == "connect":
        cmd_connect(args.interface, args.talker_entity_id, args.listener_entity_id,
                    format_name=args.format,
                    talker_uid=args.talker_uid, listener_uid=args.listener_uid,
                    match_supported=args.match_supported,
                    class_b=args.class_b)
    elif args.command == "disconnect":
        cmd_disconnect(args.interface, args.talker_entity_id, args.listener_entity_id,
                       talker_uid=args.talker_uid, listener_uid=args.listener_uid)
    elif args.command == "stream-info":
        cmd_stream_info(args.interface, args.entity_id)
    elif args.command == "clock-source":
        cmd_clock_source(args.interface, args.entity_id,
                         clock_domain_index=args.clock_domain,
                         clock_source_index=args.clock_source)
    elif args.command == "identify":
        cmd_identify(args.interface, args.entity_id, value=args.value)
    elif args.command == "volume":
        value = None if args.set_db is None else int(round(args.set_db * 10.0))
        cmd_volume(args.interface, args.entity_id, value_tenth_db=value)
    elif args.command == "mic-gain":
        value = None if args.set_db is None else int(round(args.set_db * 10.0))
        cmd_mic_gain(args.interface, args.entity_id, value_tenth_db=value)
    elif args.command == "get-tx-state":
        cmd_get_tx_state(args.interface, args.talker_id, args.talker_uid)
    elif args.command == "direct-disconnect-tx":
        cmd_direct_disconnect_tx(args.interface, args.talker_id,
                                 args.listener_id, args.talker_uid,
                                 args.listener_uid)
    elif args.command == "read-descriptor":
        cmd_read_descriptor(args.interface, args.entity_id, args.descriptor,
                            descriptor_index=args.index,
                            configuration_index=args.config_index)
    elif args.command == "avb-info":
        cmd_get_avb_info(args.interface, args.entity_id,
                         descriptor_index=args.index)
    elif args.command == "harvest":
        cmd_harvest(args.interface, args.entity_id,
                    descriptor_index=args.index,
                    timeout=args.timeout, repeat=args.repeat)


if __name__ == "__main__":
    main()
