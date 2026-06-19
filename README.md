# tools

Community tools for testing AVB (Audio Video Bridging) networks. Includes a packet capture audio analyzer, an ATDECC network controller, an MSRP/MVRP test applicant, and an AVTP PCM stream generator.

## Scripts

### `avb_audio_analyzer.py`

Extracts and analyzes PCM audio from AVTP (IEEE 1722-2016) packet captures. Reads pcap/pcapng files containing AVTP audio streams in AAF PCM or IEC 61883-6 AM824 format, extracts raw PCM samples, optionally writes a WAV file, and performs signal analysis including glitch detection, silence gap detection, periodic artifact detection, SNR, and THD.

Supports both numpy-accelerated analysis (FFT, SNR, THD, phase continuity) and a pure-Python fallback for basic analysis.

**Dependencies:** Python 3. Optional: `numpy` (for full FFT/SNR/THD/phase analysis), `scipy` (for Hilbert-transform phase analysis). Requires `editcap` (from Wireshark) for pcapng input files.

### `avb_controller.py`

ATDECC (IEEE 1722.1-2021) controller for managing AVB stream connections on a local network. Discovers AVB entities via ADP, connects and disconnects talkers and listeners via ACMP, queries stream info via AECP, and can set stream formats before connecting.

Uses raw AF_PACKET sockets with ethertype 0x22F0 (AVTP/ATDECC). Requires root privileges or `CAP_NET_RAW` capability.

**Dependencies:** Python 3 (standard library only). Linux only (uses `AF_PACKET` sockets).

### `mrp_applicant.py`

MSRP/MVRP test applicant. Acts as an MRP applicant for MSRP (IEEE 802.1Qat) and MVRP (IEEE 802.1ak): declares Talker, Listener, Domain, and VLAN attributes to a connected switch, decodes incoming MRPDUs, and prints a per-run summary with pass/fail expectations. Useful for verifying that a bridge has SR class / MSRP configured correctly and that VLAN registration is working before bringing up real streams.

Uses raw AF_PACKET sockets with ethertypes 0x22EA (MSRP) and 0x88F5 (MVRP). Requires root privileges or `CAP_NET_RAW`.

**Dependencies:** Python 3 (standard library only). Linux only.

### `avtp_streamer.py`

AVTP PCM stream generator. Synthesizes a continuous sine wave and transmits it as an AAF or IEC 61883-6 AM824 AVTP stream paced at the SR class A (8000 pps) or class B (4000 pps) rate. The stream carries N total channels; the first M are filled with PCM and the remaining N-M carry silence. Configurable destination MAC, StreamID, sample rate, bit depth, frequency, amplitude, duration, and optional 802.1Q tag. Useful for driving a listener under test or exercising MSRP reservations end-to-end without needing real audio source hardware.

Uses raw AF_PACKET sockets with ethertype 0x22F0 (AVTP). Requires root privileges or `CAP_NET_RAW`.

**Dependencies:** Python 3 (standard library only). Linux only.

---

## avb_audio_analyzer.py

### Usage

```
python3 avb_audio_analyzer.py <pcap> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `pcap` | Input pcap/pcapng file. pcapng is auto-converted via `editcap`. |

### Options

| Option | Default | Description |
|---|---|---|
| `--wav FILE` | *(none)* | Write extracted audio to WAV (mono, 24/16-bit). |
| `--src-mac MAC` | *(none)* | Filter by source MAC (e.g., `00:11:22:33:44:55`). |
| `--channel N` | `0` | Channel index to extract (0-based). |
| `--sample-rate HZ` | `48000` | Sample rate in Hz. Fallback when not in headers (IEC 61883-6). AAF auto-detects. |
| `--bit-depth BITS` | `24` | Bit depth for analysis scaling. |

### Examples

```bash
# Basic analysis of a capture file
python3 avb_audio_analyzer.py capture.pcap

# Extract audio to WAV
python3 avb_audio_analyzer.py capture.pcap --wav output.wav

# Filter by source device and extract channel 1
python3 avb_audio_analyzer.py capture.pcap --src-mac 00:11:22:33:44:55 --channel 1

# Analyze a 96kHz stream
python3 avb_audio_analyzer.py capture.pcap --sample-rate 96000
```

### Analysis Report

The tool outputs a report containing:

- **Stream Information** -- format, packet/sample counts, channels, sample rate, duration, sequence gaps.
- **Signal Level** -- peak and RMS in raw values and dBFS.
- **Discontinuity Detection** -- sample-to-sample jumps exceeding adaptive threshold.
- **Silence Gaps** -- near-zero runs (below -60 dBFS) longer than 1 ms.
- **RMS Envelope Anomalies** *(numpy)* -- windowed RMS spikes/dips with periodicity detection.
- **Frequency Analysis** *(numpy)* -- fundamental frequency, SNR, THD (harmonics 2-10).
- **Phase Continuity** *(numpy)* -- phase discontinuities and periodic glitch detection via Hilbert transform.

---

## avb_controller.py

### Overview

`avb_controller.py` is a minimal ATDECC controller built around the three IEEE 1722.1-2021 protocols:

- **ADP** -- AVDECC Discovery Protocol. Listens for periodic `ENTITY_AVAILABLE` advertisements to find devices.
- **ACMP** -- AVDECC Connection Management Protocol. Establishes and tears down stream connections between talkers and listeners.
- **AECP** -- AVDECC Enumeration and Control Protocol. Reads descriptors (entity name, stream descriptors, supported formats) and changes stream formats.

The controller acts as a transient ATDECC controller entity for the duration of a single command. Its own entity ID is derived from the local interface MAC (EUI-64). It does not maintain state between invocations.

### Permissions

Raw `AF_PACKET` sockets require either root or the `CAP_NET_RAW` capability:

```bash
# Option A: run with sudo (simplest)
sudo python3 avb_controller.py discover

# Option B: grant CAP_NET_RAW to the Python interpreter (one-time)
sudo setcap cap_net_raw+ep $(readlink -f $(which python3))
python3 avb_controller.py discover
```

The script prints a warning to stderr if it is not running as root.

### Picking the network interface

All commands operate on a single Ethernet interface, which must be the one connected to the AVB network. The default is `enp5s0f3u4` -- almost certainly not what you want -- so override it with `--interface`/`-i`:

```bash
sudo python3 avb_controller.py -i eno1 discover
ip -br link  # list interfaces if you're not sure
```

The interface should be up, have a MAC address, and ideally be on a switch that supports the AVB stream reservation protocol (MSRP / IEEE 802.1Qat). The controller itself does not require MSRP, but successful streaming usually does.

### Usage

```
sudo python3 avb_controller.py [--interface IFACE] <command> [args]
```

### Global Options

| Option | Default | Description |
|---|---|---|
| `--interface`, `-i` | `enp5s0f3u4` | Network interface for AVB. |

### Commands at a glance

| Command | Purpose |
|---|---|
| `discover` | List entities advertising on the network; optionally summarize their streams. |
| `stream-info` | Query live stream state (format, dest MAC, MSRP failure, latency) for one entity. |
| `connect` | Tell a listener to subscribe to a talker's stream (optionally setting format first). |
| `disconnect` | Tell a listener to unsubscribe from a talker's stream. |
| `get-tx-state` | Ask a talker how many listeners are currently connected to one of its outputs. |
| `clock-source` | Get or set an entity CLOCK_DOMAIN active CLOCK_SOURCE index. |
| `direct-disconnect-tx` | Send a `DISCONNECT_TX_COMMAND` straight to a talker (diagnostic / state-machine probe). |

---

#### `discover`

Listens for ADP `ENTITY_AVAILABLE` advertisements and asynchronously fires AECP `READ_DESCRIPTOR` requests for each new entity to fetch its name, stream input/output descriptors, and (if needed) `STRINGS` descriptors for stream names. Prints a summary table when the discovery window expires; with `--streams`, also prints a per-entity breakdown of stream descriptors and their supported format ranges.

```
sudo python3 avb_controller.py discover [--duration SECONDS] [--streams]
```

| Option | Default | Description |
|---|---|---|
| `--duration`, `-d` | `5.0` | How long to listen for advertisements, in seconds. Increase if a device advertises infrequently. |
| `--streams`, `-s` | off | Append a per-entity stream descriptor section (current format, supported formats, sample-rate / bit-depth / channel ranges). |

**Examples:**

```bash
sudo python3 avb_controller.py discover
sudo python3 avb_controller.py -i eno1 discover --duration 10
sudo python3 avb_controller.py -i eno1 discover -s
```

**Summary table columns:**

```
Entity ID                  Name                 Model ID                   Roles                  MAC                Streams
```

- **Roles** -- combination of `Talker`, `Listener`, `Controller` (from each entity's capability flags).
- **Streams** -- counts in the form `TX:<n>, RX:<m>` where TX is talker stream sources and RX is listener stream sinks.

**Example stream descriptor output (`--streams`):**

```
--- Stream Descriptors ---

  My Device (00:1b:21:ff:fe:01:02:03):
    Stream Output[0] (Main Out): Cur Set Format: AAF 48k 24bit 8ch          Supported Formats: 3
    Stream Input[0] (Main In):   Cur Set Format: AAF 48k 24bit 8ch          Supported Formats: 3

    Supported Format Ranges:
      Stream Output[0]: Formats: AAF  Sample Rate: 44.1k-96k  Bit Depth: 16-24bit  Max Channels: 8
      Stream Input[0]:  Formats: AAF  Sample Rate: 44.1k-96k  Bit Depth: 16-24bit  Max Channels: 8
```

---

#### `stream-info`

Sends AECP `GET_STREAM_INFO` for indices 0-3 of both `STREAM_OUTPUT` and `STREAM_INPUT` on a single entity, stopping when an index returns `NO_SUCH_DESCRIPTOR`. Resolves the entity's MAC by listening briefly for ADP, falling back to EUI-64 → EUI-48 derivation if no advertisement arrives in time.

```
sudo python3 avb_controller.py stream-info <entity_id>
```

| Argument | Description |
|---|---|
| `entity_id` | Entity ID to query (colon-separated hex, see [Entity ID Format](#entity-id-format)). |

**Per-stream fields shown:**

| Field | Meaning |
|---|---|
| `Format` | Currently set stream format, with `(valid)` / `(invalid)` flag. |
| `Stream ID` | 8-byte stream identifier the talker emits (only populated for active streams). |
| `Connected` | Whether the entity considers this stream connected. |
| `Dest MAC` | Multicast destination MAC for the stream (typically `91:e0:f0:xx:xx:xx`). |
| `VLAN ID` | VLAN the stream is reserved on (0 if none). |
| `Class` | SR class A or B. |
| `Talker Failed` | Talker reports it cannot stream. |
| `Streaming Wait` | Stream is configured but waiting (e.g., paused). |
| `MSRP Fail` | MSRP failure code from the bridge that rejected the reservation (0 = none). |
| `Acc Latency` | Negotiated presentation-time latency in nanoseconds. |
| `Raw format` | Raw 8-byte stream-format hex (useful for cross-referencing the spec). |

**Example:**

```bash
sudo python3 avb_controller.py stream-info 00:1b:21:ff:fe:01:02:03
```

---

#### `connect`

Sends ACMP `CONNECT_RX_COMMAND` to the listener (via the well-known ACMP multicast `91:e0:f0:01:00:00`) to bind one of its stream input sinks to one of the talker's stream output sources. With `--format`, first sends AECP `SET_STREAM_FORMAT` to both endpoints (talker output 0 and listener input 0) so they agree on rate / bit depth / channel count. The listener forwards a `CONNECT_TX_COMMAND` to the talker as part of the standard ACMP handshake; the controller prints both responses if it sees them and exits non-zero on a non-`SUCCESS` final status.

```
sudo python3 avb_controller.py connect <talker_entity_id> <listener_entity_id>
                                       [--format FMT]
                                       [--talker-uid N] [--listener-uid N]
```

| Argument | Description |
|---|---|
| `talker_entity_id` | Talker entity ID. |
| `listener_entity_id` | Listener entity ID. |

| Option | Default | Description |
|---|---|---|
| `--format`, `-f` | *(none)* | Stream format to set on both endpoints before connecting. See [Stream formats](#stream-formats). |
| `--match-supported`, `-m` | off | When set with `--format`, first read each endpoint's supported_formats list and pick the closest entry (scored on subtype, sample rate, channel count, bit depth) for each side independently. Use this when devices encode the same logical format with different bytes — most commonly the AAF byte-3 difference between PCM32 (Milan, byte 0x20) and PCM24 (byte 0x18). Without this flag, the literal preset bytes are sent and a strict-match firmware will reject anything that doesn't byte-equal an entry in its supported_formats. |
| `--talker-uid` | `0` | Talker stream output index (`STREAM_OUTPUT[N]`). |
| `--listener-uid` | `0` | Listener stream input index (`STREAM_INPUT[N]`). |

> **Note:** `--format` only sets the format on `STREAM_OUTPUT[0]` / `STREAM_INPUT[0]` regardless of `--talker-uid` / `--listener-uid`. If you need a non-default index pre-configured, set the format out of band first and connect without `--format`.

**Examples:**

```bash
# Connect talker stream 0 to listener stream 0 (most common case)
sudo python3 avb_controller.py connect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06

# Force AAF 48 kHz on both ends, then connect
sudo python3 avb_controller.py connect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06 \
    --format aaf-48k

# Connect talker output #1 to listener input #2
sudo python3 avb_controller.py connect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06 \
    --talker-uid 1 --listener-uid 2
```

---

#### `disconnect`

Sends ACMP `DISCONNECT_RX_COMMAND` to the listener for a specific stream input. Does not change stream formats.

```
sudo python3 avb_controller.py disconnect <talker_entity_id> <listener_entity_id>
                                          [--talker-uid N] [--listener-uid N]
```

| Argument | Description |
|---|---|
| `talker_entity_id` | Talker entity ID. |
| `listener_entity_id` | Listener entity ID. |

| Option | Default | Description |
|---|---|---|
| `--talker-uid` | `0` | Talker stream output index. |
| `--listener-uid` | `0` | Listener stream input index. |

**Example:**

```bash
sudo python3 avb_controller.py disconnect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06
```

---

#### `get-tx-state`

Sends ACMP `GET_TX_STATE_COMMAND` to a specific talker stream output. Useful for confirming how many listeners a talker believes are subscribed -- the `Connection Count` field in the response is the authoritative number from the talker's perspective. Helpful when the listener and talker disagree about a connection's state.

```
sudo python3 avb_controller.py get-tx-state <talker_id> <talker_uid>
```

| Argument | Description |
|---|---|
| `talker_id` | Talker entity ID. |
| `talker_uid` | Talker stream output index (e.g., `0`). |

**Example:**

```bash
sudo python3 avb_controller.py get-tx-state 00:1b:21:ff:fe:01:02:03 0
```

---

#### `clock-source`

Gets or sets the active CLOCK_SOURCE index for a CLOCK_DOMAIN descriptor.
Useful for testing internal/gPTP vs CRF/media-clock clock-domain scenarios.

```
sudo python3 avb_controller.py clock-source <entity_id> [--clock-domain N] [--set SOURCE_INDEX]
```

Examples:

```bash
# Read CLOCK_DOMAIN[0] current source
sudo python3 avb_controller.py -i eno1 clock-source 00:1b:21:ff:fe:01:02:03

# Set CLOCK_DOMAIN[0] to CLOCK_SOURCE[1]
sudo python3 avb_controller.py -i eno1 clock-source 00:1b:21:ff:fe:01:02:03 --set 1
```

CRF/media-clock streams can be connected with the normal `connect` command by selecting the CRF stream UIDs, for example `--talker-uid 1 --listener-uid 1` on devices whose CRF stream is index 1.

---

#### `direct-disconnect-tx`

Sends ACMP `DISCONNECT_TX_COMMAND` straight to a talker, bypassing the normal listener-driven flow. This is a diagnostic tool for probing how a talker's ACMP state machine reacts to an explicit disconnect (or for clearing stuck listener registrations on misbehaving talkers). Most networks should use `disconnect` instead.

```
sudo python3 avb_controller.py direct-disconnect-tx <talker_id> <listener_id> <talker_uid> <listener_uid>
```

| Argument | Description |
|---|---|
| `talker_id` | Talker entity ID (the recipient). |
| `listener_id` | Listener entity ID (placed in the command's listener fields). |
| `talker_uid` | Talker stream output index. |
| `listener_uid` | Listener stream input index. |

**Example:**

```bash
sudo python3 avb_controller.py direct-disconnect-tx \
    00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06 0 0
```

---

### Stream formats

`--format` accepts the following well-known IEEE 1722-2016 stream formats:

| Name | Subtype | Sample rate | Bit depth | Channels |
|---|---|---|---|---|
| `am824-44.1k` | IEC 61883-6 AM824 | 44.1 kHz | 24 (in 32-bit AM824) | 8 |
| `am824-48k` | IEC 61883-6 AM824 | 48 kHz | 24 | 8 |
| `am824-96k` | IEC 61883-6 AM824 | 96 kHz | 24 | 8 |
| `am824-176.4k` | IEC 61883-6 AM824 | 176.4 kHz | 24 | 8 |
| `am824-192k` | IEC 61883-6 AM824 | 192 kHz | 24 | 8 |
| `aaf-44.1k` | AAF PCM | 44.1 kHz | 24 | 8 |
| `aaf-48k` | AAF PCM | 48 kHz | 24 | 8 |
| `aaf-96k` | AAF PCM | 96 kHz | 24 | 8 |
| `aaf-176.4k` | AAF PCM | 176.4 kHz | 24 | 8 |
| `aaf-192k` | AAF PCM | 192 kHz | 24 | 8 |

**Aliases:** `am824` → `am824-48k`, `aaf` → `aaf-48k`, `61883` → `am824-48k`.

The controller does not currently expose presets for non-8-channel formats; if the entity advertises a different channel count in its `STREAM_OUTPUT` / `STREAM_INPUT` descriptor, configure the format on the device side and connect without `--format`.

---

### End-to-end example

A typical workflow for bringing up a single stream between two devices:

```bash
# 1. Find the entities on your AVB interface.
sudo python3 avb_controller.py -i eno1 discover -s

# 2. Inspect the talker's outputs and the listener's inputs.
sudo python3 avb_controller.py -i eno1 stream-info 00:1b:21:ff:fe:aa:bb:cc   # talker
sudo python3 avb_controller.py -i eno1 stream-info 00:1b:21:ff:fe:dd:ee:ff   # listener

# 3. Set both endpoints to AAF 48 kHz and connect.
sudo python3 avb_controller.py -i eno1 connect \
    00:1b:21:ff:fe:aa:bb:cc 00:1b:21:ff:fe:dd:ee:ff --format aaf-48k

# 4. Verify the talker sees the new listener.
sudo python3 avb_controller.py -i eno1 get-tx-state 00:1b:21:ff:fe:aa:bb:cc 0

# 5. Tear it down when done.
sudo python3 avb_controller.py -i eno1 disconnect \
    00:1b:21:ff:fe:aa:bb:cc 00:1b:21:ff:fe:dd:ee:ff
```

---

### Troubleshooting

- **`No entities discovered.`** -- Wrong `--interface`, link is down, the AVB devices are on a different VLAN, or the switch is filtering ATDECC multicast. Try a longer `--duration`. ADP advertisements typically arrive every 2 s but some devices are slower.
- **`Warning: this tool requires root privileges...`** -- Re-run with `sudo` or grant `CAP_NET_RAW` (see [Permissions](#permissions)).
- **`Timeout: no <RESPONSE> received within 5 seconds.`** on `connect` / `disconnect` -- The listener didn't reply on the ACMP multicast. Confirm with `discover` that it is still online and that its entity ID is correct.
- **`SET_STREAM_FORMAT` returns `NOT_SUPPORTED`** -- The format isn't in that stream's supported list. Run `discover -s` and pick one from the "Supported Format Ranges" line.
- **`MSRP Fail: code=<n> (valid)` in `stream-info`** -- The bridge rejected the stream reservation (insufficient bandwidth, missing class, MSRP not configured). The connection itself can still succeed at the ACMP layer but no audio will flow. Configure MSRP / SR class on the switch.
- **Format set succeeds but `connect` still fails** -- Some devices need the connect command issued at a higher `--talker-uid` / `--listener-uid` than the format was applied to. `--format` always targets index 0; configure other indices via the device's own management interface.

---

## Entity ID Format

Entity IDs are 8 bytes represented as colon-separated hex (e.g., `00:1b:21:ff:fe:01:02:03`). For devices using standard EUI-64 derivation from a MAC address, bytes 4-5 are `ff:fe` (e.g., MAC `00:1b:21:01:02:03` becomes entity ID `00:1b:21:ff:fe:01:02:03`). The controller uses this same derivation as a MAC fallback when ADP discovery doesn't return a source MAC for an entity in time.

## Protocol References

- IEEE 1722-2016 (AVTP) -- Section 7 (AAF), Section 9 (IEC 61883)
- IEEE 1722.1-2021 (ATDECC) -- ADP, ACMP, AECP

---

## mrp_applicant.py

### Overview

`mrp_applicant.py` is a stateless MRP applicant for the two protocols built on the Multiple Registration Protocol:

- **MVRP** (IEEE 802.1ak) -- declares VLAN registrations on EtherType `0x88F5` / multicast `01:80:c2:00:00:21`.
- **MSRP** (IEEE 802.1Qat) -- declares Talker, Listener, and Domain attributes on EtherType `0x22EA` / multicast `01:80:c2:00:00:0e`.

It encodes the standard MRPDU format (ProtocolVersion, Messages, VectorAttributes with ThreePackedEvents, plus FourPackedEvents for Listener declarations), periodically retransmits its JoinIn while the run is active, decodes any MRPDUs the bridge or peers send back, and finishes with a pass/fail summary describing which expectations were met.

### Permissions

Same as the controller -- raw `AF_PACKET` requires root or `CAP_NET_RAW`:

```bash
sudo python3 mrp_applicant.py -i eno1 monitor
# or
sudo setcap cap_net_raw+ep $(readlink -f $(which python3))
```

### Usage

```
sudo python3 mrp_applicant.py [--interface IFACE] [-v] <command> [args]
```

### Global Options

| Option | Default | Description |
|---|---|---|
| `--interface`, `-i` | `eno1` | Network interface to use. |
| `--verbose`, `-v` | off | Print every decoded MRPDU as it arrives (otherwise only the run summary is printed). |

### Commands at a glance

| Command | Purpose |
|---|---|
| `monitor` | Passively decode MSRP+MVRP frames, then print a summary. |
| `mvrp` | Register a VLAN ID with MVRP and check whether the bridge responds. |
| `talker` | Advertise an MSRP Talker (StreamID + TSpec) and report any TalkerFailed code or Listener replies. |
| `listener` | Declare an MSRP Listener (Ready / AskingFailed / ReadyFailed) and report any matching Talker attribute. |
| `domain` | Declare an MSRP Domain (SR class, priority, VID) and report responses. |

---

#### `monitor`

Listens for MSRP and MVRP traffic for `--duration` seconds and prints a summary of every VID, stream, and SR-class domain seen.

```
sudo python3 mrp_applicant.py [-v] monitor [--duration SECONDS]
```

| Option | Default | Description |
|---|---|---|
| `--duration` | `10.0` | Listen duration in seconds. |

---

#### `mvrp`

Sends MVRP `JoinIn` for a VLAN ID and (by default) periodically retransmits while listening for the bridge's response. On exit, sends a `Lv` for the same VID unless `--no-leave` is passed.

```
sudo python3 mrp_applicant.py mvrp <vid> [--duration SECONDS] [--join-interval SECONDS] [--no-leave]
```

| Argument | Description |
|---|---|
| `vid` | VLAN ID to register (1..4094). |

| Option | Default | Description |
|---|---|---|
| `--duration` | `5.0` | Run duration in seconds. |
| `--join-interval` | `1.0` | Seconds between repeat `JoinIn` declarations. |
| `--no-leave` | off | Don't emit a `Lv` frame on exit. |

The summary reports a `PASS` if any of `New`, `JoinIn`, `In`, or `JoinMt` events for the VID were observed -- a healthy switch will reflect the registration back so neighboring ports see it as `In`.

---

#### `talker`

Advertises an MSRP Talker for a specific StreamID. Repeats the advertisement on `--join-interval` until `--duration` elapses, then sends a `Lv`.

```
sudo python3 mrp_applicant.py talker <stream_id> [options]
```

| Argument | Description |
|---|---|
| `stream_id` | 8-byte StreamID as colon-hex (e.g. `00:1b:21:01:02:03:00:01`). |

| Option | Default | Description |
|---|---|---|
| `--dest-mac` | `91:e0:f0:00:fe:00` | Stream destination MAC carried in the TSpec. |
| `--max-frame-size` | `1500` | TSpec MaxFrameSize in bytes. |
| `--max-interval-frames` | `1` | TSpec MaxIntervalFrames per class interval. |
| `--rank` | `1` | Rank: `0`=emergency, `1`=non-emergency. |
| `--accumulated-latency` | `0` | Initial accumulated latency in ns. |
| `--send-domain` | off | Also send a Domain declaration before the advertisement. |
| `--sr-class` | `A` | SR class A (PCP 3, VID 2) or B (PCP 2, VID 2). |
| `--pcp` | from class | Override 802.1Q PCP. |
| `--vid` | from class | Override stream VLAN ID. |
| `--duration` | `5.0` | Run duration in seconds. |
| `--join-interval` | `1.0` | Seconds between repeat declarations. |
| `--no-leave` | off | Don't emit a `Lv` frame on exit. |

The summary reports three expectations:

- `TalkerAdvertise not rejected by bridge` -- fails if any `TalkerFailed` is observed for this StreamID; the failure code is decoded (e.g. "Insufficient bandwidth", "VLAN tagging is disabled").
- `Stream registered at the bridge` -- expects the bridge to propagate the advertisement back as `JoinIn`/`In`.
- `Listener declared Ready` -- expects any peer to respond with a `Ready` Listener attribute (passes only if a Listener is actually subscribing).

---

#### `listener`

Declares an MSRP Listener for a specific StreamID with a chosen declaration type (`Ready`, `AskingFailed`, `ReadyFailed`, or `Ignore`).

```
sudo python3 mrp_applicant.py listener <stream_id> [--declaration ready|asking_failed|ready_failed|ignore] [options]
```

| Argument | Description |
|---|---|
| `stream_id` | 8-byte StreamID as colon-hex. |

| Option | Default | Description |
|---|---|---|
| `--declaration` | `ready` | Listener declaration type. |
| `--send-domain` | off | Also send a Domain declaration before subscribing. |
| `--sr-class`, `--pcp`, `--vid` | (see `talker`) | Class / priority / VID overrides. |
| `--duration`, `--join-interval`, `--no-leave` | (see `talker`) | Pacing and teardown. |

The summary reports whether a corresponding Talker attribute was observed for the StreamID; if `TalkerFailed` is reported, the failure code is decoded.

---

#### `domain`

Declares an MSRP Domain (SR class ID + priority + VID).

```
sudo python3 mrp_applicant.py domain [--sr-class A|B] [--sr-class-id N] [--pcp N] [--vid N] [options]
```

| Option | Default | Description |
|---|---|---|
| `--sr-class` | `A` | SR class for default ID / priority / VID. |
| `--sr-class-id` | from class | Override SR class ID (default A=6, B=5). |
| `--pcp` | from class | Override priority (A=3, B=2). |
| `--vid` | from class | Override VID (default 2). |
| `--duration`, `--join-interval`, `--no-leave` | (see `talker`) | Pacing and teardown. |

The summary verifies that the bridge or a peer echoes back a matching Domain declaration (same SR class ID, priority, and VID).

---

### Example: bring up an MSRP stream reservation

```bash
# 1. Watch the wire for two seconds with no other applicant active.
sudo python3 mrp_applicant.py -i eno1 monitor --duration 2

# 2. Register VLAN 2 on the local port via MVRP.
sudo python3 mrp_applicant.py -i eno1 mvrp 2 --duration 3

# 3. Declare an SR class A Domain.
sudo python3 mrp_applicant.py -i eno1 domain --sr-class A --duration 3

# 4. Pretend to be a Talker. If the bridge has MSRP off, expect a TalkerFailed.
sudo python3 mrp_applicant.py -i eno1 talker 00:1b:21:01:02:03:00:01 \
    --max-frame-size 200 --max-interval-frames 1 --duration 5
```

### Troubleshooting

- **No MRPDUs received in `monitor`** -- the port is not on an MRP-aware bridge, or it is treating these as reserved/control frames and forwarding them only to other bridges. Confirm the link partner is a switch with MSRP/MVRP enabled.
- **`TalkerFailed code=1 (Insufficient bandwidth)`** -- the bridge does not have enough idle slope on the egress port for the requested TSpec. Lower `--max-frame-size` / `--max-interval-frames` or increase the configured SR-class slope.
- **`TalkerFailed code=18 (VLAN tagging is disabled)`** -- the bridge requires SR-class frames to be VLAN tagged on this port. Most MSRP implementations need a VLAN configured for the SR class; ensure the stream's VID is allowed on this port.
- **`Listener declared Ready` fails even when streams exist** -- no actual listener is registered downstream. The Talker test alone exercises only the Talker leg; pair with a real listener (or run `mrp_applicant.py listener ...` on a second host) to drive that expectation.

---

## avtp_streamer.py

### Overview

`avtp_streamer.py` synthesizes a sine wave and transmits it as an AVTP audio stream. It builds correct headers for either AAF (IEEE 1722-2016 §7) or IEC 61883-6 AM824 (§9), interleaves PCM samples across N channels, and paces packets at the SR class A (8000 pps) or class B (4000 pps) rate. The first M channels carry the sine wave; the remaining N-M channels carry silence -- useful for testing channel routing and rendering on listeners without needing real audio source hardware.

This is a generator-only tool -- it does not negotiate MSRP or ATDECC. Use `mrp_applicant.py` or `avb_controller.py` to set up reservation / connection state first if your target listener needs them.

### Permissions

Raw `AF_PACKET` requires root or `CAP_NET_RAW`:

```bash
sudo python3 avtp_streamer.py -i eno1 --stream-id 00:1b:21:01:02:03:00:01 ...
```

### Usage

```
sudo python3 avtp_streamer.py [--interface IFACE] --stream-id <ID> [options]
```

### Options

| Option | Default | Description |
|---|---|---|
| `--interface`, `-i` | `eno1` | Network interface for transmission. |
| `--format` | `aaf` | `aaf` or `am824`. |
| `--stream-id` | *(required)* | 8-byte StreamID (colon-hex or 16 hex chars). |
| `--dest-mac` | `91:e0:f0:00:fe:00` | Destination MAC for the AVTP frames. |
| `--freq` | `1000` | Sine wave frequency in Hz. |
| `--duration` | `5.0` | Stream duration in seconds. |
| `--amplitude` | `0.5` | Amplitude as a 0..1 fraction of full scale. |
| `--sample-rate` | `48000` | Audio sample rate in Hz (8k/16k/32k/44.1k/48k/88.2k/96k/176.4k/192k for AAF; 32k–192k for AM824). |
| `--bit-depth` | `24` | AAF bit depth (`16`, `24`, or `32`). AM824 is always 24-bit. |
| `--channels` | `8` | Total channels per frame (N). |
| `--active-channels` | `2` | First M channels filled with sine; channels [M..N) carry silence. |
| `--sr-class` | `A` | `A` (8000 pps) or `B` (4000 pps). |
| `--vlan` | *(none)* | If set, prepend an 802.1Q tag with this VID. |
| `--pcp` | from class | 802.1Q priority (used only when `--vlan` is set). Defaults: A=3, B=2. |
| `--presentation-offset` | `2.0` | Milliseconds added to `avtp_timestamp` (uses `CLOCK_TAI` when available). |

### Examples

```bash
# 1 kHz sine on the first two of eight channels, AAF 48 kHz/24-bit, 5 seconds.
sudo python3 avtp_streamer.py -i eno1 \
    --stream-id 00:1b:21:01:02:03:00:01 \
    --freq 1000 --duration 5 \
    --channels 8 --active-channels 2

# AM824 (IEC 61883-6) at 440 Hz, two-channel stereo, tagged on VLAN 2.
sudo python3 avtp_streamer.py -i eno1 \
    --format am824 \
    --stream-id 00:1b:21:01:02:03:00:02 \
    --freq 440 --duration 30 \
    --channels 2 --active-channels 2 \
    --vlan 2

# Full-scale 96 kHz / 32-bit AAF on a known multicast destination MAC.
sudo python3 avtp_streamer.py -i eno1 \
    --stream-id aa:bb:cc:dd:ee:ff:00:01 \
    --sample-rate 96000 --bit-depth 32 \
    --amplitude 1.0 --freq 5000 \
    --dest-mac 91:e0:f0:00:fe:10 --duration 60
```

### Progress and summary

While streaming, the tool prints a one-line progress update each second showing packets sent, samples sent vs. target, and the current measured bit rate. On exit it prints a summary including measured pps, measured sample rate, and total bytes -- handy for confirming that the host is meeting the configured SR-class cadence:

```
Streaming summary
================================================================
  Packets sent:   40000
  Samples sent:   240000 (target 240000)
  Bytes sent:     11200000
  Elapsed:        5.001s
  Actual pps:     7998.2 (target 8000)
  Actual sample rate: 47989.4 Hz (target 48000)
  Actual bit rate: 17.92 Mbit/s
```

Exits non-zero (`2`) if it could not deliver at least 99.9% of the requested samples in the requested wall-clock time (typically a sign the host is overloaded or pacing is being throttled).

### Pairing with the analyzer

`avtp_streamer.py` emits frames in the exact layout `avb_audio_analyzer.py` parses, so a Wireshark capture of a stream produced by this tool can be fed straight into the analyzer:

```bash
# In one terminal, stream for 30 s.
sudo python3 avtp_streamer.py -i eno1 \
    --stream-id 00:1b:21:01:02:03:00:01 --freq 1000 --duration 30

# In another, capture and analyze.
sudo tshark -i eno1 -f 'ether proto 0x22f0' -a duration:30 -w stream.pcap
python3 avb_audio_analyzer.py stream.pcap --wav out.wav
```

### Troubleshooting

- **Listener hears clicks or dropouts** -- check the "Actual pps / Actual sample rate" lines on the summary. If they're significantly below target, the host can't keep up with the SR-class cadence; try a lower channel count, switch to SR class B (`--sr-class B`), or reduce `--sample-rate`.
- **No audio at the listener even though packets are flowing** -- the listener may need an explicit ACMP connection (`avb_controller.py connect ...`) or an MSRP reservation (`mrp_applicant.py talker ...`) before it accepts the stream. Streaming raw AVTP onto the wire is not enough for compliant listeners.
- **Listener mutes the inactive channels** -- intended behavior; channels `[--active-channels..--channels)` carry exact zeros. Increase `--active-channels` if you want signal on more channels.
- **`unsupported sample rate` error** -- AAF and AM824 only encode a fixed set of rates; see the `--sample-rate` row above.
