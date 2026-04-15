# tools

Community tools for testing AVB (Audio Video Bridging) networks. Includes a packet capture audio analyzer and an ATDECC network controller.

## Scripts

### `avb_audio_analyzer.py`

Extracts and analyzes PCM audio from AVTP (IEEE 1722-2016) packet captures. Reads pcap/pcapng files containing AVTP audio streams in AAF PCM or IEC 61883-6 AM824 format, extracts raw PCM samples, optionally writes a WAV file, and performs signal analysis including glitch detection, silence gap detection, periodic artifact detection, SNR, and THD.

Supports both numpy-accelerated analysis (FFT, SNR, THD, phase continuity) and a pure-Python fallback for basic analysis.

**Dependencies:** Python 3. Optional: `numpy` (for full FFT/SNR/THD/phase analysis), `scipy` (for Hilbert-transform phase analysis). Requires `editcap` (from Wireshark) for pcapng input files.

### `avb_controller.py`

ATDECC (IEEE 1722.1-2021) controller for managing AVB stream connections on a local network. Discovers AVB entities via ADP, connects and disconnects talkers and listeners via ACMP, queries stream info via AECP, and can set stream formats before connecting.

Uses raw AF_PACKET sockets with ethertype 0x22F0 (AVTP/ATDECC). Requires root privileges or `CAP_NET_RAW` capability.

**Dependencies:** Python 3 (standard library only). Linux only (uses `AF_PACKET` sockets).

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

### Usage

```
sudo python3 avb_controller.py [--interface IFACE] <command> [args]
```

### Global Options

| Option | Default | Description |
|---|---|---|
| `--interface`, `-i` | `enp5s0f3u4` | Network interface for AVB. |

### Commands

#### `discover`

Discover AVB entities on the network via ADP (AVTP Discovery Protocol). Listens for `ENTITY_AVAILABLE` messages and queries each entity's name via AECP `READ_DESCRIPTOR`. Also reads `STREAM_INPUT` and `STREAM_OUTPUT` descriptors for each discovered entity, displaying the stream name, current format, clock domain, and number of supported formats. Prints a summary table of all discovered entities followed by per-entity stream descriptor details.

```
sudo python3 avb_controller.py discover [options]
```

| Option | Default | Description |
|---|---|---|
| `--duration`, `-d` | `5.0` | Discovery duration in seconds. |

**Example:**

```bash
sudo python3 avb_controller.py discover
sudo python3 avb_controller.py -i eno1 discover --duration 10
```

**Example output (stream descriptors):**

```
--- Stream Descriptors ---

  My Device (00:1b:21:ff:fe:01:02:03):
    Stream Output[0]: Main Out                  Format: AAF 48k 24bit 8ch          Clock Domain: 0  Supported Formats: 3
    Stream Input[0]:  Main In                   Format: AAF 48k 24bit 8ch          Clock Domain: 0  Supported Formats: 3
```

#### `connect`

Connect a talker to a listener via ACMP `CONNECT_RX_COMMAND`. Optionally sets the stream format on both endpoints via AECP `SET_STREAM_FORMAT` before connecting.

```
sudo python3 avb_controller.py connect <talker_entity_id> <listener_entity_id> [options]
```

| Argument | Description |
|---|---|
| `talker_entity_id` | Talker entity ID (e.g., `00:1b:21:ff:fe:01:02:03`). |
| `listener_entity_id` | Listener entity ID. |

| Option | Default | Description |
|---|---|---|
| `--format`, `-f` | *(none)* | Stream format to set before connecting. See formats below. |

**Formats:** `am824-44.1k`, `am824-48k`, `am824-96k`, `aaf-44.1k`, `aaf-48k`, `aaf-96k`. Aliases: `am824` (= `am824-48k`), `aaf` (= `aaf-48k`), `61883` (= `am824-48k`).

**Example:**

```bash
sudo python3 avb_controller.py connect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06
sudo python3 avb_controller.py connect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06 --format aaf-48k
```

#### `disconnect`

Disconnect a talker from a listener via ACMP `DISCONNECT_RX_COMMAND`.

```
sudo python3 avb_controller.py disconnect <talker_entity_id> <listener_entity_id>
```

| Argument | Description |
|---|---|
| `talker_entity_id` | Talker entity ID. |
| `listener_entity_id` | Listener entity ID. |

**Example:**

```bash
sudo python3 avb_controller.py disconnect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06
```

#### `stream-info`

Query stream info for all input and output streams (indices 0-3) of an entity via AECP `GET_STREAM_INFO`. Displays format, stream ID, connection status, destination MAC, VLAN ID, traffic class, MSRP failure info, and latency for each stream.

```
sudo python3 avb_controller.py stream-info <entity_id>
```

| Argument | Description |
|---|---|
| `entity_id` | Entity ID to query. |

**Example:**

```bash
sudo python3 avb_controller.py stream-info 00:1b:21:ff:fe:01:02:03
```

---

## Entity ID Format

Entity IDs are 8 bytes represented as colon-separated hex (e.g., `00:1b:21:ff:fe:01:02:03`). For devices using standard EUI-64 derivation from a MAC address, bytes 4-5 are `ff:fe` (e.g., MAC `00:1b:21:01:02:03` becomes entity ID `00:1b:21:ff:fe:01:02:03`).

## Protocol References

- IEEE 1722-2016 (AVTP) -- Section 7 (AAF), Section 9 (IEC 61883)
- IEEE 1722.1-2021 (ATDECC) -- ADP, ACMP, AECP
