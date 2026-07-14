# AVB tools

Community tools for testing AVB (Audio Video Bridging) networks: an ATDECC
controller, an MSRP/MVRP test applicant, a live SRP reservation dashboard, an
AVTP stream generator, a capture-based audio analyzer, two gPTP
inspection tools, and a self-healing macOS stream monitor.

## Tool index

| Tool | What it does | Platforms | Privileges |
|---|---|---|---|
| [`atdecc_controller.py`](#atdecc_controllerpy) | Discover, connect, configure and query AVB entities (ADP / ACMP / AECP) | Linux, macOS | root / `CAP_NET_RAW` |
| [`mrp_applicant.py`](#mrp_applicantpy) | Declare MSRP/MVRP attributes and verify the bridge's responses | Linux, macOS | root / `CAP_NET_RAW` |
| [`msrp_dashboard.py`](#msrp_dashboardpy) | Live full-screen view of SRP stream reservations and their flaps | Linux, macOS | capture rights (tshark) |
| [`avtp_streamer.py`](#avtp_streamerpy) | Generate a paced AAF / AM824 sine-wave stream | Linux, macOS | root / `CAP_NET_RAW` |
| [`avtp_audio_analyzer.py`](#avtp_audio_analyzerpy) | Extract and analyze PCM audio from AVTP captures | any (offline) | none |
| [`gptp_inspector.py`](#gptp_inspectorpy) | Live decoder for 802.1AS frames with direction tagging | Linux, macOS | root / `CAP_NET_RAW` |
| [`gptp_monitor_macos.py`](#gptp_monitor_macospy) | Report a Mac's outbound gPTP state (invisible to packet capture) | macOS | none |
| [`stream_monitor_macos.swift`](#stream_monitor_macosswift) | Self-healing play-through monitor: render a Mac's AVB stream input to any output device | macOS | none |

`bpf_shim.py` is not a tool: it is the raw-Ethernet backend the others load
automatically on macOS and must sit in the same directory as them.

---

## Getting started

### Requirements

- Python 3 (standard library only, with per-tool extras):
  - `avtp_audio_analyzer.py`: optional `numpy` (FFT/SNR/THD/phase analysis),
    optional `scipy` (Hilbert phase analysis); `editcap` from Wireshark for
    pcapng input.
  - `msrp_dashboard.py`: `tshark` (Wireshark) and `rich` (installed
    automatically when run with `uv`).
- On macOS, `bpf_shim.py` alongside the scripts (ships in this repo).

### Permissions

The live tools open raw sockets. On Linux, either run with `sudo` or grant
the capability once:

```bash
sudo python3 atdecc_controller.py discover            # option A
sudo setcap cap_net_raw+ep $(readlink -f $(which python3))   # option B, then no sudo
```

On macOS there is no capability equivalent; `/dev/bpf*` requires root, so run
the live tools with `sudo`. Exceptions: `gptp_monitor_macos.py` needs no
privileges (it reads the IORegistry), and `msrp_dashboard.py` needs only
capture rights (`wireshark` group on Linux).

### Picking the network interface

Every live tool operates on one Ethernet interface, selected with
`--interface` / `-i`. The built-in defaults (`eno1`, `enp5s0f3u4`) are
almost certainly not your interface — treat `-i` as required:

```bash
ip -br link        # Linux: list interfaces
networksetup -listallhardwareports   # macOS
```

The interface should be up and connected to the AVB network. The tools
themselves don't require an MSRP-capable switch, but successful streaming
usually does.

### Entity IDs and Stream IDs

Entity IDs are 8 bytes written as colon-separated hex
(`00:1b:21:ff:fe:01:02:03`). Devices that derive them from a MAC insert
`ff:fe` in the middle (EUI-64), and the controller uses the same derivation
in reverse as a fallback when it must guess an entity's MAC.

Stream IDs are also 8 bytes; by convention the first six are the talker's
MAC and the last two a per-talker stream index — which is why the dashboard
can name the true talker even when a bridge relays the attribute.

---

## macOS notes

All cross-platform tools detect the OS at import time (`sys.platform`) and
swap their socket layer for a BPF backend on macOS — no flags. A kernel-side
BPF filter admits only the ethertypes each tool needs, so VLAN-tagged AVTP
media streams never reach the tools even on a port carrying live audio.

Behaviors worth knowing, all verified against live gear:

- **A Mac's own outbound gPTP is invisible to every packet capture** —
  Apple builds 802.1AS frames inside `IOgPTPPlugin.kext` and hands them to
  the NIC's realtime transmit queue, below both BPF and pktap. That's why
  Wireshark on a Mac shows only inbound PTP, and why `gptp_monitor_macos.py`
  exists (it reads the transmitting kext's own counters instead).
  `gptp_inspector.py` on a Mac therefore shows inbound and third-party
  frames only.
- **Same-host multicast does not hairpin.** BPF-injected frames egress the
  wire but are not looped into the local stack, so ACMP (multicast per
  spec) sent *from a Mac to its own entity* gets no response. Over the wire
  from another host, the macOS listener accepts external
  `CONNECT_RX`/`DISCONNECT_RX` normally. Unicast AECP to the interface's
  own MAC does hairpin, which is why enumeration and format changes work
  locally.
- **macOS `SET_STREAM_FORMAT` returns `STREAM_IS_RUNNING`** while the
  stream is connected or its CoreAudio engine holds the device. Disconnect
  first and retry; after a talker disappears, allow ~10 s for the departure
  to register.
- **macOS ignores `SET_SAMPLING_RATE`** — change the Mac device rate
  locally (Audio MIDI Setup / CoreAudio), not over AVDECC.
- **macOS fast-connect** re-establishes saved connections when the remote
  talker reappears, but only with the format it bound with — it will not
  re-bind an AAF-bound input to a talker now offering AM824.
- **ADP discovery on a Mac includes the Mac's own entities** — the BPF
  backend sees the interface's own transmissions, so the local virtual
  entity and controller appear alongside remote devices.
- `avtp_streamer.py` paces within a fraction of a percent of target on
  macOS, but expect slightly more jitter than on Linux — fine for a
  test-signal generator.

---

## atdecc_controller.py

A minimal ATDECC (IEEE 1722.1-2021) controller built around the three
protocols:

- **ADP** — discovery: listens for periodic `ENTITY_AVAILABLE` advertisements.
- **ACMP** — connection management: binds and unbinds talker/listener streams.
- **AECP** — enumeration and control: reads descriptors, changes stream
  formats, drives controls (identify / volume / mic gain / clock source),
  and queries runtime gPTP state.

It acts as a transient controller entity for one command at a time (entity
ID derived from the interface MAC) and keeps no state between invocations.

```
sudo python3 atdecc_controller.py [--interface IFACE] <command> [args]
```

### Commands at a glance

| Command | Purpose |
|---|---|
| `discover` | List entities advertising on the network; optionally summarize their streams. |
| `stream-info` | Query live stream state (format, dest MAC, MSRP failure, latency) for one entity. |
| `connect` | Tell a listener to subscribe to a talker's stream (optionally setting format / SR class first). |
| `disconnect` | Tell a listener to unsubscribe from a talker's stream. |
| `get-tx-state` | Ask a talker how many listeners are connected to one of its outputs. |
| `clock-source` | Get or set an entity CLOCK_DOMAIN active CLOCK_SOURCE index. |
| `stream-format` | Get or set a STREAM_INPUT/OUTPUT format word without reconnecting. |
| `sampling-rate` | Get or set the AUDIO_UNIT current sampling rate. |
| `max-transit-time` | Get or set a talker's Milan max transit time (presentation offset). |
| `identify` | Trigger an entity's CONTROL[0] IDENTIFY (e.g. blink an LED). |
| `volume` | Get or set CONTROL[1] Speaker Volume (dB). |
| `mic-gain` | Get or set CONTROL[2] Mic Gain (dB). |
| `direct-disconnect-tx` | Send `DISCONNECT_TX_COMMAND` straight to a talker (diagnostic). |
| `read-descriptor` | Send AECP `READ_DESCRIPTOR` and dump the raw + parsed response. |
| `avb-info` | Query runtime gPTP/SRP state via `GET_AVB_INFO` (BTC, AS_CAPABLE, propagation delay). |
| `harvest` | Read every well-known descriptor type and report per-request RTT. |

#### `discover`

Listens for ADP advertisements and asynchronously reads each new entity's
name, stream descriptors, and stream-name strings. Prints a summary table
when the window expires; `--streams` adds a per-entity breakdown of stream
descriptors and supported format ranges.

```
sudo python3 atdecc_controller.py discover [--duration SECONDS] [--streams]
```

| Option | Default | Description |
|---|---|---|
| `--duration`, `-d` | `5.0` | Listen window. Increase for devices that advertise infrequently. |
| `--streams`, `-s` | off | Append per-entity stream descriptors (current format, supported formats, rate/depth/channel ranges). |

Summary columns: entity ID, name, model ID, roles (`Talker`/`Listener`/
`Controller` from capability flags), MAC, and stream counts (`TX:<n>, RX:<m>`).

#### `stream-info`

Sends `GET_STREAM_INFO` for indices 0–3 of both `STREAM_OUTPUT` and
`STREAM_INPUT`, stopping at `NO_SUCH_DESCRIPTOR`.

```
sudo python3 atdecc_controller.py stream-info <entity_id>
```

Per-stream fields: current format (with validity flag), stream ID, connected
flag, dest MAC, VLAN, SR class, talker-failed / streaming-wait flags, MSRP
failure code from the rejecting bridge, negotiated accumulated latency, and
the raw 8-byte format word for cross-referencing the spec.

#### `connect` / `disconnect`

`connect` sends ACMP `CONNECT_RX_COMMAND` to the listener (via the ACMP
multicast `91:e0:f0:01:00:00`); the listener completes the standard
handshake with the talker. With `--format`, the controller first sends
`SET_STREAM_FORMAT` to both endpoints so they agree on rate / depth /
channels. `disconnect` sends `DISCONNECT_RX_COMMAND` and leaves formats
untouched.

```
sudo python3 atdecc_controller.py connect <talker_id> <listener_id>
        [--format FMT] [--match-supported] [--class-b]
        [--talker-uid N] [--listener-uid N]
sudo python3 atdecc_controller.py disconnect <talker_id> <listener_id>
        [--talker-uid N] [--listener-uid N]
```

| Option | Default | Description |
|---|---|---|
| `--format`, `-f` | *(none)* | Stream format preset to set on both endpoints first. See [Stream formats](#stream-formats). |
| `--match-supported`, `-m` | off | With `--format`: read each endpoint's supported-formats list and pick the closest entry per side (scored on subtype, rate, channels, depth). Use when devices encode the same logical format with different bytes — most commonly the AAF bit-depth byte (Milan PCM32 `0x20` vs the widespread 24-bit `0x18`). Without it, strict-matching firmware rejects anything not byte-equal to its list. |
| `--class-b`, `-b` | off (Class A) | Set the ACMP `CLASS_B` flag so the connection uses SR Class B (priority 2, 250 µs interval). |
| `--talker-uid` | `0` | Talker `STREAM_OUTPUT[N]` index. |
| `--listener-uid` | `0` | Listener `STREAM_INPUT[N]` index. |

> `--format` always targets `STREAM_OUTPUT[0]` / `STREAM_INPUT[0]`
> regardless of the uid options. For other indices, set formats out of band
> and connect without `--format`. CRF media-clock streams connect with the
> normal `connect` command using the CRF stream uids (commonly index 1).

```bash
# Most common case: stream 0 to stream 0
sudo python3 atdecc_controller.py connect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06

# Force AAF 48 kHz on both ends first
sudo python3 atdecc_controller.py connect 00:1b:21:ff:fe:01:02:03 00:1b:21:ff:fe:04:05:06 \
    --format aaf-48k --match-supported
```

#### `get-tx-state`

Asks a talker output for its authoritative `Connection Count` — useful when
talker and listener disagree about a connection.

```
sudo python3 atdecc_controller.py get-tx-state <talker_id> <talker_uid>
```

#### `clock-source`

Gets or sets the active CLOCK_SOURCE index of a CLOCK_DOMAIN — for switching
between internal, gPTP, and CRF/media-clock domains.

```
sudo python3 atdecc_controller.py clock-source <entity_id> [--clock-domain N] [--set SOURCE_INDEX]
```

#### `stream-format`

Gets or sets one stream's 8-byte format word directly (the `connect`
command can also set formats as part of a connection; this one works on
either end, standalone). Most entities refuse SET while the stream is
running — disconnect first.

```
sudo python3 atdecc_controller.py stream-format <entity_id> input|output [--index N] [--set FORMAT_HEX]
```

#### `sampling-rate`

Gets or sets the AUDIO_UNIT current sampling rate (Hz). Note that many
devices refuse or ignore SET (macOS answers NOT_SUPPORTED; some
endpoints change rate only through `stream-format`).

```
sudo python3 atdecc_controller.py sampling-rate <entity_id> [--index N] [--set HZ]
```

#### `max-transit-time`

Gets or sets a STREAM_OUTPUT's Milan max transit time (the talker's
presentation-time offset, in nanoseconds; Milan v1.2 §5.4.2.29). SET is
refused with STREAM_IS_RUNNING while the stream is active.

```
sudo python3 atdecc_controller.py max-transit-time <talker_entity_id> [--index N] [--set NS]
```

#### `identify`, `volume`, `mic-gain`

Standard AEM controls. `identify` writes CONTROL[0] (uint8: `1` starts
identifying, `0` clears; `--value`). `volume` (CONTROL[1]) and `mic-gain`
(CONTROL[2]) read the current value with no arguments or set it with
`--set-db DB` (encoded as int16 tenths of a dB on the wire).

```bash
sudo python3 atdecc_controller.py identify 00:1b:21:ff:fe:01:02:03
sudo python3 atdecc_controller.py volume   00:1b:21:ff:fe:01:02:03 --set-db -6
sudo python3 atdecc_controller.py mic-gain 00:1b:21:ff:fe:01:02:03          # read
```

#### `direct-disconnect-tx`

Sends `DISCONNECT_TX_COMMAND` straight to a talker, bypassing the listener —
a diagnostic for probing talker state machines or clearing stuck listener
registrations. Normal teardown should use `disconnect`.

```
sudo python3 atdecc_controller.py direct-disconnect-tx <talker_id> <listener_id> <talker_uid> <listener_uid>
```

#### `read-descriptor`

Sends one `READ_DESCRIPTOR` and dumps the response as hex plus a parsed
summary (parsing implemented for entity, configuration, stream in/out and
strings; others hex-only). Handy for diagnosing controller-reported model
errors by seeing exactly what the entity returns.

```
sudo python3 atdecc_controller.py read-descriptor <entity_id> <descriptor> [--index N] [--config-index N]
```

`descriptor` is a known name (`entity`, `configuration`, `audio_unit`,
`stream_input`, `stream_output`, `strings`, `control`, `avb_interface`,
`clock_source`, `memory_object`, `locale`, `stream_port_input`,
`stream_port_output`, `audio_cluster`, `audio_map`, `clock_domain`) or a
numeric type (`0x0007`).

#### `avb-info`

Sends `GET_AVB_INFO` and prints the entity's *runtime* gPTP/SRP state —
which grandmaster (BTC) it is actually locked to, the domain, `AS_CAPABLE` /
gPTP / SRP flags, measured propagation delay, and MSRP mapping count. This
is live state, unlike `read-descriptor avb_interface`, which returns the
interface's own identity.

```
sudo python3 atdecc_controller.py avb-info <entity_id> [--index N]
```

#### `harvest`

Reads every well-known descriptor type in turn and times each round-trip —
for benchmarking AECP responsiveness (e.g. wired endpoint vs one behind a
Wi-Fi bridge) and seeing which descriptors an entity implements.

```
sudo python3 atdecc_controller.py harvest <entity_id> [--index N] [--timeout SECONDS] [--repeat N]
```

### Stream formats

`--format` presets (all 8-channel):

| Name | Encoding | Sample rate |
|---|---|---|
| `am824-44.1k` … `am824-192k` | IEC 61883-6 AM824, 24-bit | 44.1 / 48 / 96 / 176.4 / 192 kHz |
| `aaf-44.1k` … `aaf-192k` | AAF PCM, 24-bit in 32-bit container | 44.1 / 48 / 96 / 176.4 / 192 kHz |

Aliases: `am824` → `am824-48k`, `aaf` → `aaf-48k`, `61883` → `am824-48k`.

The AAF words carry the Milan-canonical `samples_per_frame` (one Class A
interval: 6 @48 k, 12 @96 k, 24 @176.4/192 k) and bit-depth byte `0x18`
(24 significant bits) — the encoding macOS uses natively. Strict Milan Base
formats differ in exactly one byte (bit depth `0x20`); when a device only
lists one variant, `--match-supported` bridges the gap. Non-8-channel
formats have no presets: configure the device out of band and connect
without `--format`.

### End-to-end example

```bash
# 1. Find the entities.
sudo python3 atdecc_controller.py -i eno1 discover -s

# 2. Inspect both ends.
sudo python3 atdecc_controller.py -i eno1 stream-info 00:1b:21:ff:fe:aa:bb:cc   # talker
sudo python3 atdecc_controller.py -i eno1 stream-info 00:1b:21:ff:fe:dd:ee:ff   # listener

# 3. Set AAF 48 kHz on both endpoints and connect.
sudo python3 atdecc_controller.py -i eno1 connect \
    00:1b:21:ff:fe:aa:bb:cc 00:1b:21:ff:fe:dd:ee:ff --format aaf-48k

# 4. Verify from the talker's perspective.
sudo python3 atdecc_controller.py -i eno1 get-tx-state 00:1b:21:ff:fe:aa:bb:cc 0

# 5. Tear down.
sudo python3 atdecc_controller.py -i eno1 disconnect \
    00:1b:21:ff:fe:aa:bb:cc 00:1b:21:ff:fe:dd:ee:ff
```

### Troubleshooting

- **`No entities discovered.`** — wrong `-i`, link down, devices on another
  VLAN, or the switch filters ATDECC multicast. Try a longer `--duration`.
- **`Timeout: no <RESPONSE> received`** on connect/disconnect — the listener
  didn't answer on the ACMP multicast; confirm with `discover` that it is
  online and the entity ID is right. (Targeting a macOS entity from the
  same Mac? See [macOS notes](#macos-notes).)
- **`SET_STREAM_FORMAT` returns `NOT_SUPPORTED`** — the exact bytes aren't
  in the stream's supported list; use `discover -s` to see the list, or
  `--match-supported`.
- **`MSRP Fail: code=<n>` in `stream-info`** — a bridge rejected the
  reservation (bandwidth, missing SR class, MSRP off). ACMP can still
  report connected while no audio flows; fix the switch config, and watch
  it live with `msrp_dashboard.py`.
- **Format set succeeds but `connect` fails** — `--format` targets index 0;
  a connect at higher uids needs the format configured on those indices out
  of band.

---

## mrp_applicant.py

A stateless MRP applicant for the two registration protocols: **MVRP**
(IEEE 802.1ak, VLAN registration, ethertype `0x88F5`) and **MSRP**
(IEEE 802.1Qat, Talker / Listener / Domain attributes, ethertype `0x22EA`).
It encodes standard MRPDUs, retransmits its JoinIn while running, decodes
everything the bridge and peers send back, and ends with a pass/fail summary
of protocol expectations — useful for verifying a bridge's SR configuration
before bringing up real streams.

```
sudo python3 mrp_applicant.py [--interface IFACE] [-v] <command> [args]
```

`-v` prints every decoded MRPDU as it arrives; otherwise only the summary.

| Command | Purpose |
|---|---|
| `monitor` | Passively decode MSRP+MVRP for `--duration`, then summarize every VID, stream, and domain seen. |
| `mvrp <vid>` | Register a VLAN ID and check that the bridge reflects it back. |
| `talker <stream_id>` | Advertise an MSRP Talker (StreamID + TSpec); report TalkerFailed codes and Listener replies. |
| `listener <stream_id>` | Declare an MSRP Listener (`--declaration ready\|asking_failed\|ready_failed\|ignore`); report the matching Talker attribute. |
| `domain` | Declare an MSRP Domain (SR class, priority, VID); expect a matching echo. |

Common options across the active commands:

| Option | Default | Description |
|---|---|---|
| `--duration` | `5.0` (`10.0` for monitor) | Run length in seconds. |
| `--join-interval` | `1.0` | Seconds between repeated JoinIn declarations. |
| `--no-leave` | off | Skip the `Lv` normally sent on exit. |
| `--sr-class` | `A` | Selects default SR class ID / PCP / VID (A: 6/3/2, B: 5/2/2). |
| `--pcp`, `--vid` | from class | Overrides. |
| `--send-domain` | off | (`talker`/`listener`) also declare a Domain first. |

Talker-specific TSpec options: `--dest-mac` (default `91:e0:f0:00:fe:00`),
`--max-frame-size` (1500), `--max-interval-frames` (1), `--rank` (1 =
non-emergency), `--accumulated-latency` (0 ns).

```bash
# Watch the wire quietly, then exercise the SRP control plane step by step.
sudo python3 mrp_applicant.py -i eno1 monitor --duration 2
sudo python3 mrp_applicant.py -i eno1 mvrp 2 --duration 3
sudo python3 mrp_applicant.py -i eno1 domain --sr-class A --duration 3
sudo python3 mrp_applicant.py -i eno1 talker 00:1b:21:01:02:03:00:01 \
    --max-frame-size 200 --max-interval-frames 1 --duration 5
```

### Troubleshooting

- **No MRPDUs in `monitor`** — the port isn't on an MRP-aware bridge, or
  the bridge forwards these control frames only to other bridges. Confirm
  the link partner runs MSRP/MVRP.
- **`TalkerFailed code=1` (insufficient bandwidth)** — the requested TSpec
  exceeds the egress idle slope; shrink the TSpec or raise the SR-class
  allocation on the switch.
- **`TalkerFailed code=18` (VLAN tagging disabled)** — the bridge requires
  SR frames tagged; ensure the stream's VID is configured on the port.
- **`Listener declared Ready` fails** — nothing is subscribing; that
  expectation needs a real listener (or a second host running
  `mrp_applicant.py listener ...`).

---

## msrp_dashboard.py

A live, full-screen terminal dashboard of MSRP/SRP stream reservations,
captured with `tshark`. Per Stream ID it tracks the talker declaration
(`ADV`, or `FAIL` with the 802.1Q failure code and reporting bridge), every
listener beneath it (`RDY` / `ASK-FAIL` / `RDY-FAIL` / `IGN`), and a derived
per-listener reservation state — with a rolling event log of
`RESERVATION UP` / `RESERVATION LOST` transitions. Built to make a flapping
reservation — the classic cause of audio dropouts while every controller
still shows "connected" — visible as it happens.

```
uv run msrp_dashboard.py -i <iface> [-i <iface> ...]
uv run msrp_dashboard.py -r <capture.pcap>
```

`uv` installs `rich` on first run from the script's inline metadata; plain
`python3` works if `rich` is present. `Ctrl-C` quits with a summary.

| Option | Default | Description |
|---|---|---|
| `-i`, `--interface` | *(required unless `-r`)* | Capture interface; repeat to watch several. |
| `-r`, `--read FILE` | *(none)* | Replay a pcap/pcapng instead of live capture. |
| `--confirm SECONDS` | `= --leaveall-max` | Freshness window for a green `YES`. |
| `--leavetime SECONDS` | `5` | MSRP LeaveTime (Milan v1.3 default). |
| `--leaveall-max SECONDS` | `15.5` | Max LeaveAll timer (Milan tolerance); the reservation-lost ceiling is `leaveall-max + leavetime`. |
| `--forget SECONDS` | `60` | Drop a stream row this long after its last update. |
| `--filter BPF` | `ether proto 0x22ea` | Override the capture filter (applied per interface). |
| `--no-color` | off | Plain output. |

**Tap placement matters.** Capture on more than one interface when talker
and listener sit on different links, and tap each side at its *source*
egress (the talker's own link and each listener's own link). A registered
MRP attribute is only guaranteed to be re-sent once per LeaveAll
(~10–15 s), and the relayed copy on the far side is sparser — a one-sided
view can make a healthy reservation read `YES?` or even `no`.

### Reading the dashboard

- **`Rsv` is the signal that matters** (a Milan talker transmits only while
  a Listener Ready is registered):
  - `YES` (green) — advertise and Ready both re-seen within one LeaveAll
    cycle.
  - `YES?` (yellow) — still held, but not re-seen recently; almost always a
    tap or re-declaration gap, not a dropout.
  - `no` (red) — torn down: an explicit Leave (debounced ~2 s per Milan
    4.2.7.2.2), a Talker Failed, a non-Ready listener, or no refresh past
    the ceiling.
- **Timers default to Milan v1.3 Table 4.3** (LeaveTime 5 s, LeaveAll
  10–15 s). For plain-802.1Q networks set `--leavetime` ≈ 1.
- **Rows group one header per Stream ID with one `└` sub-row per
  listener.** The Stream ID names the true talker (its first six bytes are
  the talker's MAC and survive relays), which is why there is deliberately
  no talker-MAC column. The listener MAC is the *immediate sender* of the
  Listener declaration.
- **One listener row can stand for many devices.** MRP is hop-by-hop:
  a bridge merges all downstream listeners into a single declaration with
  its *own* MAC. A listener row bearing a switch's MAC is the aggregate of
  everything behind that switch — indistinguishable on the wire from an end
  device, because MSRP carries no listener identity beyond the sender MAC.
  To see individual listeners, tap their own access links.
- **LeaveAll appears in the event log** (blue, tagged with the attribute
  scope it rode in), never as a phantom all-zero stream.
- **An idle classic-AVB talker shows no row at all** — macOS and other
  classic talkers only advertise once a listener connects; Milan talkers
  advertise continuously. Absence isn't a capture problem.

```bash
uv run msrp_dashboard.py -i enp2s0f2 -i enp2s0f0   # talker egress + listener egress
uv run msrp_dashboard.py -r msrp.pcap               # replay a capture
uv run msrp_dashboard.py -i eno1 --leavetime 1      # non-Milan timers
```

### Troubleshooting

- **`YES?` / flips to `no` while audio plays** — the Ready isn't re-crossing
  your tap between LeaveAlls, or the listener is behind a bridge on an
  untapped link. Add its link with another `-i`, or match the timers to
  your bridge.
- **`FAIL` rows for streams you don't care about** — the dashboard shows
  every stream on the wire; other talkers' failures don't affect yours.
- **Nothing appears** — verify MSRP is on the interface
  (`tshark -i <iface> -f 'ether proto 0x22ea'`) and SR is enabled on the
  bridge.

---

## avtp_streamer.py

Synthesizes a sine wave and transmits it as a correctly-paced AVTP audio
stream — AAF (IEEE 1722-2016 §7) or IEC 61883-6 AM824 (§9) — at the SR
Class A (8000 pps) or Class B (4000 pps) cadence. The first M of N channels
carry the sine; the rest carry silence, which makes channel routing on a
listener easy to verify without audio hardware.

This is a generator only: it performs no MSRP or ATDECC. Compliant listeners
usually need a reservation and/or an ACMP connection first — use
`mrp_applicant.py` / `atdecc_controller.py` for that.

```
sudo python3 avtp_streamer.py [--interface IFACE] --stream-id <ID> [options]
```

| Option | Default | Description |
|---|---|---|
| `--format` | `aaf` | `aaf` or `am824`. |
| `--stream-id` | *(required)* | 8-byte StreamID (colon-hex or 16 hex chars). |
| `--dest-mac` | `91:e0:f0:00:fe:00` | Destination MAC. |
| `--freq` | `1000` | Sine frequency (Hz). |
| `--duration` | `5.0` | Stream length (seconds). |
| `--amplitude` | `0.5` | 0..1 fraction of full scale. |
| `--sample-rate` | `48000` | 8 k–192 k for AAF; 32 k–192 k for AM824. |
| `--bit-depth` | `24` | AAF: 16/24/32. AM824 is always 24. |
| `--channels` | `8` | Total channels per frame (N). |
| `--active-channels` | `2` | First M channels carry the sine. |
| `--sr-class` | `A` | `A` (8000 pps) or `B` (4000 pps). |
| `--vlan` / `--pcp` | *(none)* / from class | Optional 802.1Q tag (PCP defaults A=3, B=2). |
| `--presentation-offset` | `2.0` | ms added to `avtp_timestamp` (uses `CLOCK_TAI` when available). |

```bash
# 1 kHz sine on 2 of 8 channels, AAF 48 kHz/24-bit, 5 s
sudo python3 avtp_streamer.py -i eno1 --stream-id 00:1b:21:01:02:03:00:01 \
    --freq 1000 --duration 5 --channels 8 --active-channels 2

# AM824 stereo at 440 Hz, tagged VLAN 2
sudo python3 avtp_streamer.py -i eno1 --format am824 \
    --stream-id 00:1b:21:01:02:03:00:02 --freq 440 --duration 30 \
    --channels 2 --active-channels 2 --vlan 2
```

A per-second progress line and an exit summary report measured pps, sample
rate and bit rate; the tool exits `2` if it delivered less than 99.9% of the
requested samples on time (host overloaded / throttled pacing). Pair it with
the analyzer for a closed loop:

```bash
sudo tshark -i eno1 -f 'ether proto 0x22f0' -a duration:30 -w stream.pcap
python3 avtp_audio_analyzer.py stream.pcap --wav out.wav
```

### Troubleshooting

- **Clicks or dropouts at the listener** — check the measured pps / sample
  rate in the summary; if low, reduce channels, use `--sr-class B`, or a
  lower rate.
- **Packets flow but no audio** — the listener likely requires an MSRP
  reservation and/or ACMP connection before accepting the stream.
- **Muted channels** — intended: channels `[M..N)` carry exact zeros.

---

## avtp_audio_analyzer.py

Extracts PCM audio from AVTP captures (AAF PCM or IEC 61883-6 AM824),
optionally writes a WAV, and analyzes the signal: sequence gaps, level
(peak/RMS dBFS), discontinuities, silence gaps, and — with `numpy` — RMS
envelope anomalies with periodicity detection, fundamental/SNR/THD, and
Hilbert-transform phase continuity (with `scipy`). Offline and
platform-independent.

```
python3 avtp_audio_analyzer.py <pcap> [options]
```

| Option | Default | Description |
|---|---|---|
| `--wav FILE` | *(none)* | Write extracted audio as WAV (mono). |
| `--src-mac MAC` | *(none)* | Filter by source MAC. |
| `--channel N` | `0` | Channel index to extract. |
| `--sample-rate HZ` | `48000` | Fallback rate for IEC 61883-6 (AAF auto-detects). |
| `--bit-depth BITS` | `24` | Bit depth for analysis scaling. |

pcapng input is auto-converted via `editcap` (from Wireshark).

```bash
python3 avtp_audio_analyzer.py capture.pcap                       # analysis report
python3 avtp_audio_analyzer.py capture.pcap --wav out.wav          # extract audio
python3 avtp_audio_analyzer.py capture.pcap --src-mac 00:11:22:33:44:55 --channel 1
```

---

## gptp_inspector.py

Live decoder for gPTP (IEEE 802.1AS, ethertype 0x88F7) frames with direction
tagging (`OUT` = sent by this machine, by source MAC). Per-packet lines show
message type, sequence, source port identity, and the interesting body
fields — Announce priority vectors (priority1/2, clock class, BTC identity,
steps removed), Follow_Up origin timestamps and corrections, Pdelay
requesting ports. Ends (and can periodically print) a per-type count/rate
summary plus measured outbound Sync/Announce cadence.

Cross-platform: BPF via `bpf_shim.py` on macOS, AF_PACKET elsewhere (it
joins the 802.1AS link-local multicast group so NIC filtering can't hide
peer traffic). On a Mac, remember the [kext caveat](#macos-notes): only
inbound and third-party frames are visible there.

```
sudo python3 gptp_inspector.py [-i IFACE] [options]
```

| Option | Default | Description |
|---|---|---|
| `-i`, `--interface` | `en0` | Capture interface. |
| `-d`, `--duration` | *(until Ctrl-C)* | Stop after N seconds. |
| `-n`, `--count` | *(none)* | Stop after N matching packets. |
| `--direction` | `out` | `out`, `in`, or `both`. |
| `-t`, `--type NAME` | *(all)* | Only show these message types (repeatable): `Sync`, `Announce`, `Follow_Up`, `Pdelay_Req`, … |
| `-q`, `--quiet` | off | Summary only, no per-packet lines. |
| `-v`, `--verbose` | off | Extra body fields (log intervals, corrections, clock quality). |
| `--summary-interval N` | *(none)* | Print a rolling summary every N seconds. |

```bash
# Who is announcing, and with what priority vector?
sudo python3 gptp_inspector.py -i eno1 --direction both -d 10 -t Announce -v

# Is my machine transmitting Sync at the right cadence? (Linux)
sudo python3 gptp_inspector.py -i eno1 -q -d 30
```

---

## gptp_monitor_macos.py

Reports a Mac's **outbound** gPTP activity — the side no packet capture on
macOS can see (see [macOS notes](#macos-notes)). The transmitting kext
publishes per-port state and counters in the IORegistry
(`IOTimeSyncEthernetPort`); this tool polls them and reports outbound
Sync / Announce / Pdelay rates (attempted and transmit-confirmed),
asCapable, measured link propagation delay, sync interval, the inferred
port role (`timeTransmitter` / `timeReceiver`), local and received priority
vectors, and any movement in the RX-discard reason counters (domain / role /
length mismatches — the fields that name most negotiation failures). No
root required.

Ports typically appear twice per interface (domain + CMLDS instances),
shown as `[0]` / `[1]`.

```
python3 gptp_monitor_macos.py [options]
```

| Option | Default | Description |
|---|---|---|
| `-i`, `--interval` | `2.0` | Sampling cadence in seconds. |
| `-n`, `--samples` | *(until Ctrl-C)* | Stop after N samples. |
| `--mac SUBSTR` | *(all ports)* | Only ports whose MAC contains this substring. |
| `--once` | off | Dump every raw property of each port once and exit. |

```bash
python3 gptp_monitor_macos.py --mac d0:11 -i 3        # live rates + role
python3 gptp_monitor_macos.py --once                  # raw property dump
```

---

## stream_monitor_macos.swift

Live play-through monitor for an AVB stream a Mac is listening to: opens the
Mac's AVB CoreAudio input device (the virtual entity), taps one channel,
sample-rate-converts, and renders it to any CoreAudio output device — a
headphone jack, a USB codec feeding a measurement rig, or the speakers.
Built for unattended bench monitoring where DAW monitor paths give up:
it ignores CoreAudio configuration-change notifications entirely (they
storm and also miss real stalls), and instead watches its own frame
counters — if audio stops flowing for ~5 s it tears the engines down and
rebuilds, and if a device is missing it retries every 2 s. CoreAudio HAL
calls that hang (a wedged coreaudiod can block `AVAudioEngine` start or
teardown forever) are handled by a watchdog that exits the process
(rc=42) so a supervisor can relaunch a fresh HAL client.

Build on the Mac (no Xcode project needed, just the command-line tools):

```bash
swiftc -O -swift-version 5 stream_monitor_macos.swift -o stream_monitor_macos
```

Usage:

```bash
./stream_monitor_macos list      # enumerate input/output devices with rates
./stream_monitor_macos run [--input SUBSTR] [--output SUBSTR|default]
                           [--channel N] [--gain DB] [--buffer MS]
```

| Option | Default | Description |
|---|---|---|
| `--input SUBSTR` | `Ethernet` | Input device name substring (the AVB virtual entity appears as e.g. `Mac mini:Ethernet` once a stream input is bound). |
| `--output SUBSTR` | system default | Output device name substring, or `default`. |
| `--channel N` | `0` | Which stream channel to monitor. |
| `--gain DB` | `0` | Output gain in dB. |
| `--buffer MS` | `200` | Ring buffer depth; absorbs the clock drift between the AVB stream and the output DAC (drop-oldest on overflow). |

It prints an attach line on every (re)build and a stats line every 10 s
(`in=`/`out=` frame counters, ring fill, over/underruns, restarts) — useful
as render-health telemetry in logs.

For unattended operation run it under the supervisor wrapper
(`stream_monitor_macos.sh`, relaunches on watchdog exits) or as a launchd
agent so it starts at login and is relaunched automatically:

```xml
<!-- ~/Library/LaunchAgents/com.example.stream_monitor.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.example.stream_monitor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/you/stream_monitor_macos</string>
    <string>run</string>
    <string>--input</string><string>Ethernet</string>
    <string>--output</string><string>default</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
  <key>ThrottleInterval</key><integer>3</integer>
  <key>StandardOutPath</key><string>/Users/you/stream_monitor.log</string>
  <key>StandardErrorPath</key><string>/Users/you/stream_monitor.log</string>
</dict>
</plist>
```

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.stream_monitor.plist
```

### Troubleshooting

- **`waiting (no input device matching ...)`** — the AVB CoreAudio device
  only materializes while a stream input is bound (ACMP) and a user is
  logged in; the tool attaches by itself once it appears.
- **Input exists but delivers silence** — macOS microphone privacy may be
  gating the launching context; run it once from a local Terminal to
  trigger the prompt, or grant under System Settings → Privacy & Security
  → Microphone.
- **Repeated `exited rc=42` relaunches** — a HAL call hung, usually a
  wedged/dead coreaudiod. If coreaudiod will not respawn (SIP blocks
  `kickstart`/`bootout`/`killall` for it), only a reboot recovers audio.
- **Do not clock the Mac from a CRF stream while monitoring** — on
  current macOS builds a CRF-clocked AVB input kills coreaudiod within
  minutes (crash in AudioDSPManager); use INPUT_STREAM clocking.

---

## Protocol references

- IEEE 1722-2016 (AVTP) — §7 AAF, §9 IEC 61883, §10 CRF
- IEEE 1722.1-2021 (ATDECC) — ADP, ACMP, AECP
- IEEE 802.1Q-2018 — §10 MRP/MVRP, §35 MSRP
- IEEE 802.1AS (gPTP)
- Avnu Milan v1.3 — stream formats (§6), media clocking (§7), SRP timers (Table 4.3)
