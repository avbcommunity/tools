// stream_monitor_macos — live play-through monitor for an AVB stream input.
//
// Opens a CoreAudio input device (default: the AVB virtual entity,
// matched by name substring), taps one channel, sample-rate-converts,
// and renders it to a chosen CoreAudio output device. Unlike a DAW
// monitor path it survives AVB device blinks: on any configuration
// change or device disappearance it tears down and rebuilds until the
// devices come back.
//
// Build:  swiftc -O -swift-version 5 stream_monitor_macos.swift -o stream_monitor_macos
// Usage:  stream_monitor_macos list
//         stream_monitor_macos run [--input SUBSTR] [--output SUBSTR|default]
//                    [--channel N] [--gain DB] [--buffer MS]
//
// Notes:
//  - Input capture may require a one-time Microphone privacy grant for
//    the launching context (Terminal / sshd) in System Settings.
//  - Clock domains differ (AVB stream clock vs output DAC); the ring
//    absorbs drift and drops oldest audio on overflow — stats show it.

import Foundation
import AVFoundation
import CoreAudio
import AudioToolbox

// ---------- CoreAudio device helpers ----------

func propAddr(_ sel: AudioObjectPropertySelector,
              _ scope: AudioObjectPropertyScope = kAudioObjectPropertyScopeGlobal)
    -> AudioObjectPropertyAddress {
    AudioObjectPropertyAddress(mSelector: sel, mScope: scope,
                               mElement: kAudioObjectPropertyElementMain)
}

func allDeviceIDs() -> [AudioDeviceID] {
    var addr = propAddr(kAudioHardwarePropertyDevices)
    var size: UInt32 = 0
    guard AudioObjectGetPropertyDataSize(AudioObjectID(kAudioObjectSystemObject),
                                         &addr, 0, nil, &size) == noErr else { return [] }
    var ids = [AudioDeviceID](repeating: 0,
                              count: Int(size) / MemoryLayout<AudioDeviceID>.size)
    guard AudioObjectGetPropertyData(AudioObjectID(kAudioObjectSystemObject),
                                     &addr, 0, nil, &size, &ids) == noErr else { return [] }
    return ids
}

func deviceName(_ id: AudioDeviceID) -> String {
    var addr = propAddr(kAudioObjectPropertyName)
    var cfName: CFString = "" as CFString
    var size = UInt32(MemoryLayout<CFString>.size)
    let err = withUnsafeMutablePointer(to: &cfName) { ptr -> OSStatus in
        AudioObjectGetPropertyData(id, &addr, 0, nil, &size, ptr)
    }
    return err == noErr ? (cfName as String) : "?"
}

func channelCount(_ id: AudioDeviceID, input: Bool) -> Int {
    var addr = propAddr(kAudioDevicePropertyStreamConfiguration,
                        input ? kAudioDevicePropertyScopeInput
                              : kAudioDevicePropertyScopeOutput)
    var size: UInt32 = 0
    guard AudioObjectGetPropertyDataSize(id, &addr, 0, nil, &size) == noErr,
          size > 0 else { return 0 }
    let raw = UnsafeMutableRawPointer.allocate(byteCount: Int(size),
                                               alignment: MemoryLayout<AudioBufferList>.alignment)
    defer { raw.deallocate() }
    guard AudioObjectGetPropertyData(id, &addr, 0, nil, &size, raw) == noErr else { return 0 }
    let abl = UnsafeMutableAudioBufferListPointer(raw.assumingMemoryBound(to: AudioBufferList.self))
    return abl.reduce(0) { $0 + Int($1.mNumberChannels) }
}

func nominalRate(_ id: AudioDeviceID) -> Double {
    var addr = propAddr(kAudioDevicePropertyNominalSampleRate)
    var rate: Float64 = 0
    var size = UInt32(MemoryLayout<Float64>.size)
    return AudioObjectGetPropertyData(id, &addr, 0, nil, &size, &rate) == noErr ? rate : 0
}

func defaultOutputDevice() -> AudioDeviceID? {
    var addr = propAddr(kAudioHardwarePropertyDefaultOutputDevice)
    var id: AudioDeviceID = 0
    var size = UInt32(MemoryLayout<AudioDeviceID>.size)
    let err = AudioObjectGetPropertyData(AudioObjectID(kAudioObjectSystemObject),
                                         &addr, 0, nil, &size, &id)
    return (err == noErr && id != 0) ? id : nil
}

func findDevice(nameContains needle: String, input: Bool) -> AudioDeviceID? {
    let n = needle.lowercased()
    return allDeviceIDs().first {
        channelCount($0, input: input) > 0 && deviceName($0).lowercased().contains(n)
    }
}

// ---------- SPSC float ring ----------

final class Ring {
    private var buf: [Float]
    private var head = 0 // write index
    private var tail = 0 // read index
    private var lock = os_unfair_lock()
    let capacity: Int
    private(set) var overruns = 0
    private(set) var underruns = 0

    init(capacity: Int) {
        self.capacity = capacity
        buf = [Float](repeating: 0, count: capacity)
    }

    var fill: Int {
        os_unfair_lock_lock(&lock); defer { os_unfair_lock_unlock(&lock) }
        return (head - tail + capacity) % capacity
    }

    func write(_ src: UnsafePointer<Float>, count n: Int) {
        os_unfair_lock_lock(&lock); defer { os_unfair_lock_unlock(&lock) }
        let free = capacity - 1 - (head - tail + capacity) % capacity
        if n > free { // drop oldest to make room; keeps latency bounded
            let need = n - free
            tail = (tail + need) % capacity
            overruns += 1
        }
        for i in 0..<n {
            buf[(head + i) % capacity] = src[i]
        }
        head = (head + n) % capacity
    }

    func read(into dst: UnsafeMutablePointer<Float>, count n: Int) {
        os_unfair_lock_lock(&lock); defer { os_unfair_lock_unlock(&lock) }
        let avail = (head - tail + capacity) % capacity
        let take = min(n, avail)
        for i in 0..<take {
            dst[i] = buf[(tail + i) % capacity]
        }
        if take < n {
            for i in take..<n { dst[i] = 0 }
            underruns += 1
        }
        tail = (tail + take) % capacity
    }
}

// ---------- Monitor ----------

final class Monitor {
    let inNeedle: String
    let outNeedle: String? // nil = system default output
    let channel: Int
    let gain: Float
    let bufferMs: Int

    private var engineIn: AVAudioEngine?
    private var engineOut: AVAudioEngine?
    private var srcNode: AVAudioSourceNode?
    private var converter: AVAudioConverter?
    private var monoInFmt: AVAudioFormat?
    private var monoOutFmt: AVAudioFormat?
    private var ring: Ring
    private let restartFlag = DispatchSemaphore(value: 0)
    private var hwInFmt: AVAudioFormat?
    private var buildGen = 0
    private var restarts = 0
    // Phase tracking for the suicide watchdog: CoreAudio HAL calls
    // (engine start, tap removal) can block forever when coreaudiod or
    // the AVB plugin wedges. A hung process renders silence and can't
    // recover in-process, so past a deadline we exit and let the
    // supervisor wrapper relaunch a fresh HAL client.
    private var phase = "idle"
    private var phaseStart = Date()

    private func setPhase(_ p: String) {
        phase = p
        phaseStart = Date()
    }
    private var framesIn: UInt64 = 0
    private var framesOut: UInt64 = 0

    init(inNeedle: String, outNeedle: String?, channel: Int, gain: Float, bufferMs: Int) {
        self.inNeedle = inNeedle
        self.outNeedle = outNeedle
        self.channel = channel
        self.gain = gain
        self.bufferMs = bufferMs
        self.ring = Ring(capacity: 1) // replaced at build time
    }

    private func setDevice(_ node: AVAudioIONode, _ dev: AudioDeviceID) -> Bool {
        guard let au = node.audioUnit else { return false }
        var d = dev
        return AudioUnitSetProperty(au, kAudioOutputUnitProperty_CurrentDevice,
                                    kAudioUnitScope_Global, 0, &d,
                                    UInt32(MemoryLayout<AudioDeviceID>.size)) == noErr
    }

    private func teardown() {
        engineIn?.inputNode.removeTap(onBus: 0)
        engineIn?.stop()
        engineOut?.stop()
        engineIn = nil
        engineOut = nil
        srcNode = nil
        converter = nil
    }

    /// One build attempt; throws a descriptive error when a device is
    /// missing or an engine refuses to start.
    private func build() throws {
        guard let inDev = findDevice(nameContains: inNeedle, input: true) else {
            throw NSError(domain: "stream_monitor", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "no input device matching \"\(inNeedle)\""])
        }
        let outDev: AudioDeviceID
        if let n = outNeedle {
            guard let d = findDevice(nameContains: n, input: false) else {
                throw NSError(domain: "stream_monitor", code: 2, userInfo: [
                    NSLocalizedDescriptionKey: "no output device matching \"\(n)\""])
            }
            outDev = d
        } else {
            guard let d = defaultOutputDevice() else {
                throw NSError(domain: "stream_monitor", code: 3, userInfo: [
                    NSLocalizedDescriptionKey: "no default output device"])
            }
            outDev = d
        }

        let ein = AVAudioEngine()
        let eout = AVAudioEngine()

        guard setDevice(ein.inputNode, inDev) else {
            throw NSError(domain: "stream_monitor", code: 4, userInfo: [
                NSLocalizedDescriptionKey: "cannot select input device"])
        }
        guard setDevice(eout.outputNode, outDev) else {
            throw NSError(domain: "stream_monitor", code: 5, userInfo: [
                NSLocalizedDescriptionKey: "cannot select output device"])
        }

        let inFmt = ein.inputNode.inputFormat(forBus: 0)
        let outRate = nominalRate(outDev)
        guard inFmt.sampleRate > 0, inFmt.channelCount > 0 else {
            throw NSError(domain: "stream_monitor", code: 6, userInfo: [
                NSLocalizedDescriptionKey: "input device has no usable format (mic privacy grant missing?)"])
        }
        guard outRate > 0 else {
            throw NSError(domain: "stream_monitor", code: 7, userInfo: [
                NSLocalizedDescriptionKey: "output device has no nominal rate"])
        }

        let ch = min(channel, Int(inFmt.channelCount) - 1)
        let monoIn = AVAudioFormat(commonFormat: .pcmFormatFloat32,
                                   sampleRate: inFmt.sampleRate, channels: 1,
                                   interleaved: false)!
        let monoOut = AVAudioFormat(commonFormat: .pcmFormatFloat32,
                                    sampleRate: outRate, channels: 1,
                                    interleaved: false)!
        guard let conv = AVAudioConverter(from: monoIn, to: monoOut) else {
            throw NSError(domain: "stream_monitor", code: 8, userInfo: [
                NSLocalizedDescriptionKey: "cannot build \(inFmt.sampleRate)->\(outRate) converter"])
        }

        ring = Ring(capacity: max(4096, Int(outRate) * bufferMs / 1000))
        // Prefill half the ring with silence so output starts with
        // headroom in both directions instead of underrunning while the
        // input side fills.
        var zeros = [Float](repeating: 0, count: ring.capacity / 2)
        ring.write(&zeros, count: zeros.count)
        hwInFmt = inFmt
        converter = conv
        monoInFmt = monoIn
        monoOutFmt = monoOut

        let g = gain
        let ringRef = ring

        // Input side: tap hw format, extract one channel, SRC, push.
        ein.inputNode.installTap(onBus: 0, bufferSize: 4096, format: inFmt) {
            [weak self] buffer, _ in
            guard let self = self, let conv = self.converter,
                  let monoIn = self.monoInFmt, let monoOut = self.monoOutFmt,
                  let data = buffer.floatChannelData else { return }
            let n = Int(buffer.frameLength)
            if n == 0 { return }
            self.framesIn &+= UInt64(n)

            guard let inBuf = AVAudioPCMBuffer(pcmFormat: monoIn,
                                               frameCapacity: AVAudioFrameCount(n)),
                  let outBuf = AVAudioPCMBuffer(pcmFormat: monoOut,
                                                frameCapacity: AVAudioFrameCount(n) + 64)
            else { return }
            inBuf.frameLength = AVAudioFrameCount(n)
            memcpy(inBuf.floatChannelData![0], data[ch], n * MemoryLayout<Float>.size)

            var fed = false
            var err: NSError?
            let st = conv.convert(to: outBuf, error: &err) { _, outStatus in
                if fed { outStatus.pointee = .noDataNow; return nil }
                fed = true
                outStatus.pointee = .haveData
                return inBuf
            }
            if st == .error { return }
            let m = Int(outBuf.frameLength)
            if m == 0 { return }
            let p = outBuf.floatChannelData![0]
            if g != 1.0 {
                for i in 0..<m { p[i] *= g }
            }
            ringRef.write(p, count: m)
        }

        // Output side: source node pulls from the ring.
        let src = AVAudioSourceNode(format: monoOut) {
            [weak self] _, _, frameCount, abl -> OSStatus in
            let ablp = UnsafeMutableAudioBufferListPointer(abl)
            guard let dst = ablp[0].mData?.assumingMemoryBound(to: Float.self) else {
                return noErr
            }
            ringRef.read(into: dst, count: Int(frameCount))
            self?.framesOut &+= UInt64(frameCount)
            return noErr
        }
        eout.attach(src)
        eout.connect(src, to: eout.mainMixerNode, format: monoOut)
        eout.connect(eout.mainMixerNode, to: eout.outputNode, format: nil)

        try eout.start()
        do {
            try ein.start()
        } catch {
            eout.stop()
            throw error
        }

        engineIn = ein
        engineOut = eout
        srcNode = src
        buildGen += 1

        print("stream_monitor: \(deviceName(inDev)) ch\(ch) @\(Int(inFmt.sampleRate))Hz -> " +
              "\(deviceName(outDev)) @\(Int(outRate))Hz " +
              "(ring \(ring.capacity) samples, gain \(g))")
    }

    func scheduleRestart() { restartFlag.signal() }

    func run() {
        // Stats every 10 s on a background timer.
        let statsQ = DispatchQueue(label: "stream_monitor.stats")
        let timer = DispatchSource.makeTimerSource(queue: statsQ)
        timer.schedule(deadline: .now() + 10, repeating: 10)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            let fillMs = self.monoOutFmt.map {
                Int(Double(self.ring.fill) / $0.sampleRate * 1000) } ?? 0
            print("stream_monitor: in=\(self.framesIn) out=\(self.framesOut) " +
                  "fill=\(fillMs)ms over=\(self.ring.overruns) " +
                  "under=\(self.ring.underruns) restarts=\(self.restarts)")
            fflush(stdout)
        }
        timer.resume()

        // Watchdog: rebuild when frame counters stop advancing. HAL
        // configuration-change notifications proved untrustworthy both
        // ways (spurious storms AND engines silently pausing), so the
        // only signal we act on is "is audio actually flowing".
        let wdQ = DispatchQueue(label: "stream_monitor.watchdog")
        let wd = DispatchSource.makeTimerSource(queue: wdQ)
        wd.schedule(deadline: .now() + 2.5, repeating: 2.5)
        var wdGen = -1
        var wdIn: UInt64 = 0
        var wdOut: UInt64 = 0
        var wdStall = 0
        wd.setEventHandler { [weak self] in
            guard let self = self else { return }
            if self.buildGen != wdGen { // fresh build: re-baseline
                wdGen = self.buildGen
                wdIn = self.framesIn
                wdOut = self.framesOut
                wdStall = 0
                return
            }
            let inFroze = self.framesIn == wdIn
            let outFroze = self.framesOut == wdOut
            if inFroze || outFroze {
                wdStall += 1
            } else {
                wdStall = 0
            }
            wdIn = self.framesIn
            wdOut = self.framesOut
            if wdStall >= 2 {
                wdStall = 0
                print("stream_monitor: stall source: input=\(inFroze ? "FROZEN" : "ok") " +
                      "output=\(outFroze ? "FROZEN" : "ok")")
                fflush(stdout)
                self.scheduleRestart()
            }
        }
        wd.resume()

        let suicideQ = DispatchQueue(label: "stream_monitor.suicide")
        let sw = DispatchSource.makeTimerSource(queue: suicideQ)
        sw.schedule(deadline: .now() + 2, repeating: 2)
        sw.setEventHandler { [weak self] in
            guard let self = self else { return }
            let dt = Date().timeIntervalSince(self.phaseStart)
            if (self.phase == "teardown" && dt > 8) ||
               (self.phase == "build" && dt > 30) {
                print("stream_monitor: \(self.phase) hung \(Int(dt))s, exiting for relaunch")
                fflush(stdout)
                _exit(42)
            }
        }
        sw.resume()

        signal(SIGINT) { _ in
            print("\nstream_monitor: bye")
            exit(0)
        }

        // Build/rebuild loop. Any configuration change (device blink,
        // rate change, unplug) lands here and we retry until it works.
        while true {
            setPhase("build")
            do {
                try build()
                setPhase("run")
            } catch {
                setPhase("teardown")
                teardown()
                setPhase("idle")
                print("stream_monitor: waiting (\(error.localizedDescription))")
                fflush(stdout)
                Thread.sleep(forTimeInterval: 2.0)
                continue
            }
            // Discard restart requests raised while (re)building.
            while restartFlag.wait(timeout: .now()) == .success {}
            fflush(stdout)
            restartFlag.wait() // block until the watchdog sees a stall
            while restartFlag.wait(timeout: .now() + 0.5) == .success {}
            restarts += 1
            print("stream_monitor: audio stalled, rebuilding")
            fflush(stdout)
            setPhase("teardown")
            teardown()
            setPhase("idle")
            Thread.sleep(forTimeInterval: 0.5)
        }
    }
}

// ---------- CLI ----------

func listDevices() {
    print("Input devices:")
    for id in allDeviceIDs() where channelCount(id, input: true) > 0 {
        print(String(format: "  [%u] %@ (%dch @%.0fHz)", id, deviceName(id),
                     channelCount(id, input: true), nominalRate(id)))
    }
    print("Output devices:")
    for id in allDeviceIDs() where channelCount(id, input: false) > 0 {
        let def = (id == defaultOutputDevice()) ? "  <- default" : ""
        print(String(format: "  [%u] %@ (%dch @%.0fHz)%@", id, deviceName(id),
                     channelCount(id, input: false), nominalRate(id), def))
    }
}

var args = Array(CommandLine.arguments.dropFirst())
guard let cmd = args.first else {
    print("usage: stream_monitor_macos list | stream_monitor_macos run [--input SUBSTR] [--output SUBSTR] " +
          "[--channel N] [--gain DB] [--buffer MS]")
    exit(2)
}
args.removeFirst()

switch cmd {
case "list":
    listDevices()
case "run":
    var inNeedle = "Ethernet" // AVB virtual entity device name substring
    var outNeedle: String? = nil
    var channel = 0
    var gainDb: Float = 0
    var bufferMs = 200
    var i = 0
    while i < args.count {
        let a = args[i]
        func next() -> String {
            i += 1
            guard i < args.count else { fputs("missing value for \(a)\n", stderr); exit(2) }
            return args[i]
        }
        switch a {
        case "--input": inNeedle = next()
        case "--output":
            let v = next()
            outNeedle = (v == "default") ? nil : v
        case "--channel": channel = Int(next()) ?? 0
        case "--gain": gainDb = Float(next()) ?? 0
        case "--buffer": bufferMs = Int(next()) ?? 200
        default:
            fputs("unknown option \(a)\n", stderr); exit(2)
        }
        i += 1
    }
    let mon = Monitor(inNeedle: inNeedle, outNeedle: outNeedle, channel: channel,
                      gain: pow(10, gainDb / 20), bufferMs: bufferMs)
    mon.run()
default:
    print("unknown command \(cmd)")
    exit(2)
}
