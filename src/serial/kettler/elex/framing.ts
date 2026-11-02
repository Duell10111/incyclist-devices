// Binary framing of the Kettler "Elex" protocol (Racer S generation, Bluetooth).
//
// Frame:  STX | escaped( header + payload ) | ETX | escaped( crcHi ) | escaped( crcLo )
// header: [0, messageId, subType, 0, payloadLength]
// Bytes 0x02 (STX), 0x03 (ETX) and 0x10 (DLE) are sent as DLE followed by (byte XOR 0x20).
// The CRC is a Kermit CRC16 over the unescaped header + payload.

export const STX = 0x02
export const ETX = 0x03
export const DLE = 0x10

export enum ElexMessage {
    Authentication = 1,
    FirmwareVersion = 2,
    DeviceId = 4,
    SwitchToTextMode = 90
}

export enum ElexSubType {
    Read = 1,
    Write = 2,
    Answer = 3
}

const CRC_TABLE: number[] = (() => {
    const table: number[] = []
    for (let i = 0; i < 256; i++) {
        let c = 0
        let v = i
        for (let b = 0; b < 8; b++) {
            c = ((c ^ v) & 1) ? ((c >>> 1) ^ 0x8408) : (c >>> 1)
            v >>>= 1
        }
        table.push(c & 0xffff)
    }
    return table
})()

export const crcUpdate = (crc: number, byte: number): number =>
    ((crc >>> 8) ^ CRC_TABLE[(crc ^ byte) & 0xff]) & 0xffff

const needsEscape = (b: number) => b === STX || b === ETX || b === DLE

export function buildFrame(messageId: number, subType: number, payload: Buffer | number[] = []): Buffer {
    const body = [0, messageId, subType, 0, payload.length, ...Array.from(payload)]
    const out: number[] = [STX]
    const pushEscaped = (b: number) => {
        if (needsEscape(b))
            out.push(DLE, (b ^ 0x20) & 0xff)
        else
            out.push(b & 0xff)
    }

    let crc = 0
    for (const b of body) {
        crc = crcUpdate(crc, b)
        pushEscaped(b)
    }
    out.push(ETX)
    pushEscaped((crc >>> 8) & 0xff)
    pushEscaped(crc & 0xff)
    return Buffer.from(out)
}

export type ElexFrame = {
    messageId: number
    subType: number
    payload: Buffer
}

/**
 * Incremental receive parser: feed bytes as they arrive, completed frames with a valid CRC are returned.
 * Bytes outside of a frame (e.g. text lines) are ignored.
 */
export class ElexFrameParser {
    protected state: 'idle' | 'body' | 'crcHi' | 'crcLo' = 'idle'
    protected escaped = false
    protected crc = 0
    protected frameCrc = 0
    protected body: number[] = []

    feed(data: Buffer | number[]): ElexFrame[] {
        const frames: ElexFrame[] = []
        for (const byte of Array.from(data)) {
            const frame = this.feedByte(byte)
            if (frame)
                frames.push(frame)
        }
        return frames
    }

    protected reset() {
        this.body = []
        this.escaped = false
        this.crc = 0
        this.state = 'body'
    }

    protected unescape(byte: number): number | undefined {
        if (this.escaped) {
            this.escaped = false
            return byte ^ 0x20
        }
        if (byte === DLE) {
            this.escaped = true
            return undefined
        }
        return byte
    }

    protected feedByte(byte: number): ElexFrame | undefined {
        switch (this.state) {
            case 'idle':
                if (byte === STX)
                    this.reset()
                return
            case 'body': {
                if (!this.escaped && byte === STX) {
                    this.reset()
                    return
                }
                if (!this.escaped && byte === ETX) {
                    this.state = 'crcHi'
                    return
                }
                const b = this.unescape(byte)
                if (b === undefined)
                    return
                this.crc = crcUpdate(this.crc, b)
                this.body.push(b)
                return
            }
            case 'crcHi': {
                const b = this.unescape(byte)
                if (b === undefined)
                    return
                this.frameCrc = b << 8
                this.state = 'crcLo'
                return
            }
            case 'crcLo': {
                const b = this.unescape(byte)
                if (b === undefined)
                    return
                this.frameCrc |= b
                this.state = 'idle'
                if (this.frameCrc !== this.crc || this.body.length < 5)
                    return
                const length = this.body[4]
                return {
                    messageId: this.body[1],
                    subType: this.body[2],
                    payload: Buffer.from(this.body.slice(5, 5 + length))
                }
            }
        }
    }
}
