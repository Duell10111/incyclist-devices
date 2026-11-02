import { EventLogger } from "gd-eventlog";
import { BindingsFactory } from "../../../bindings/index.js";
import { ICryptoBinding } from "../../../bindings/crypto/types.js";
import { sleep } from "../../../utils/utils.js";
import { SerialPortStream } from "../../types.js";
import { buildFrame, ElexFrame, ElexFrameParser, ElexMessage, ElexSubType } from "./framing.js";

// Fixed key of the Elex authentication: the request carries two random bytes followed by MD5(random bytes + key)
export const ELEX_AUTH_KEY = [53, 216, 52, 213, 157, 160, 11, 187, 67, 201, 23, 67, 172, 205, 86, 3]

const CRLF = '\r\n'

export type ElexHandshakeTimeouts = {
    /** time to collect and drop leftovers from a previous session */
    flush: number
    /** time to wait for an answer to the text ID probe */
    textProbe: number
    /** time to wait for a binary answer frame */
    frame: number
    /** time to wait for a text answer after switching to text mode */
    text: number
}

// the bike answers within a few 100ms; keep the delay for ports without a Kettler bike (e.g. during scans) short
const DEFAULT_TIMEOUTS: ElexHandshakeTimeouts = { flush: 300, textProbe: 1500, frame: 2000, text: 2000 }

export type ElexHandshakeProps = {
    logger?: EventLogger
    timeouts?: Partial<ElexHandshakeTimeouts>
}

export type ElexHandshakeResult = {
    /**
     * - `text`: the bike already answered in text protocol (classic Kettler bike, or an Elex bike still in text mode)
     * - `elex`: binary handshake done, bike switched to text protocol
     * - `none`: neither text nor binary answer
     */
    mode: 'text' | 'elex' | 'none'
    id?: string
    elexId?: string
    firmware?: number
}

/** device IDs look like "EA10S1801" (letters/digits only) - anything else is a leftover or an error */
export const isValidIdentifier = (s: string | undefined): boolean =>
    !!s && !s.includes('ERROR') && /^[A-Z]{2}[A-Z0-9]{2,}$/.test(s)

const getCrypto = (): ICryptoBinding => {
    let crypto = BindingsFactory.getInstance()?.getBinding()?.crypto
    if (!crypto)
        // same fallback as the Zwift Play sensor: Node's crypto when no binding is registered
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        crypto = require('node:crypto')
    return crypto as ICryptoBinding
}

export const buildAuthPayload = (random: Buffer): Buffer => {
    const md5 = getCrypto().createHash('md5').update(Buffer.from([random[0], random[1], ...ELEX_AUTH_KEY])).digest()
    return Buffer.concat([random.subarray(0, 2), md5])
}

/**
 * Prepares a freshly opened port of a Kettler bike for the text protocol (ID, VE, KI, CM, ST, PW, RS).
 *
 * Bikes of the Racer S generation (Bluetooth) start in a binary protocol ("Elex") and only accept text
 * commands after an authentication and a "switch to text mode" message. Depending on the platform the bike
 * might still be in text mode from a previous session (e.g. iOS keeps the Bluetooth link when a session is
 * closed), and leftovers of that session might still be buffered. Therefore:
 *
 * 1. leftovers are dropped
 * 2. a text `ID` is sent - in binary mode the bike ignores it, in text mode it answers
 * 3. only if there is no answer, the binary handshake is done
 *
 * The data listener is removed again before returning, so the caller can attach its own parser.
 */
export async function prepareConnection(port: SerialPortStream, props: ElexHandshakeProps = {}): Promise<ElexHandshakeResult> {
    const timeouts = { ...DEFAULT_TIMEOUTS, ...props.timeouts }
    const logger = props.logger

    const parser = new ElexFrameParser()
    const frames: ElexFrame[] = []
    let lines: string[] = []
    let partial = ''

    const onData = (data: Buffer | string) => {
        const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'latin1')
        frames.push(...parser.feed(buffer))
        partial += buffer.toString('latin1')
        const parts = partial.split(CRLF)
        partial = parts.pop() ?? ''
        lines.push(...parts)
    }

    const flush = () => {
        lines = []
        partial = ''
        frames.splice(0, frames.length)
    }

    const waitFor = async <T>(get: () => T | undefined, timeout: number): Promise<T | undefined> => {
        const end = Date.now() + timeout
        while (Date.now() < end) {
            const value = get()
            if (value !== undefined)
                return value
            await sleep(10)
        }
        return undefined
    }

    const sendText = async (cmd: string, timeout: number): Promise<string | undefined> => {
        lines = []
        port.write(cmd + CRLF)
        return waitFor(() => lines.shift(), timeout)
    }

    const sendFrame = async (messageId: ElexMessage, subType: ElexSubType, payload: Buffer = Buffer.alloc(0), timeout = timeouts.frame) => {
        frames.splice(0, frames.length)
        port.write(buildFrame(messageId, subType, payload))
        return waitFor(() => frames.find(f => f.messageId === messageId), timeout)
    }

    // asks for the ID until a clean answer arrives; late answers of earlier commands are dropped in between
    const syncText = async (attempts: number, timeout: number): Promise<{ answered: boolean, id?: string }> => {
        let answered = false
        for (let i = 0; i < attempts; i++) {
            const answer = await sendText('ID', timeout)
            logger?.logEvent({ message: 'text ID probe', answer })
            if (answer === undefined)
                return { answered }
            answered = true
            if (isValidIdentifier(answer))
                return { answered, id: answer }
            await sleep(500)
            flush()
        }
        return { answered }
    }

    port.on('data', onData)
    try {
        await sleep(timeouts.flush)
        flush()

        const probe = await syncText(3, timeouts.textProbe)
        if (probe.id)
            return { mode: 'text', id: probe.id }
        if (probe.answered) {
            // answers in text, but never in sync - leave it to the regular protocol handling
            return { mode: 'text' }
        }

        logger?.logEvent({ message: 'no text answer, trying Elex handshake' })
        const auth = await sendFrame(ElexMessage.Authentication, ElexSubType.Read, buildAuthPayload(getCrypto().randomBytes(2)))
        if (!auth) {
            logger?.logEvent({ message: 'Elex handshake: no answer to authentication' })
            return { mode: 'none' }
        }

        const result: ElexHandshakeResult = { mode: 'elex' }
        const deviceId = await sendFrame(ElexMessage.DeviceId, ElexSubType.Read)
        if (deviceId)
            result.elexId = deviceId.payload.toString('latin1')
        const firmware = await sendFrame(ElexMessage.FirmwareVersion, ElexSubType.Read)
        if (firmware?.payload.length >= 2)
            result.firmware = firmware.payload.readUInt16BE(0)

        // switching has no answer frame; the first text command afterwards is usually answered with ERROR
        port.write(buildFrame(ElexMessage.SwitchToTextMode, ElexSubType.Write))
        await sleep(300)
        flush()

        const text = await syncText(3, timeouts.text)
        result.id = text.id
        logger?.logEvent({ message: 'Elex handshake done', ...result })
        if (!text.answered)
            return { ...result, mode: 'none' }
        return result
    }
    catch (err) {
        logger?.logEvent({ message: 'Elex handshake error', error: err.message })
        return { mode: 'none' }
    }
    finally {
        port.removeListener('data', onData)
    }
}
