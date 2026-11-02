import { buildFrame, ElexFrameParser, ElexMessage, ElexSubType } from './framing'
import { buildAuthPayload } from './handshake'

// captured from a Kettler Racer S (EA10S, firmware 4609)
const CAPTURED_AUTH = Buffer.from('020001010012528947e088f294011940f94670c94167288e0305e0', 'hex')

describe('Elex framing', () => {

    describe('buildFrame', () => {
        test('authentication request as captured from the bike', () => {
            const payload = buildAuthPayload(Buffer.from([0x52, 0x89]))
            expect(buildFrame(ElexMessage.Authentication, ElexSubType.Read, payload)).toEqual(CAPTURED_AUTH)
        })

        test('request without payload', () => {
            const frame = buildFrame(ElexMessage.DeviceId, ElexSubType.Read)
            expect(frame[0]).toBe(0x02)
            expect(frame.subarray(1, 6)).toEqual(Buffer.from([0, 4, 1, 0, 0]))
            expect(frame[6]).toBe(0x03)
        })

        test('escapes STX, ETX and DLE', () => {
            const frame = buildFrame(ElexMessage.FirmwareVersion, ElexSubType.Read)
            // message id 2 = STX must be sent as DLE, 0x22
            expect(frame.subarray(1, 4)).toEqual(Buffer.from([0x00, 0x10, 0x22]))
        })
    })

    describe('ElexFrameParser', () => {
        test('round trip', () => {
            const frames = new ElexFrameParser().feed(buildFrame(ElexMessage.DeviceId, ElexSubType.Answer, Buffer.from('EA10S1201')))
            expect(frames).toEqual([{ messageId: 4, subType: 3, payload: Buffer.from('EA10S1201') }])
        })

        test('round trip with escaped bytes in payload', () => {
            const payload = Buffer.from([0x02, 0x03, 0x10, 0x12, 0x01])
            const frames = new ElexFrameParser().feed(buildFrame(ElexMessage.FirmwareVersion, ElexSubType.Answer, payload))
            expect(frames).toEqual([{ messageId: 2, subType: 3, payload }])
        })

        test('frame split over several chunks, surrounded by text', () => {
            const parser = new ElexFrameParser()
            const frame = buildFrame(ElexMessage.DeviceId, ElexSubType.Answer, Buffer.from('EA10S1201'))
            const data = Buffer.concat([Buffer.from('ERROR\r\n'), frame, Buffer.from('ACK\r\n')])

            const frames = [...parser.feed(data.subarray(0, 10)), ...parser.feed(data.subarray(10))]
            expect(frames.map(f => f.payload.toString())).toEqual(['EA10S1201'])
        })

        test('frame with wrong CRC is dropped', () => {
            const frame = buildFrame(ElexMessage.DeviceId, ElexSubType.Answer, Buffer.from('EA10S1201'))
            frame[frame.length - 1] ^= 0xff
            expect(new ElexFrameParser().feed(frame)).toEqual([])
        })
    })
})
