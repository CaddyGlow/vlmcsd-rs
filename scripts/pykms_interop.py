#!/usr/bin/env python3
"""Generate fixtures and independently validate Rust responses using unmodified py-kms codecs.

python3 scripts/pykms_interop.py --source /path/to/py-kms --fixtures tests/fixtures
python3 scripts/pykms_interop.py --source /path/to/py-kms --connect 127.0.0.1:21688

Reference: Py-KMS-Organization/py-kms b0e1615dec06293c927625006a99e6ec54a001aa.
Only protocol modules are imported; no third-party Python packages are required.
"""
import argparse
import contextlib
import hashlib
import hmac
import io
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import uuid

EPID = "03612-00206-471-111111-03-1033-17763.0000-0012024"
HWID = bytes.fromhex("364f463a8863d35f")
TIME = 133444736000000000
CMID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff").bytes_le
NDR32 = bytes.fromhex("045d888aeb1cc9119fe808002b104860")
NDR64 = bytes.fromhex("33057171babe37498319b5dbef9ccc36")
INTERFACE = bytes.fromhex("7521c8514e845047b0d8ec255555bc06")


def encoded(value):
    return str(value).encode("latin-1")


def packet(kind, call, body):
    return struct.pack("<BBBB4sHHI", 5, 0, kind, 3, b"\x10\0\0\0", len(body) + 16, 0, call) + body


def receive(sock):
    def exact(size):
        out = bytearray()
        while len(out) < size:
            chunk = sock.recv(size - len(out))
            if not chunk:
                raise AssertionError("unexpected EOF")
            out.extend(chunk)
        return bytes(out)
    header = exact(16)
    size = struct.unpack_from("<H", header, 8)[0]
    assert 16 <= size <= 4096
    return header, exact(size - 16)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--connect")
    args = parser.parse_args()
    if not args.fixtures and not args.connect:
        parser.error("specify --fixtures or --connect")
    sys.path.insert(0, str(args.source / "py-kms"))
    import pykms_Aes as aes
    from pykms_Base import kmsBase, UUID
    from pykms_RequestV4 import kmsRequestV4
    from pykms_RequestV5 import kmsRequestV5
    from pykms_RequestV6 import kmsRequestV6

    # Silence upstream presentation output without modifying protocol implementation.
    import pykms_RequestV4, pykms_RequestV5
    pykms_RequestV4.pretty_printer = lambda **kwargs: None
    pykms_RequestV5.pretty_printer = lambda **kwargs: None
    metadata = {"repository": "https://github.com/Py-KMS-Organization/py-kms", "commit": subprocess.check_output(
        ["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip(), "sha256": {}}
    for version, handler_type in [(4, kmsRequestV4), (5, kmsRequestV5), (6, kmsRequestV6)]:
        handler = handler_type(None, {"epid": EPID, "hwid": HWID, "activation": 120, "renewal": 10080, "sqlite": False})
        handler.getRandomSalt = lambda: bytearray(range(16))
        base = kmsBase.kmsRequestStruct()
        for key, value in {"versionMinor": 0, "versionMajor": version, "isClientVm": 0,
                           "licenseStatus": 2, "graceTime": 43200, "requiredClientCount": 25,
                           "requestTime": TIME}.items():
            base[key] = value
        for key, value in {
            "applicationId": uuid.UUID("55c92734-d682-4d71-983e-d6ec3f16059f").bytes_le,
            "skuId": uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588").bytes_le,
            "kmsCountedId": uuid.UUID("58e2134f-8e11-4d17-9cb2-91069c151148").bytes_le,
            "clientMachineId": CMID, "previousClientMachineId": bytes(16),
        }.items():
            base[key] = UUID(value)
        base["machineName"] = "TEST-PC".encode("utf-16le")
        base["mnPad"] = bytes((63 - 7) * 2)
        with contextlib.redirect_stdout(io.StringIO()):
            request = handler.generateRequest(base)
            wire = encoded(request)
            response_base = encoded(handler.createKmsResponse(base, 50, "Windows"))
        size = struct.unpack_from("<I", wire)[0]
        raw = wire[8:8 + size]
        assert len(encoded(base)) == 236
        assert len(raw) == (252 if version == 4 else 260)
        if args.fixtures:
            args.fixtures.mkdir(parents=True, exist_ok=True)
            files = {f"v{version}-request.bin": raw, f"v{version}-response-base.bin": response_base}
            if version == 4:
                files["v4-response.bin"] = response_base + handler.generateHash(bytearray(response_base))
            else:
                with contextlib.redirect_stdout(io.StringIO()):
                    parsed_request = handler.RequestV5(wire)
                    decrypted = handler.decryptRequest(parsed_request)
                    iv, encrypted = handler.encryptResponse(
                        parsed_request, decrypted, kmsBase.kmsResponseStruct(response_base))
                files[f"v{version}-response.bin"] = struct.pack("<I", version << 16) + iv + encrypted
            for name, data in files.items():
                (args.fixtures / name).write_bytes(data)
                metadata["sha256"][name] = hashlib.sha256(data).hexdigest()
        if not args.connect:
            continue
        host, port = args.connect.rsplit(":", 1)
        for ndr64 in (False, True):
            for fragmented in (False, True):
                with socket.create_connection((host, int(port)), timeout=5) as sock:
                    context = struct.pack("<HBB", 7, 1, 0) + INTERFACE + struct.pack("<I", 1)
                    context += (NDR64 if ndr64 else NDR32) + struct.pack("<I", 1 if ndr64 else 2)
                    sock.sendall(packet(11, 1, struct.pack("<HHII", 4096, 4096, 0, 1) + context))
                    header, ack = receive(sock)
                    assert header[2] == 12
                    address_len = struct.unpack_from("<H", ack, 8)[0]
                    results = (10 + address_len + 3) & ~3
                    assert struct.unpack_from("<I", ack, results)[0] == 1
                    assert ack[results + 4:results + 8] == bytes(4)
                    # Reuse the bound connection and check call IDs for each exchange.
                    for call in (2, 3):
                        stub = struct.pack("<QQ" if ndr64 else "<II", len(raw), len(raw)) + raw
                        prefix = struct.pack("<IHH", len(stub), 7, 0)
                        if fragmented:
                            first = bytearray(packet(0, call, prefix + stub[:97])); first[3] = 1
                            last = bytearray(packet(0, call, prefix + stub[97:])); last[3] = 2
                            sock.sendall(first + last)
                        else:
                            sock.sendall(packet(0, call, prefix + stub))
                        header, body = receive(sock)
                        assert header[2] == 2 and struct.unpack_from("<I", header, 12)[0] == call
                        width = 8 if ndr64 else 4
                        length = int.from_bytes(body[8:8 + width], "little")
                        assert int.from_bytes(body[8 + 2 * width:8 + 3 * width], "little") == length
                        response = body[8 + 3 * width:8 + 3 * width + length]
                        assert body[-4:] == bytes(4)
                        # Reuse Python's response structures and decryptResponse implementation.
                        ndr32_body = struct.pack("<III", length, 0x20000, length) + response + bytes(4 + (-length % 4))
                        if version == 4:
                            parsed = handler.ResponseV4(ndr32_body)
                            plain = encoded(parsed['response'])
                            assert parsed['hash'].encode('latin-1') == handler.generateHash(bytearray(plain))
                        else:
                            parsed = handler.ResponseV5(ndr32_body)
                            decrypted = handler.decryptResponse(parsed)
                            message = decrypted if version == 5 else decrypted['message']
                            plain = encoded(message['response'])
                            cipher = aes.AES(); cipher.v6 = version == 6
                            request_iv = bytes(cipher.decrypt(list(raw[4:20]), handler.key, 16))
                            keys = message['keys'].encode('latin-1')
                            recovered_random = bytes(a ^ b for a, b in zip(keys, request_iv))
                            assert hashlib.sha256(recovered_random).digest() == message['hash'].encode('latin-1')
                            if version == 5:
                                assert response[4:20] == raw[4:20]
                            else:
                                assert message['hwid'].encode('latin-1') == HWID
                                assert message['xorSalts'].encode('latin-1') == request_iv
                                response_iv = bytes(cipher.decrypt(list(response[4:20]), handler.key, 16))
                                expected = hmac.new(handler.getMACKey(TIME), response_iv + encoded(message), hashlib.sha256).digest()[16:]
                                assert decrypted['hmac'].encode('latin-1') == expected
                        assert plain == response_base
                print(f"PASS V{version} NDR{64 if ndr64 else 32} fragmented={fragmented}: two responses, identity, time, intervals and integrity")
    if args.fixtures:
        (args.fixtures / "provenance.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
