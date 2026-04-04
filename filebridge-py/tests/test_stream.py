"""Tests for JSON response encryption/decryption."""

import json
import pytest

from filebridge.stream import decrypt_json_response, encrypt_json_response, parse_json_response, StreamError
from filebridge.exceptions import FileBridgeError


TOKEN = "test-secret"
IV_HEX = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


def test_encrypt_decrypt_roundtrip():
    payload = {"items": [{"name": "foo.txt", "is_dir": False}]}
    json_bytes = json.dumps(payload).encode()

    encoded = encrypt_json_response(TOKEN, IV_HEX, json_bytes)
    decoded = decrypt_json_response(TOKEN, IV_HEX, encoded)

    assert json.loads(decoded) == payload


def test_wrong_token_fails():
    json_bytes = b'{"name": "test.txt", "is_dir": false}'
    encoded = encrypt_json_response(TOKEN, IV_HEX, json_bytes)

    with pytest.raises(StreamError):
        decrypt_json_response("wrong-token", IV_HEX, encoded)


def test_wrong_iv_fails():
    json_bytes = b'{"name": "test.txt", "is_dir": false}'
    encoded = encrypt_json_response(TOKEN, IV_HEX, json_bytes)

    with pytest.raises(StreamError):
        decrypt_json_response(TOKEN, "0000000000000000", encoded)


def test_parse_json_response_plain():
    body = b'{"name": "file.txt", "is_dir": false}'
    data = parse_json_response(None, None, body)
    assert data == {"name": "file.txt", "is_dir": False}


def test_parse_json_response_encrypted():
    inner = {"name": "file.txt", "is_dir": False}
    encoded = encrypt_json_response(TOKEN, IV_HEX, json.dumps(inner).encode())
    envelope = json.dumps({"message": encoded}).encode()

    data = parse_json_response(TOKEN, IV_HEX, envelope)
    assert data == inner


def test_parse_json_response_missing_message_raises():
    body = json.dumps({"unexpected": "field"}).encode()
    with pytest.raises(FileBridgeError, match="Missing 'message'"):
        parse_json_response(TOKEN, IV_HEX, body)


def test_parse_json_response_no_token_skips_decrypt():
    # Even if there's a signature, no token means plain JSON
    body = b'{"items": []}'
    data = parse_json_response(None, IV_HEX, body)
    assert data == {"items": []}


# ---------------------------------------------------------------------------
# StreamAead
# ---------------------------------------------------------------------------

import struct  # noqa: E402

from filebridge.stream import StreamAead, StreamDecoder, encode_data, encode_stop  # noqa: E402


def test_stream_aead_roundtrip():
    aead_enc = StreamAead(TOKEN, IV_HEX)
    ct = aead_enc.encrypt(b"hello world")
    aead_dec = StreamAead(TOKEN, IV_HEX)
    pt = aead_dec.decrypt(ct)
    assert pt == b"hello world"


def test_stream_aead_counter_mismatch():
    # Encrypt two chunks; ct1 was produced at counter=1.
    # A fresh AEAD (counter=0) must reject ct1.
    aead = StreamAead(TOKEN, IV_HEX)
    aead.encrypt(b"chunk0")
    ct1 = aead.encrypt(b"chunk1")

    fresh = StreamAead(TOKEN, IV_HEX)
    with pytest.raises(StreamError):
        fresh.decrypt(ct1)


def test_stream_aead_wrong_token():
    aead = StreamAead(TOKEN, IV_HEX)
    ct = aead.encrypt(b"data")
    wrong = StreamAead("wrong-token", IV_HEX)
    with pytest.raises(StreamError):
        wrong.decrypt(ct)


def test_stream_aead_finalize_verify():
    aead_enc = StreamAead(TOKEN, IV_HEX)
    hex_sig = aead_enc.finalize()
    aead_dec = StreamAead(TOKEN, IV_HEX)
    # Must not raise
    aead_dec.verify_stop(hex_sig)


# ---------------------------------------------------------------------------
# Frame encoding
# ---------------------------------------------------------------------------


def test_encode_data_header():
    payload = b"hello"
    frame = encode_data(payload)
    assert frame[:4] == b"DATA"
    length = struct.unpack(">I", frame[4:8])[0]
    assert length == len(payload)
    assert frame[8:] == payload


def test_encode_stop_no_sig():
    frame = encode_stop()
    assert frame[:4] == b"STOP"
    assert frame[4:8] == b"\x00\x00\x00\x00"


def test_encode_stop_with_sig():
    sig = "deadbeef1234"
    frame = encode_stop(sig)
    assert frame[:4] == b"STOP"
    length = struct.unpack(">I", frame[4:8])[0]
    assert length == len(sig.encode())
    assert frame[8 : 8 + length] == sig.encode()


# ---------------------------------------------------------------------------
# StreamDecoder
# ---------------------------------------------------------------------------


def test_stream_decoder_data_frame():
    data = b"hello world"
    decoder = StreamDecoder()
    decoder.push(encode_data(data))
    result = decoder.next_frame()
    assert result is not None
    tag, sig_str, payload = result
    assert tag == "DATA"
    assert payload == data
    assert sig_str is None


def test_stream_decoder_stop_frame():
    sig = "abc123"
    decoder = StreamDecoder()
    decoder.push(encode_stop(sig))
    result = decoder.next_frame()
    assert result is not None
    tag, sig_str, payload = result
    assert tag == "STOP"
    assert sig_str == sig


def test_stream_decoder_split_push():
    data = b"hello world"
    frame = encode_data(data)
    half = len(frame) // 2
    decoder = StreamDecoder()
    decoder.push(frame[:half])
    assert decoder.next_frame() is None
    decoder.push(frame[half:])
    result = decoder.next_frame()
    assert result is not None
    tag, _, payload = result
    assert tag == "DATA"
    assert payload == data


def test_stream_decoder_multiple_frames():
    chunks = [b"chunk1", b"chunk2", b"chunk3"]
    combined = b"".join(encode_data(c) for c in chunks)
    decoder = StreamDecoder()
    decoder.push(combined)
    results = []
    while True:
        f = decoder.next_frame()
        if not f:
            break
        results.append(f)
    assert len(results) == 3
    for i, (tag, _, payload) in enumerate(results):
        assert tag == "DATA"
        assert payload == chunks[i]


def test_decode_verified_stream_roundtrip():
    from filebridge.stream import build_encrypted_write_body, decode_verified_stream_content

    original = b"roundtrip test data"
    encrypted = build_encrypted_write_body(TOKEN, IV_HEX, original)
    result = decode_verified_stream_content(TOKEN, IV_HEX, encrypted)
    assert result == original
