"""Tests for JSON request/response encryption/decryption."""

import json
import pytest

from filebridge.stream import decrypt_json, encrypt_json, parse_json_response, StreamError
from filebridge.exceptions import FileBridgeError


TOKEN = "test-secret"
IV_HEX = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


@pytest.mark.parametrize("direction", ["request", "response"])
def test_encrypt_decrypt_roundtrip(direction):
    payload = {"items": [{"name": "foo.txt", "is_dir": False}]}
    json_bytes = json.dumps(payload).encode()

    encoded = encrypt_json(TOKEN, IV_HEX, json_bytes, direction)
    decoded = decrypt_json(TOKEN, IV_HEX, encoded, direction)

    assert json.loads(decoded) == payload


def test_wrong_token_fails():
    json_bytes = b'{"name": "test.txt", "is_dir": false}'
    encoded = encrypt_json(TOKEN, IV_HEX, json_bytes, "request")

    with pytest.raises(StreamError):
        decrypt_json("wrong-token", IV_HEX, encoded, "request")


def test_wrong_iv_fails():
    json_bytes = b'{"name": "test.txt", "is_dir": false}'
    encoded = encrypt_json(TOKEN, IV_HEX, json_bytes, "request")

    with pytest.raises(StreamError):
        decrypt_json(TOKEN, "0000000000000000", encoded, "request")


def test_json_directions_are_cryptographically_separate():
    # Regression test for C1 (nonce reuse): request and response under the
    # same (token, sig) must use distinct keys/nonces, so a ciphertext from
    # one direction must not decrypt in the other.
    from filebridge.stream import _derive_json_key_nonce

    req_key, req_nonce = _derive_json_key_nonce(TOKEN, IV_HEX, "request")
    resp_key, resp_nonce = _derive_json_key_nonce(TOKEN, IV_HEX, "response")
    assert req_key != resp_key
    assert req_nonce != resp_nonce

    encoded = encrypt_json(TOKEN, IV_HEX, b'{"path":"foo.txt"}', "request")
    with pytest.raises(StreamError):
        decrypt_json(TOKEN, IV_HEX, encoded, "response")


def test_hkdf_cross_language_vectors():
    # These values must match the Rust implementation exactly
    # (test_hkdf_cross_language_vectors in filebridge/src/stream.rs).
    from filebridge.stream import _derive_json_key_nonce, _derive_stream_key_nonce

    stream_key, stream_nonce = _derive_stream_key_nonce(TOKEN, IV_HEX)
    assert (
        stream_key.hex() == "4e1f082bb3d869ec18ee2f8a06fcf9cd8741f2d847fd443a1b6a0d761a7405e7"
    )
    assert stream_nonce.hex() == "fd55d161ad566053ff2d2a0d"

    req_key, req_nonce = _derive_json_key_nonce(TOKEN, IV_HEX, "request")
    assert req_key.hex() == "1ec0e019cb826536296459785c0681fefd1b325049409a7abc4f091cd29665f2"
    assert req_nonce.hex() == "d5bfeb81da44fd83eb5d7f91"

    resp_key, resp_nonce = _derive_json_key_nonce(TOKEN, IV_HEX, "response")
    assert resp_key.hex() == "e4ca88541d1b3086ea6f4c4eeefa346a2cbcb7c56f6ec3b6d768e371f8f24219"
    assert resp_nonce.hex() == "77587e1217cfdec101632a65"


def test_parse_json_response_plain():
    body = b'{"name": "file.txt", "is_dir": false}'
    data = parse_json_response(None, None, body)
    assert data == {"name": "file.txt", "is_dir": False}


def test_parse_json_response_encrypted():
    inner = {"name": "file.txt", "is_dir": False}
    encoded = encrypt_json(TOKEN, IV_HEX, json.dumps(inner).encode(), "response")
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


# ---------------------------------------------------------------------------
# decode_read_response: token mode must reject unverified responses
# ---------------------------------------------------------------------------


def test_decode_read_response_token_rejects_plaintext():
    """Regression: a downgraded (unencrypted) response must not be accepted."""
    from filebridge.stream import decode_read_response

    with pytest.raises(FileBridgeError, match="Unexpected content type"):
        decode_read_response(
            TOKEN, "application/octet-stream", b"forged content", IV_HEX, "f.txt"
        )


def test_decode_read_response_plain_mode_passthrough():
    from filebridge.stream import decode_read_response

    result = decode_read_response(None, "application/octet-stream", b"data", None, "f.txt")
    assert result == b"data"


def test_decode_read_response_json_without_items_raises():
    """Regression: metadata JSON must not be returned as file content."""
    from filebridge.stream import decode_read_response

    body = json.dumps({"name": "f.txt", "is_dir": False}).encode()
    with pytest.raises(FileBridgeError, match="Unexpected JSON metadata"):
        decode_read_response(None, "application/json", body, None, "f.txt")
