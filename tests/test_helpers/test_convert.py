from seedwarden.helpers import Convert


def test_base64str():
    plain = b"hello world"
    encoded = Convert.bytes_to_base64str(plain)
    assert encoded == "aGVsbG8gd29ybGQ="
    decoded = Convert.base64str_to_bytes(encoded)
    assert decoded == plain
