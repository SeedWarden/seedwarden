import base64


class Convert:
    "Static conversion method."

    @staticmethod
    def bytes_to_base64str(b: bytes) -> str:
        return base64.standard_b64encode(b).decode("ascii")

    @staticmethod
    def base64str_to_bytes(s: str) -> bytes:
        return base64.b64decode(s, validate=True)
