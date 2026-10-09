import os

from seedwarden.helpers import Convert


class Scalar:
    """
    Modulo N arithmetic.

    Note: using big integers, which is generally not safe for cryptography,
    but should be acceptable for an offline system like SeedWarden.
    """

    # Modulus. Happens to be the secp256k1 curve order, so it _could_ be used as private key (but isn't),
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    @staticmethod
    def random() -> Scalar:
        "Create a random scalar."
        while True:
            candidate = int.from_bytes(os.urandom(32), "big", signed=False)
            if candidate < Scalar.N:
                return Scalar(candidate)

    __slots__ = ("_v",)

    def __init__(self, value: int):
        assert value >= 0 and value < Scalar.N
        self._v = value

    def __add__(self, other):
        other = other if isinstance(other, Scalar) else Scalar(other)
        return Scalar((self._v + other._v) % Scalar.N)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        other = other if isinstance(other, Scalar) else Scalar(other)
        return Scalar((self._v - other._v) % Scalar.N)

    def __rsub__(self, other):
        other = other if isinstance(other, Scalar) else Scalar(other)
        return Scalar((other._v - self._v) % Scalar.N)

    def __neg__(self):
        return Scalar((-self._v) % Scalar.N)

    def __mul__(self, other):
        other = other if isinstance(other, Scalar) else Scalar(other)
        return Scalar((self._v * other._v) % Scalar.N)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __floordiv__(self, other):
        """Modular division: a // b  ≡  a * b⁻¹  (mod N)"""
        other = other if isinstance(other, Scalar) else Scalar(other)
        if other._v == 0:
            raise ZeroDivisionError("division by zero in Scalar")
        inv = pow(other._v, -1, Scalar.N)
        return Scalar((self._v * inv) % Scalar.N)

    def __rfloordiv__(self, other):
        other = other if isinstance(other, Scalar) else Scalar(other)
        return other.__floordiv__(self)

    # ---------- helpers ----------

    def __int__(self):
        return self._v

    def __eq__(self, other):
        if isinstance(other, Scalar):
            return self._v == other._v
        return self._v == (other % Scalar.N)

    def __repr__(self):
        return str(self._v)

    def is_zero(self):
        return self._v == 0


class Share:
    __slots__ = ("id", "x", "y")

    def __init__(self, id: str, x: Scalar, y: Scalar):
        self.id = id
        self.x = x
        self.y = y

    def serialize_qr(self) -> str:
        y_bytes = int(self.y).to_bytes(32, "big", signed=False)
        qr = f"seedwarden:sss:{self.id}:{self.x}:{Convert.bytes_to_base64str(y_bytes)}"
        return qr

    @staticmethod
    def deserialize_qr(qr: str) -> Share:
        parts = qr.split(":")
        assert len(parts) == 5
        assert parts[0] == "seedwarden"
        assert parts[1] == "sss"
        id = parts[2]
        x = Scalar(int(parts[3]))
        y_bytes = Convert.base64str_to_bytes(parts[4])
        y = Scalar(int.from_bytes(y_bytes, "big", signed=False))
        return Share(id, x, y)

    def __repr__(self):
        return self.serialize_qr()


class Polynomial:
    "A polynomial to create shares from."

    __slots__ = ("_coefficients", "_shares", "id", "threshold")

    def __init__(self, threshold: int):
        assert threshold >= 2
        self.threshold = threshold
        self.id = f"{os.urandom(8).hex()}-{threshold}"
        self._coefficients = [Scalar.random() for _ in range(threshold)]
        self._shares = dict[int, Share]()

    @property
    def secret(self) -> Scalar:
        return self._coefficients[0]

    def get_share(self, x: Scalar) -> Share:
        assert x != 0  # zero not allowed, as it would reveal the secret

        share = self._shares.get(int(x))
        if isinstance(share, Share):
            return share

        pow_x = Scalar(1)
        y = self._coefficients[0]
        for c in self._coefficients[1:]:
            pow_x *= x
            y += c * pow_x
        share = Share(self.id, x, y)
        self._shares[int(share.x)] = share
        return share


class Interpolator:
    "Recreate secret from shares."

    __slots__ = ("_shares", "id", "secret", "threshold")

    def __init__(self, share: Share):
        "Initialize with 1st share."
        self.id = share.id
        self.threshold = int(share.id[share.id.find("-") + 1 :])
        assert self.threshold >= 2
        self.secret = None
        self._shares = dict[int, Share]()
        self._shares[int(share.x)] = share

    @property
    def num_shares(self) -> int:
        "Returns the number of shares already added."
        return len(self._shares)

    def add_share(self, share: Share) -> None:
        "Add a share."
        assert share.id == self.id

        existing = self._shares.get(int(share.x))
        if isinstance(existing, Share):  # ignore share that's already added
            assert existing.y == share.y
            return

        if self.secret is not None:  # ignore redundant share
            return

        self._shares[int(share.x)] = share
        if len(self._shares) < self.threshold:  # not enough shares yet
            return

        # interpolate
        sum = Scalar(0)
        for sh in self._shares.values():
            prod = Scalar(1)
            for other in self._shares.values():
                diff = other.x - sh.x
                if diff != 0:
                    prod *= other.x // diff
            sum += sh.y * prod
        self.secret = sum
