"""
SeedWarden vault: an encrypted list of items, see docs/vault-format.md.
"""

import hashlib
import json
import os
import shutil
import tempfile
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from seedwarden.helpers import Convert

from .pbkdf import Pbkdf
from .shamir import Scalar

FORMAT_NAME = "seedwarden-vault"
FORMAT_MAJOR = 1
FORMAT = f"{FORMAT_NAME}/{FORMAT_MAJOR}"
CIPHER = "AES-256-GCM"
SHAMIR_KEK_INFO = b"seedwarden-shamir-kek"


class VaultError(Exception):
    "Base class for vault errors."


class VaultFormatError(VaultError):
    "The vault file is malformed or of an unsupported format."


class VaultDecryptionError(VaultError):
    "Decryption failed: wrong credentials, wrong shares, or tampered data."


class VaultIntegrityError(VaultError):
    "The ciphertext does not match its sha256 checksum."


def _fsync_directory(directory: str) -> None:
    "Persist a rename in directory. Not supported on all platforms (e.g. Windows), skipped there."
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _aad(format: str, id: str) -> bytes:
    return (format + "\n" + id).encode("utf-8")


def _encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    "Encrypt with AES-256-GCM and a fresh random nonce. Returns (nonce, ciphertext)."
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def _decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise VaultDecryptionError("Wrong key, or the data was tampered with.") from None


class Field:
    "A named, typed field. Values are always strings."

    __slots__ = ("name", "type", "value")

    def __init__(self, name: str, type: str, value: str):
        self.name = name
        self.type = type
        self.value = value

    def serialize(self) -> dict:
        return {"name": self.name, "type": self.type, "value": self.value}

    @staticmethod
    def deserialize(serialized: dict) -> Field:
        return Field(serialized["name"], serialized["type"], serialized["value"])


class Item:
    "A named collection of fields."

    __slots__ = ("fields", "name")

    def __init__(self, name: str, fields: list[Field] | None = None):
        self.name = name
        self.fields = fields if fields is not None else []

    def serialize(self) -> dict:
        return {"name": self.name, "fields": [f.serialize() for f in self.fields]}

    @staticmethod
    def deserialize(serialized: dict) -> Item:
        return Item(serialized["name"], [Field.deserialize(f) for f in serialized["fields"]])


class Login(ABC):
    "A login wraps the DEK with a key encryption key (KEK)."

    TYPE: str

    _nonce: bytes
    _wrapped_key: bytes

    def _wrap(self, kek: bytes, dek: bytes, aad: bytes) -> None:
        self._nonce, self._wrapped_key = _encrypt(kek, dek, aad)

    def _unwrap(self, kek: bytes, aad: bytes) -> bytes:
        return _decrypt(kek, self._nonce, self._wrapped_key, aad)

    def _serialize_wrap(self) -> dict:
        return {
            "cipher": CIPHER,
            "nonce": Convert.bytes_to_base64str(self._nonce),
            "wrapped-key": Convert.bytes_to_base64str(self._wrapped_key),
        }

    def _deserialize_wrap(self, serialized: dict) -> None:
        wrap = serialized["wrap"]
        if wrap["cipher"] != CIPHER:
            raise VaultFormatError(f"Unsupported cipher {wrap['cipher']}.")
        self._nonce = Convert.base64str_to_bytes(wrap["nonce"])
        self._wrapped_key = Convert.base64str_to_bytes(wrap["wrapped-key"])

    @abstractmethod
    def serialize(self) -> dict:
        "Convert to a jsonable object with an entry 'type'."

    @staticmethod
    def deserialize(serialized: dict) -> Login | None:
        "Deserialize, or return None for login types unknown to this release."
        match serialized.get("type"):
            case PasswordLogin.TYPE:
                return PasswordLogin.deserialize(serialized)
            case ShamirLogin.TYPE:
                return ShamirLogin.deserialize(serialized)
            case _:
                return None


class PasswordLogin(Login):
    "Login with password + optional PIN, KEK derived by a PBKDF."

    TYPE = "password"

    _kdf: Pbkdf

    @staticmethod
    def create(credentials: Pbkdf.Credentials, dek: bytes, aad: bytes, kdf: Pbkdf | None = None) -> PasswordLogin:
        r = PasswordLogin()
        r._kdf = kdf if kdf is not None else Pbkdf.create()
        r._wrap(r._kdf.digest(credentials), dek, aad)
        return r

    def unlock(self, credentials: Pbkdf.Credentials, aad: bytes) -> bytes:
        return self._unwrap(self._kdf.digest(credentials), aad)

    def serialize(self) -> dict:
        return {"type": self.TYPE, "kdf": self._kdf.serialize(), "wrap": self._serialize_wrap()}

    @staticmethod
    def deserialize(serialized: dict) -> PasswordLogin:
        r = PasswordLogin()
        r._kdf = Pbkdf.deserialize(serialized["kdf"])
        r._deserialize_wrap(serialized)
        return r


class ShamirLogin(Login):
    "Login with a secret recovered from Shamir shares, KEK derived by HKDF."

    TYPE = "shamir"
    KDF_ALGO = "HKDF-SHA256"

    share_set_id: str
    _salt: bytes

    @staticmethod
    def create(share_set_id: str, secret: Scalar, dek: bytes, aad: bytes) -> ShamirLogin:
        r = ShamirLogin()
        r.share_set_id = share_set_id
        r._salt = os.urandom(16)
        r._wrap(r._kek(secret), dek, aad)
        return r

    def _kek(self, secret: Scalar) -> bytes:
        ikm = int(secret).to_bytes(32, "big", signed=False)
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=self._salt, info=SHAMIR_KEK_INFO).derive(ikm)

    def unlock(self, secret: Scalar, aad: bytes) -> bytes:
        return self._unwrap(self._kek(secret), aad)

    def serialize(self) -> dict:
        return {
            "type": self.TYPE,
            "share-set-id": self.share_set_id,
            "kdf": {"algo": self.KDF_ALGO, "salt": Convert.bytes_to_base64str(self._salt)},
            "wrap": self._serialize_wrap(),
        }

    @staticmethod
    def deserialize(serialized: dict) -> ShamirLogin:
        kdf = serialized["kdf"]
        if kdf["algo"] != ShamirLogin.KDF_ALGO:
            raise VaultFormatError(f"Unsupported kdf {kdf['algo']}.")
        r = ShamirLogin()
        r.share_set_id = serialized["share-set-id"]
        r._salt = Convert.base64str_to_bytes(kdf["salt"])
        r._deserialize_wrap(serialized)
        return r


class Vault:
    """
    An unlocked vault: items in plaintext plus the DEK and logins.

    Create with Vault.create(), or load with Vault.unlock_with_password() / unlock_with_shamir().
    Changes set `dirty`; save with to_json(), which re-encrypts and clears `dirty`.
    """

    id: str
    name: str
    items: list[Item]
    logins: list[dict | Login]  # unknown logins are kept as raw dicts so they survive a save
    dirty: bool
    _dek: bytes

    @staticmethod
    def create(name: str) -> Vault:
        r = Vault()
        r.id = os.urandom(16).hex()
        r.name = name
        r.items = []
        r.logins = []
        r.dirty = True
        r._dek = os.urandom(32)
        return r

    @property
    def _aad(self) -> bytes:
        return _aad(FORMAT, self.id)

    # ---------- modification ----------

    def mark_dirty(self) -> None:
        "Call after modifying items or fields in place."
        self.dirty = True

    def add_item(self, item: Item) -> None:
        self.items.append(item)
        self.dirty = True

    def remove_item(self, item: Item) -> None:
        self.items.remove(item)
        self.dirty = True

    def rename(self, name: str) -> None:
        self.name = name
        self.dirty = True

    def add_password_login(self, credentials: Pbkdf.Credentials, kdf: Pbkdf | None = None) -> None:
        self.logins.append(PasswordLogin.create(credentials, self._dek, self._aad, kdf))
        self.dirty = True

    def add_shamir_login(self, share_set_id: str, secret: Scalar) -> None:
        "share_set_id is Polynomial.id, secret is Polynomial.secret."
        self.logins.append(ShamirLogin.create(share_set_id, secret, self._dek, self._aad))
        self.dirty = True

    def list_logins(self) -> list[dict | Login]:
        """
        Logins of this vault, in file order. Indices match remove_login().
        Unknown login types appear as raw dicts.
        """
        return list(self.logins)

    def remove_login(self, index: int) -> None:
        """
        Remove a login. Note: the removed login's key still unwraps the DEK of older copies,
        and of this vault unless rotate_key() is called.
        """
        del self.logins[index]
        self.dirty = True

    def rotate_key(self) -> None:
        """
        Generate a new DEK and drop all logins, because they wrap the old DEK.
        Add logins again before saving, save refuses a vault without logins.
        """
        self._dek = os.urandom(32)
        self.logins = []
        self.dirty = True

    # ---------- save ----------

    def to_json(self) -> str:
        "Encrypt with a new nonce and serialize. Clears the dirty flag."
        text = self._to_json()
        self.dirty = False
        return text

    def _to_json(self) -> str:
        "Encrypt with a new nonce and serialize. Refuses a vault without logins."
        if not self.logins:
            raise VaultError("A vault without logins could never be opened again.")
        payload = json.dumps({"items": [i.serialize() for i in self.items]}).encode("utf-8")
        nonce, ciphertext = _encrypt(self._dek, payload, self._aad)
        doc = {
            "format": FORMAT,
            "id": self.id,
            "name": self.name,
            "dek": {"cipher": CIPHER, "nonce": Convert.bytes_to_base64str(nonce)},
            "logins": [x if isinstance(x, dict) else x.serialize() for x in self.logins],
            "ciphertext": Convert.bytes_to_base64str(ciphertext),
            "sha256": hashlib.sha256(ciphertext).hexdigest(),
        }
        return json.dumps(doc, indent=2)

    def save(self, path) -> None:
        """
        Encrypt and write to path atomically.

        1. Write to a temp file in the same directory, flush and fsync it.
        2. Re-read the temp file and verify it parses and its sha256 matches.
        3. Copy the existing file (if any) to `<name>.bak`, replacing an older .bak.
        4. Replace the target with the temp file and fsync the directory.

        If anything fails, the original file is left untouched. The .bak is kept.
        """
        path = os.fspath(path)
        directory = os.path.dirname(os.path.abspath(path))
        text = self._to_json()

        fd, tmp = tempfile.mkstemp(prefix=".swtmp-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            with open(tmp, encoding="utf-8") as f:
                if not Vault.verify_integrity(f.read()):
                    raise VaultIntegrityError(f"Verification of {tmp} failed.")
            if os.path.exists(path):
                shutil.copy2(path, path + ".bak")
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

        _fsync_directory(directory)
        self.dirty = False

    # ---------- open ----------

    @staticmethod
    def _parse(text: str) -> dict:
        try:
            doc = json.loads(text)
            name, _, major = doc["format"].partition("/")
        except (ValueError, KeyError, AttributeError) as e:
            raise VaultFormatError("Not a SeedWarden vault.") from e
        if name != FORMAT_NAME or major != str(FORMAT_MAJOR):
            raise VaultFormatError(f"Unsupported vault format {doc['format']}.")
        if doc["dek"]["cipher"] != CIPHER:
            raise VaultFormatError(f"Unsupported cipher {doc['dek']['cipher']}.")
        return doc

    @staticmethod
    def verify_integrity(text: str) -> bool:
        "Check the sha256 of the ciphertext without decrypting."
        doc = Vault._parse(text)
        ciphertext = Convert.base64str_to_bytes(doc["ciphertext"])
        return hashlib.sha256(ciphertext).hexdigest() == doc["sha256"]

    @staticmethod
    def logins_of(text: str) -> list[Login]:
        "List the logins known to this release, e.g. to ask the user how to unlock."
        doc = Vault._parse(text)
        return [x for x in (Login.deserialize(s) for s in doc["logins"]) if x is not None]

    @staticmethod
    def unlock_with_password(text: str, credentials: Pbkdf.Credentials) -> Vault:
        "Decrypt with password + PIN. Raises VaultDecryptionError if no password login matches."
        return Vault._unlock(text, PasswordLogin, lambda login, aad: login.unlock(credentials, aad))

    @staticmethod
    def unlock_with_shamir(text: str, secret: Scalar, share_set_id: str | None = None) -> Vault:
        "Decrypt with a secret recovered by the Interpolator. Optionally restrict to one share set."
        def unlock(login: ShamirLogin, aad: bytes) -> bytes:
            if share_set_id is not None and login.share_set_id != share_set_id:
                raise VaultDecryptionError("Different share set.")
            return login.unlock(secret, aad)
        return Vault._unlock(text, ShamirLogin, unlock)

    @staticmethod
    def open(path, credentials: Pbkdf.Credentials | None = None, secret: Scalar | None = None) -> Vault:
        "Read a vault file and unlock it with either credentials or a Shamir secret."
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if credentials is not None:
            return Vault.unlock_with_password(text, credentials)
        if secret is not None:
            return Vault.unlock_with_shamir(text, secret)
        raise ValueError("Either credentials or secret is required.")

    @staticmethod
    def _unlock(text: str, login_type: type, unlock) -> Vault:
        doc = Vault._parse(text)
        aad = _aad(doc["format"], doc["id"])
        logins: list[dict | Login] = []
        dek = None
        for serialized in doc["logins"]:
            login = Login.deserialize(serialized)
            logins.append(login if login is not None else serialized)
            if dek is None and isinstance(login, login_type):
                try:
                    dek = unlock(login, aad)
                except VaultDecryptionError:
                    pass
        if dek is None:
            raise VaultDecryptionError("No login could be unlocked with the given key.")

        nonce = Convert.base64str_to_bytes(doc["dek"]["nonce"])
        ciphertext = Convert.base64str_to_bytes(doc["ciphertext"])
        payload = json.loads(_decrypt(dek, nonce, ciphertext, aad))

        r = Vault()
        r.id = doc["id"]
        r.name = doc["name"]
        r.items = [Item.deserialize(i) for i in payload["items"]]
        r.logins = logins
        r.dirty = False
        r._dek = dek
        return r
