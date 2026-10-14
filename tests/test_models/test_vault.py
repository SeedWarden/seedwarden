import json

import pytest

from seedwarden.models.pbkdf import Pbkdf, PbkdfArgon2
from seedwarden.models.shamir import Interpolator, Polynomial, Scalar
from seedwarden.models.vault import (
    Field,
    Item,
    Vault,
    VaultDecryptionError,
    VaultError,
    VaultFormatError,
)


def fast_kdf() -> PbkdfArgon2:
    "Small Argon2 parameters to keep tests fast."
    kdf = PbkdfArgon2.create()
    kdf._time_cost = 1
    kdf._memory_cost = 8 * 1024
    return kdf


def make_vault(password="password", pin="") -> Vault:
    vault = Vault.create("test")
    vault.add_item(Item("wallet", [Field("seed", "seed-bip39", "abandon about"), Field("note", "text", "hi")]))
    vault.add_password_login(Pbkdf.Credentials(password, pin), fast_kdf())
    return vault


def test_roundtrip_password():
    text = make_vault().to_json()
    vault = Vault.unlock_with_password(text, Pbkdf.Credentials("password", ""))
    assert vault.name == "test"
    assert vault.items[0].name == "wallet"
    assert vault.items[0].fields[0].value == "abandon about"
    assert not vault.dirty


def test_roundtrip_pin():
    text = make_vault(pin="1234").to_json()
    vault = Vault.unlock_with_password(text, Pbkdf.Credentials("password", "1234"))
    assert vault.items[0].fields[1].value == "hi"


@pytest.mark.parametrize("password, pin", [("wrong", "1234"), ("password", "4321"), ("password", "")])
def test_wrong_credentials(password, pin):
    text = make_vault(pin="1234").to_json()
    with pytest.raises(VaultDecryptionError):
        Vault.unlock_with_password(text, Pbkdf.Credentials(password, pin))


def shamir_vault() -> tuple[str, Polynomial]:
    poly = Polynomial(3)
    vault = Vault.create("heirs")
    vault.add_item(Item("x", [Field("a", "text", "b")]))
    vault.add_shamir_login(poly.id, poly.secret)
    return vault.to_json(), poly


def test_shamir_unlock():
    text, poly = shamir_vault()
    interp = Interpolator(poly.get_share(Scalar(1)))
    interp.add_share(poly.get_share(Scalar(5)))
    interp.add_share(poly.get_share(Scalar(9)))
    vault = Vault.unlock_with_shamir(text, interp.secret, interp.id)
    assert vault.items[0].fields[0].value == "b"


def test_shamir_wrong_secret():
    text, _ = shamir_vault()
    with pytest.raises(VaultDecryptionError):
        Vault.unlock_with_shamir(text, Scalar.random())


def test_both_logins():
    poly = Polynomial(2)
    vault = make_vault()
    vault.add_shamir_login(poly.id, poly.secret)
    text = vault.to_json()
    assert Vault.unlock_with_password(text, Pbkdf.Credentials("password", "")).items[0].name == "wallet"
    assert Vault.unlock_with_shamir(text, poly.secret).items[0].name == "wallet"
    assert {type(x).__name__ for x in Vault.logins_of(text)} == {"PasswordLogin", "ShamirLogin"}


def tamper(text: str) -> str:
    doc = json.loads(text)
    ct = bytearray(__import__("base64").b64decode(doc["ciphertext"]))
    ct[0] ^= 1
    doc["ciphertext"] = __import__("base64").b64encode(bytes(ct)).decode()
    return json.dumps(doc)


def test_tamper_detected():
    text = make_vault().to_json()
    assert Vault.verify_integrity(text)
    bad = tamper(text)
    assert not Vault.verify_integrity(bad)
    with pytest.raises(VaultDecryptionError):
        Vault.unlock_with_password(bad, Pbkdf.Credentials("password", ""))


def test_swapping_id_fails():
    doc = json.loads(make_vault().to_json())
    doc["id"] = "00" * 16
    with pytest.raises(VaultDecryptionError):
        Vault.unlock_with_password(json.dumps(doc), Pbkdf.Credentials("password", ""))


def test_new_nonce_per_save():
    vault = make_vault()
    a, b = json.loads(vault.to_json()), json.loads(vault.to_json())
    assert a["dek"]["nonce"] != b["dek"]["nonce"]
    assert a["ciphertext"] != b["ciphertext"]


def test_dirty_flag():
    vault = make_vault()
    assert vault.dirty
    text = vault.to_json()
    assert not vault.dirty
    vault = Vault.unlock_with_password(text, Pbkdf.Credentials("password", ""))
    assert not vault.dirty
    vault.add_item(Item("new"))
    assert vault.dirty
    vault.to_json()
    vault.items[0].fields[0].value = "changed"
    vault.mark_dirty()
    assert vault.dirty


def test_unknown_field_type_roundtrips():
    vault = make_vault()
    vault.items[0].fields.append(Field("future", "java-card-thing", "42"))
    text = vault.to_json()
    field = Vault.unlock_with_password(text, Pbkdf.Credentials("password", "")).items[0].fields[2]
    assert (field.type, field.value) == ("java-card-thing", "42")


def test_unknown_login_type_skipped_and_kept():
    doc = json.loads(make_vault().to_json())
    doc["logins"].insert(0, {"type": "java-card", "foo": "bar"})
    vault = Vault.unlock_with_password(json.dumps(doc), Pbkdf.Credentials("password", ""))
    assert json.loads(vault.to_json())["logins"][0] == {"type": "java-card", "foo": "bar"}


def test_unknown_format_rejected():
    doc = json.loads(make_vault().to_json())
    doc["format"] = "seedwarden-vault/2"
    with pytest.raises(VaultFormatError):
        Vault.unlock_with_password(json.dumps(doc), Pbkdf.Credentials("password", ""))


def test_save_and_open(tmp_path):
    path = tmp_path / "v.swvault"
    make_vault().save(path)
    assert Vault.open(path, credentials=Pbkdf.Credentials("password", "")).name == "test"


def test_save_creates_bak_and_no_temp(tmp_path):
    path = tmp_path / "v.swvault"
    vault = make_vault()
    vault.save(path)
    first = path.read_text()
    vault.rename("second")
    vault.save(path)
    assert not vault.dirty
    assert (tmp_path / "v.swvault.bak").read_text() == first
    assert sorted(p.name for p in tmp_path.iterdir()) == ["v.swvault", "v.swvault.bak"]
    assert Vault.open(path, credentials=Pbkdf.Credentials("password", "")).name == "second"


def test_failed_save_keeps_original(tmp_path, monkeypatch):
    path = tmp_path / "v.swvault"
    vault = make_vault()
    vault.save(path)
    original = path.read_text()

    def fail(fd):
        raise OSError("simulated failure")

    monkeypatch.setattr("os.fsync", fail)
    vault.rename("changed")
    with pytest.raises(OSError):
        vault.save(path)
    assert path.read_text() == original
    assert vault.dirty
    assert [p.name for p in tmp_path.iterdir()] == ["v.swvault"]


def test_rotate_key(tmp_path):
    path = tmp_path / "v.swvault"
    vault = make_vault()
    vault.save(path)
    old = path.read_text()

    vault.rotate_key()
    assert vault.dirty and vault.list_logins() == []
    vault.add_password_login(Pbkdf.Credentials("new", ""), fast_kdf())
    vault.save(path)
    new = path.read_text()

    with pytest.raises(VaultDecryptionError):
        Vault.unlock_with_password(new, Pbkdf.Credentials("password", ""))
    assert Vault.unlock_with_password(new, Pbkdf.Credentials("new", "")).items[0].name == "wallet"
    # rotation does not affect old copies
    assert Vault.unlock_with_password(old, Pbkdf.Credentials("password", "")).items[0].name == "wallet"


def test_remove_login():
    poly = Polynomial(2)
    vault = make_vault()
    vault.add_shamir_login(poly.id, poly.secret)
    vault.to_json()
    vault.remove_login(0)
    assert vault.dirty
    assert [type(x).__name__ for x in vault.list_logins()] == ["ShamirLogin"]
    with pytest.raises(VaultDecryptionError):
        Vault.unlock_with_password(vault.to_json(), Pbkdf.Credentials("password", ""))


def test_save_without_logins_raises(tmp_path):
    vault = Vault.create("empty")
    with pytest.raises(VaultError):
        vault.to_json()
    with pytest.raises(VaultError):
        vault.save(tmp_path / "v.swvault")
    assert list(tmp_path.iterdir()) == []
