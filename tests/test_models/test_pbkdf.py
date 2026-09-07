from seedwarden.models import Pbkdf


def test_different_salt():
    creds = Pbkdf.Credentials("password", "1234")

    kdf = Pbkdf.create()
    hash1 = kdf.digest(creds)

    kdf = Pbkdf.create()
    hash2 = kdf.digest(creds)

    assert hash1 != hash2


def test_success():
    kdf = Pbkdf.create()
    hash1 = kdf.digest(Pbkdf.Credentials("password", "1234"))

    kdf = Pbkdf.deserialize(kdf.serialize())
    hash2 = kdf.digest(Pbkdf.Credentials("password", "1234"))

    assert hash1 == hash2


def test_needs_password():
    kdf = Pbkdf.create()
    hash = kdf.digest(Pbkdf.Credentials("password", "1234"))

    kdf = Pbkdf.deserialize(kdf.serialize())
    hash1 = kdf.digest(Pbkdf.Credentials("passwor", "1234"))
    assert hash1 != hash

    hash1 = kdf.digest(Pbkdf.Credentials("password", "123"))
    assert hash1 != hash
