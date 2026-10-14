# SeedWarden vault format, version 1 (draft)

A vault is one UTF-8 JSON file (`*.swvault`) holding an encrypted list of items.
Other files (recovery README, Bitwarden export) are stored as plain files on the card and are not part of this spec.

## Design goals

- Decryptable on almost any platform: Python on the device, and a single offline HTML page using only WebCrypto plus one bundled Argon2 implementation.
- Several independent logins (password+PIN, Shamir, future methods) can each unlock the same vault.
- The integrity of a vault can be checked without decrypting it (for example, a friend's backup).
- A payload or wrapped key can't be moved to another vault without detection.

## Structure

```json
{
  "format": "seedwarden-vault/1",
  "id": "<16 random bytes, hex>",
  "name": "Martin + heirs",
  "dek": {
    "cipher": "AES-256-GCM",
    "nonce": "<12 bytes, base64>"
  },
  "logins": [
    {
      "type": "password",
      "kdf": { "algo": "Argon2", "type": 2, "version": 19, "salt": "...",
               "time-cost": 3, "memory-cost": 65536, "parallelism": 1, "hash-len": 32 },
      "wrap": { "cipher": "AES-256-GCM", "nonce": "...", "wrapped-key": "..." }
    },
    {
      "type": "shamir",
      "share-set-id": "a1b2c3d4e5f60718-3",
      "kdf": { "algo": "HKDF-SHA256", "salt": "..." },
      "wrap": { "cipher": "AES-256-GCM", "nonce": "...", "wrapped-key": "..." }
    }
  ],
  "ciphertext": "<base64, includes 16-byte GCM tag>",
  "sha256": "<hex of decoded ciphertext bytes>"
}
```

## Keys

- **DEK** (data encryption key): 32 random bytes per vault. It encrypts the payload.
- **KEK** (key encryption key): derived per login. It encrypts (wraps) the DEK.
  - `password`: `Argon2id(HMAC-SHA256(key="seedwarden"+PIN, msg=password), salt, params)`. The PIN may be empty.
  - `shamir`: the recovered secret as 32 bytes, big-endian, run through `HKDF-SHA256(salt, info="seedwarden-shamir-kek")`.
- Each login wraps the DEK with AES-256-GCM, using its own random 12-byte nonce. A wrong password or wrong shares fails at the GCM tag of that login.

## Associated data

Both the payload encryption and every DEK wrap use the same GCM associated data (AAD):

- `AAD` = UTF-8 bytes of `format + "\n" + id`, e.g. `"seedwarden-vault/1\na1b2..."`.
- Payload encryption: AES-256-GCM(DEK, `dek.nonce`, plaintext, AAD).
- DEK wrap: AES-256-GCM(KEK, `wrap.nonce`, DEK, AAD).

No canonical JSON is needed, so independent implementations can't disagree on it.
This prevents moving a payload or a wrapped key into a vault with a different `id` or format.
Other header fields (name, KDF parameters, logins) are not authenticated: tampering with them can only make a vault fail to open, which an attacker with card access could achieve by deleting it anyway.

## Rules

- Never reuse a nonce with the same key. Every save generates a new `dek.nonce`. The DEK may stay the same so logins don't need re-wrapping.
- `sha256` is a convenience check for corruption and sync only. Security comes from the GCM tags.
- Readers must reject an unknown `format` major version, and unknown login types are skipped.

## Saving

Saves are atomic, so a power loss or a pulled SD card never leaves a half-written vault:

1. Write the new vault to a temp file in the same directory, flush and fsync it.
2. Re-read the temp file and verify that it parses and that `sha256` matches.
3. Copy the previous file, if any, to `<name>.bak`, replacing an older `.bak`.
4. Rename the temp file over the target (atomic) and fsync the directory where the platform supports it.

The `.bak` is never deleted automatically. It is a full vault and opens with the logins it had at that time.
A vault without any login is never written, as it could not be opened again.

## Key rotation

Removing a login does not revoke it: its KEK still unwraps the unchanged DEK, e.g. from a copy that still contains the login.
To revoke, rotate the key:

1. Generate a new random DEK. All existing logins wrap the old DEK and are dropped.
2. Add the logins that should remain (password, new Shamir share set, ...).
3. Save. The payload is encrypted with the new DEK.

Caveat: rotation only protects future versions of the vault.
Old copies, backups (including `.bak` files and copies on a friend's card) and anyone who already decrypted the vault keep access to that old content.
Delete the old copies and change the secrets themselves if that matters.

## Plaintext payload

```json
{
  "items": [
    {
      "name": "Bitcoin cold wallet",
      "fields": [
        { "name": "seed", "type": "seed-bip39", "value": "abandon abandon ... about" },
        { "name": "passphrase", "type": "hidden", "value": "..." },
        { "name": "notes", "type": "text", "value": "..." }
      ]
    }
  ]
}
```

Field types: `text`, `hidden`, `numeric`, `boolean`, `seed-bip39`. Unknown types are shown as `text`.
Values are always strings (`"true"`/`"false"` for booleans) so unknown types survive a round trip.
