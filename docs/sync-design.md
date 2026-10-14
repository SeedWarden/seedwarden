# Card sync design (draft, not implemented)

## Goal

Two or more SD cards back each other up. Example: Alice keeps her files in `Alice/`, Bob in `Bob/`, and both cards should hold both folders.
A sync makes two cards identical. There is no master card, and any number of cards can take part (I sync with whichever friend I visit).
As long as each file is only ever modified on one card, sync just rolls changes forward. When a file was changed independently on two cards, sync detects the conflict (a fork) and asks the user.

Older versions are not kept, so there is no rollback.

## Convention

- Files and folders whose name starts with `.` are never synced.
- Each folder has a `.backups/` subfolder with one sidecar file per synced file: `.backups/<filename>`.
- Adding, editing, or deleting files between syncs never touches sidecars. Only sync writes them.

## Sidecar file

Plain text, one entry per line:

```
<tip-id> <sha256>      # line 1: current version (file exists)
<tip-id>               # line 1: current version is a deletion (no hash)
<id>                   # lines 2+: earlier version ids, an unordered set
```

- `id` is 16 random bytes, hex encoded. One id per version.
- `sha256` is the hash of the file content as last synced.
- History is a set of ids, not a chain. Without stored old versions, a hash chain would add nothing.

## Local state of a file (per card, before sync)

| File      | Sidecar                | State                |
|-----------|------------------------|----------------------|
| present   | none                   | new                  |
| present   | tip hash matches       | unchanged            |
| present   | tip hash differs       | changed              |
| missing   | tip has a hash         | deleted              |
| missing   | tip is a deletion      | unchanged (deleted)  |

**Minting:** at the start of a sync, every *new*, *changed*, or *deleted* file gets a new tip id. The old tip id (if any) moves into the history set, and the sidecar is rewritten. After this step, every file's state is fully described by its sidecar.

## Comparing two cards (per file path)

Let `A` and `B` be the sidecars on the two cards (either may be missing).

1. Only one side has it: copy file and sidecar to the other card.
2. Same tip id: nothing to do.
3. `A.tip` is in `B.history`: B is newer. Copy B's file (or delete A's) and B's sidecar to A.
4. `B.tip` is in `A.history`: the reverse.
5. Otherwise: **fork**. Exception: if both tips have the same hash (same content created or edited independently), or both tips are deletions (deleted independently on both cards), merge silently. Keep either tip, add the other tip and both histories to the history set, and write the result to both cards.

## Forks

Shown to the user with both versions' metadata (size, modification time, deleted or not). The user picks the winner.
The winner gets a new tip id, its history becomes the union of both histories plus both old tips, and the result is written to both cards.
Typical forks:

- The same new file name was created on both cards.
- A file was edited on both cards since the last common sync.
- A file was deleted on one card and edited on the other.

## Notes

- Deletion sidecars are kept forever so deletions keep propagating to cards that haven't synced yet. They are tiny, so cleanup isn't worth the complexity.
- A rename shows up as a delete plus a new file. That's acceptable.
- Copies to the other card use the same atomic write (temp file, fsync, rename) as vault saves. The sidecar is written after the file.
- Encrypted vaults sync as opaque files. A card never needs to decrypt someone else's vault.
- The vault's `sha256` field could double as the content hash, but using the file hash keeps sync independent of file type.
