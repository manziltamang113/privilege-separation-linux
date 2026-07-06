# privilege-separation-linux

A minimal demonstration of **privilege separation** on Linux using a
root-owned backend process and an unprivileged frontend process,
communicating over a Unix domain socket.

## Why privilege separation?

A common security mistake is running an entire authentication service
as `root` for its whole lifetime. If that process is compromised (via
a buffer overflow, injection, or any other bug), the attacker inherits
full root access.

Privilege separation limits the blast radius: only the small piece of
code that *needs* root (reading a protected credentials file) runs as
root, and only for as long as it needs to. Everything else — parsing
user input, handling the network connection lifecycle — runs as an
unprivileged process, or is dropped to an unprivileged UID as soon as
the privileged work is done.

## How it works

```
┌────────────┐        Unix domain socket        ┌───────────────┐
│  frontend  │ ───────  "user:pass"  ─────────▶ │    backend    │
│ (unpriv.)  │ ◀──────  "OK" / "FAIL" ────────  │ (starts root) │
└────────────┘                                   └───────────────┘
```

1. **`backend`** starts as root, creates a Unix domain socket at
   `/tmp/auth.sock`, and listens for a connection.
2. **`frontend`** (run as a normal user) connects, prompts for a
   username and password, and sends `username:password` over the
   socket.
3. **`backend`** reads the request, and — while still root — opens
   `secrets.txt` (a root-only credentials file) to check the
   username/password against it.
4. Immediately after checking credentials, **`backend`** calls
   `setresuid()` to permanently drop from root to the `nobody` user.
   It then verifies the drop by trying to reopen `secrets.txt` and
   confirming the attempt fails.
5. **`backend`** sends `OK` or `FAIL` back to the frontend and exits —
   as a non-root user, having never been root again since the drop.

## Files

| File | Description |
|------|-------------|
| `backend.c` | Privileged process: socket setup, credential parsing, authentication against `secrets.txt`, and privilege drop via `setresuid()`. |
| `frontend.c` | Unprivileged client: prompts for credentials, sends them to the backend, and prints the authentication result. |

## Building

```bash
gcc -o backend backend.c
gcc -o frontend frontend.c
```

## Running

`secrets.txt` should contain `username:password` pairs, one per line,
and should be readable only by root:

```bash
echo "alice:hunter2" | sudo tee secrets.txt
sudo chmod 600 secrets.txt
```

Start the backend as root (in one terminal):

```bash
sudo ./backend
```

Run the frontend as a regular user (in another terminal):

```bash
./frontend
```

## Security notes

- Credentials are zeroed out in memory (`explicit_bzero`) as soon as
  they're no longer needed, to reduce exposure in memory dumps.
- The backend re-checks that `secrets.txt` is truly inaccessible
  after dropping privileges, as a runtime sanity check that the drop
  actually worked.
- This is a learning/demo project, not production-hardened code —
  `secrets.txt` stores passwords in plaintext, and there's no rate
  limiting, logging, or protection against socket path hijacking. Use
  it to understand the mechanics of privilege separation, not as a
  real authentication service.

## License

No license specified — all rights reserved by the author.
