# doubleidle

A simple utility that keeps a remote host awake while another host is being used.

Imagine you have two hosts, one is your main desktop you work on and another machine
that you need to periodically look at but not typically interact with. For
example, you may have a reference manual open on that machine.

Because you don't interact with the second machine, it will eventually lock the
screen, requiring you to type the password. Disabling screen lock is not
an option, because security.

`doubleidle` is the solution. You run the server on the main machine and
connect to it from the other machine(s). The server will periodically update
the clients with the idle time on the server.

While the server is active (idle time below threshold), the client prevents
the machine from going to sleep or engaging the screensaver via the
[Inhibit portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Inhibit.html).

Once the server's idle time goes past the (client-specific) threshold, the
inhibit lock is dropped and the client can fall asleep, or lock the screen, or
whatever it thinks is appropriate.

# Building

This is a typical Rust project, see the Rust documentation for details on
cargo.

We recommend to build with zeroconf support so server detection is automatic.

```
$ cargo build --features zeroconf
$ cargo install
```

And then run it on the machines as server or client:

```console
main-machine> doubleidle server
[10:37 INFO ] Starting server on port 24999 with interval 10s
[10:37 INFO ] Generated new fingerprint and saved to "/home/user/.config/doubleidle/server-fingerprint.txt"
[10:37 INFO ] Server fingerprint: 9e754f83-712f-4cce-8ce5-ab0eb7e660e9
[10:37 INFO ] Server listening on port 24999
[...]

# If zeroconf was enabled, you can skip the hostname argument
second-machine> doubleidle client --allow=9e754f83-712f-4cce-8ce5-ab0eb7e660e9

# Otherwise connect to a specific client:
second-machine> doubleidle client --allow=9e754f83-712f-4cce-8ce5-ab0eb7e660e9 main-machine.local
```

The server's fingerprint is a UUID generated on first startup and then re-used,
you can replace it if need be (and it doesn't need to be a UUID either). The
client will only connect to servers with an allowed fingerprint - the allowlist
is stored in `$XDG_CONFIG_HOME/doubleidle/allowed-servers.txt` with one entry
per line.  If `--allow` is given to the client on the commandline, the
`allowed-servers.txt` file is ignored.

# License

GPLv3 or later
