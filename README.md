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

# If zeroconf was enabled, you can skip the hostname argument
second-machine> doubleidle client

# Otherwise connect to a specific client:
second-machine> doubleidle client main-machine.local
```

# License

GPLv3 or later
