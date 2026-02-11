# doubleidle

A simple utility that keeps a remote host awake while another host is being used.

Imagine you have two hosts, one is your main desktop you work on and another machine
that you need to periodically look at but not typically interact with. For
example, you may have a reference manual open on that machine.

Because you don't interact with the second machine, it will eventually lock the
screen, requiring you to type the password. Disabling the screen locker is not
ideal, because security. 

`doubleidle` is the solution. You run the server on the main machine and
connect to it from the other machine(s). The server will periodically update
the clients with the idle time on the server.

And before the client goes idle, it will check the server's idletime. And if
the server says you've been a busy bee, the client sends a single motion event
via the [RemoteDesktop portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)
- enough to reset the idletime and prevent the machine from going to sleep.

If you stop using the server the client will *not* do this and let the machine
fall asleep, or lock the screen, or whatever it thinks is appropriate.

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
