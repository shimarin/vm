# vm
A tool to run genpack'ed system image as a QEMU virtual machine

## Requirements

### Debian 12

- libiniparser-dev
- nlohmann-json3-dev
- libext2fs-dev
- libsmartcols-dev
- libsystemd-dev
- libxml++-2.6-dev

`socat` is required at runtime for `--sock-forward` and `--export-vsock`.

The system image is mounted read-only at runtime with `squashfuse`, so that package and
`fuse3` are needed as well: `apt install squashfuse fuse3` (Debian/Ubuntu),
`dnf install squashfuse` (Fedora), `pacman -S squashfuse` (Arch), `apk add squashfuse`
(Alpine). `vm` checks at startup that the host removes such a mount by itself when the
process that made it is killed (the `auto_unmount` mount option of `fusermount3`) and
refuses to start with an explanatory message when its fuse support is too old for that.

Each network interface without an explicit `macaddr` gets one derived from `MD5("<vmname>:<net_num>")`.
That MD5 is implemented in `netif.cpp` so that no crypto library is needed (the kernel's AF_ALG interface
requires privileges for md5 since Linux v7.3); `make test` checks it against known vectors. Changing the
algorithm would change every auto-assigned MAC address, so it is kept as MD5.

## The system image on the host

While a VM runs, its system image is mounted read-only at

    $XDG_RUNTIME_DIR/vm/<name>/ro

which is where the kernel and initramfs given to QEMU are read from, and where the rest of
the image can be looked at from the host (`ls`, `cat`, `findmnt`) while the guest is
running. The guest itself is given the image file as its disk, so the mount is host-side
only. A kernel that QEMU cannot boot as given (a gzipped one, or an EFI zboot image
wrapping one) is unpacked into `$XDG_RUNTIME_DIR/vm/<name>/boot/`, which is removed again
when the VM stops. `make test` checks that search and those unpackings against synthetic
fixtures, without mounting anything.

The mount belongs to the `vm run` process: it is released when the VM stops, and also when
that process is killed, in which case a mount that nonetheless survived is removed with a
warning on the next start. `.genpack/artifact` in the image is what names the VM when
`--name` is not given, so the image is read through a temporary mount at
`$XDG_RUNTIME_DIR/vm/.scratch-<pid>` first (a leading dot keeps it out of the run
directory's listings). That mount is also where `vm` confirms that killing the process
which made a mount really does remove it, and refuses to start a VM on a host that would
leave it behind.

## Talking to the guest over vsock

Each VM is given a `vhost-vsock` device with a CID derived from its name (the first four bytes of
`SHA256("<uid>:<vmname>")`, modulo 4294967293, plus 3), so it is stable across runs and can be looked
up with `vm cid <name>`. That makes the guest reachable without configuring any network interface, e.g.

    ssh root@vsock%<cid>            # via systemd-ssh-proxy

### --export-vsock: reach a guest service from the host

    vm run myvm --export-vsock 1158923571:mcp --export-vsock 80

binds `$XDG_RUNTIME_DIR/vm/myvm/vsock/mcp.sock` and `$XDG_RUNTIME_DIR/vm/myvm/vsock/80.sock` on the
host, and relays every connection accepted there to the guest's vsock port
(`<guest cid>:1158923571` / `<guest cid>:80`). The port is used literally and must be
1-4294967294; the optional `NAME` defaults to the port number and must match `[A-Za-z0-9._-]{1,64}`.

`vm show myvm` lists the sockets while the VM is running:

    "vsock_exports": {
      "mcp": "/run/user/1000/vm/myvm/vsock/mcp.sock",
      "80": "/run/user/1000/vm/myvm/vsock/80.sock"
    }

Nothing has to be installed in the guest besides a listening socket - systemd socket activation is
enough:

    # /etc/systemd/system/awl-mcp@.socket
    [Socket]
    ListenStream=vsock::%i
    Accept=yes

    # /etc/systemd/system/awl-mcp@.service
    [Service]
    # StandardInput=socket is required; without it fd 0 is /dev/null.
    # (systemd does not accept trailing comments, so keep it on its own line)
    StandardInput=socket
    StandardOutput=socket
    StandardError=journal
    ExecStart=/usr/local/bin/agent-workspace-linux mcp --headless

    systemctl start awl-mcp@1158923571.socket

Only `SOCK_STREAM` is supported. The guest kernel does not implement `SOCK_DGRAM` over vsock
(returning `ENODEV`), and socat has no `SEQPACKET` support, so neither can be bridged end to end.

The proxies are owned by the VM process: they are started before QEMU and terminated when the VM
stops; `vm run` fails before starting QEMU when socat is not installed (both options) or when an
exported socket cannot be bound (in `--detach` mode the reason is reported back as
`VM <name> failed to start: ...`); a proxy that dies while the VM runs is reported on stderr; and
sockets left behind by a VM that was killed are removed on the next start.

### --sock-forward: reach a host service from the guest

The reverse direction. For every path, a proxy listening on vsock port `<cid>+<n>` (`n` = 0, 1, ...
in the order the options are given) forwards accepted connections to a host Unix domain socket:

    vm run myvm --sock-forward /run/user/1000/aichannel.sock

    # in the guest
    socat - VSOCK-CONNECT:2:<cid>
