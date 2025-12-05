# NFTables - Elixir Interface to nftables

Elixir module for Linux nftables. NFTables provides both high-level helper functions for common firewall operations and flexible rule building with composable functions.

## Installation

Add `nftables` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:nftables, "~> 0.7.0"}
  ]
end
```

### Install dependencies
```bash
sudo apt-get update
sudo apt-get install -y \
  libnftables-dev \
  libcap-dev \
  zig
```

### Build
```bash
mix deps.get
mix compile
```

### Setting Capabilities

The port executable requires `CAP_NET_ADMIN` to communicate with the kernel firewall:

```bash
# After compilation
sudo setcap cap_net_admin=ep deps/nftables_port/priv/port_nftables
chmod 700 deps/nftables_port/priv/port_nftables
```

## Quickstart Guide

**Note** - before running examples on a remote machine, *be aware* you are able block your remote access.  You may want to start by experimenting in a VM or local machine.

### Build a Rule

```elixir
import NFTables.Expr
import NFTables.Expr.{Port, TCP, Verdict}

{:ok, pid} = NFTables.Port.start_link()

def ssh(rule \\ Expr.expr()), do: rule |> tcp() |> dport(22)

response =
  NFTables.add(table: "filter", family: :inet)
  |> NFTables.add(chain: "INPUT", hook: :input)
  |> NFTables.add(rule: ssh() |> accept())
  |> NFTables.submit(pid: pid)

IO.inspect(response)
```

## Features

- **High-Level APIs** - Simple functions for blocking IPs, managing sets, creating rules
- **Sysctl Management** - Read/Write access to network kernel parameters
- **Batch Operations** - Atomic multi-command execution
- **Query Operations** - List tables, chains, rules, sets, and elements
- **Elixir Port-based Architecture** - Fault isolation (crashes don't affect BEAM VM)
- **Security** - Port runs with minimal privileges (CAP_NET_ADMIN only)
- **Advanced Functionality** - Flowtables, Meters/Dynamic Sets, Raw Payload Matching Socket Matching & TPROXY, OSF (OS Fingerprinting)

### NFTables_Port 

The NFTables library depends on [NFTables.Port](https://hex.pm/packages/nftables_port) which is an elixir wrapper, and a program written in Zig which accepts json structures and sends them to Linux nftables using the libnftables (C library).  The Elixir module manages the Zig program as a Port.

```elixir
{:ok, pid} = NFTables.Port.start_link()

# Send JSON commands (for structured operations)
json_cmd = ~s({"nftables": [{"list": {"tables": {}}}]})
{:ok, json_response} = NFTables.Port.call(pid, json_cmd)
```

Visit the [NFTables.Port GitHub project](https://github.com/dcoai/nftables_port) for details.  Take some time to review the [Security](https://github.com/dcoai/nftables_port/blob/main/dev_docs/security.md) document found there.

### NFTables

NFTables.Port takes JSON requests and passes them on to the Linux nftables service.  The Elixir NFTables library is a set of tools to query and build rule sets which can be applied via NFTables.Port.

**Generate JSON using NFTables library**

```elixir
import NFTables.Expr
import NFTables.Expr.{Port, TCP, Verdict}

json =
  NFTables.add(table: "filter", family: :inet)
  |> NFTables.add(chain: "INPUT", hook: :input, policy: :drop)
  |> NFTables.add(rule: tcp() |> dport(22) |> accept())
  |> NFTables.to_json()
```

**Putting these together**

```elixir
import NFTables.Expr
import NFTables.Expr.{Port, TCP, Verdict}

{:ok, pid} = NFTables.Port.start_link()

NFTables.add(table: "filter", family: :inet)
|> NFTables.add(chain: "INPUT", hook: :input, policy: :drop)
|> NFTables.add(rule: tcp() |> dport(22) |> accept())
|> NFTables.submit(pid: pid)
```

Using this we can manage a local firewall from Elixir.

A couple possibilities:
- dynamic firewall which process events and updates firewall based on the events.
- distributed firewall on multiple nodes.

## System Requirements

- Linux kernel >= 3.18 (nf_tables support)
- Zig >= 0.11.0
- Elixir >= 1.14
- Erlang/OTP >= 24

### Required System Libraries

The following development packages must be installed:

- `libnftables-dev` >= 0.9.0 - Netfilter nftables userspace library (includes JSON API)
- `libcap-dev` >= 2.25 - POSIX capabilities library

### Installation on Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  libnftables-dev \
  libcap-dev \
  zig
```

### Verify Installation

Check that all dependencies are available:

```bash
# Check Zig
zig version

# Check nftables library
pkg-config --modversion libnftables
```

## Building

The Zig port is automatically compiled when you build the Mix project:

```bash
# Fetch dependencies
mix deps.get

# Compile (includes Zig compilation)
mix compile
```

The compiled `port_nftables` binary will be placed in `deps/nftables_port/priv/port_nftables`.

### Manual Build

To build just the Zig port:

```bash
cd deps/nftables_port/priv/port_nftables/native
zig build
```

The binary will be in `.../native/zig-out/bin/port_nftables`.

### Setting Capabilities

The port binary needs CAP_NET_ADMIN capability to manage firewall rules:

```bash
sudo setcap cap_net_admin=ep deps/nftables_port/priv/port_nftables
```

Verify:

```bash
getcap priv/port_nftables
# Should show: priv/port_nftables = cap_net_admin+ep
```

### Security considerations

Once port_nftables has CAP_NET_ADMIN capability set, it can be used to set network related parameters (like enable ip_forwarding) and
configure nftables (create/delete/update tables, chains, rules, etc...).  Considering this it would be wise to protect this executable.

the `nftables_port` executable should fail to run if it has any `rwx` permissions for `other`.  if this is the case you will see a message similar to:

```
    \\
    \\SECURITY ERROR: Executable has world permissions enabled!
    \\
    \\Current permissions: 755
    \\
    \\This executable has CAP_NET_ADMIN capability and MUST NOT be
    \\world-readable, world-writable, or world-executable.
    \\
    \\To fix, run:
    \\  chmod 750 {s}
    \\  # or
    \\  chmod 700 {s}
    \\
    \\The mode must end in 0 (no permissions for "other").
    \\Access should be controlled via user/group ownership.
    \\
    \\Refusing to start for security reasons.
    \\
```

minimally for production, do the following:

1. create a special user that the nftables_port will run as such as `exfw`.  Feel free to be more creative with the name.
2. `chown exfw nftables_port`  # make the executable belong to the new user `exfw`
3. `chmod 700 nftables_port`   # make the executable only runnable by the user `exfw`

## Useage Examples

see the project `examples` directory

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

See [LICENSE](LICENSE) for details.

## Resources

- [nftables documentation](https://wiki.nftables.org/)
- [libnftables JSON API](https://wiki.nftables.org/wiki-nftables/index.php/JSON_API)
- [nft man page](https://www.netfilter.org/projects/nftables/manpage.html)
- [Netfilter project](https://www.netfilter.org/)
