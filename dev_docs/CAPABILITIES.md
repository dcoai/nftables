# Linux Capabilities Setup for NFTex

## Overview

NFTex requires the `CAP_NET_ADMIN` Linux capability to perform netlink operations that communicate with the kernel's nftables subsystem. This document explains what capabilities are, why they're needed, and how to configure them for different deployment scenarios.

### What are Linux Capabilities?

Linux capabilities divide the privileges traditionally associated with root into distinct units. Instead of running as root (which grants all privileges), a process can be granted only the specific capabilities it needs. This follows the **principle of least privilege** and reduces security risks.

### Why NFTex Needs CAP_NET_ADMIN

The `CAP_NET_ADMIN` capability allows a process to:
- Open `NETLINK_NETFILTER` sockets
- Send nftables configuration commands to the kernel
- Receive responses from the kernel's nftables subsystem

Without this capability, operations like creating tables, chains, and rules will fail with `EPERM` (Operation not permitted).

### NFTex Security Model

When the NFTex port process starts, it:
1. **Drops all capabilities** except CAP_NET_ADMIN (principle of least privilege)
2. **Sets PR_SET_NO_NEW_PRIVS** to prevent gaining additional privileges
3. **Sets PR_SET_DUMPABLE=0** to prevent debugging/core dumps
4. **Drops CAP_NET_ADMIN on shutdown** for clean exit

This ensures the process runs with the absolute minimum privileges needed.

## Quick Start (Development)

The fastest way to get NFTex working with kernel operations:

```bash
# Compile the project
mix compile

# Set capabilities on the binary you're using
# For the recommended main port:
sudo setcap cap_net_admin+ep priv/port_nftables

# Or for other ports:
sudo setcap cap_net_admin+ep priv/port_nftables   # JSON strings only
sudo setcap cap_net_admin+ep priv/port_nftables    # Elixir terms only
sudo setcap cap_net_admin+ep priv/port_nftables     # Legacy libnftables

# Verify capabilities are set
getcap priv/port_nftables
# Should show: priv/port_nftables cap_net_admin=ep

# Run your application (no sudo needed!)
iex -S mix
```

**Note**: You'll need to re-run `setcap` after each recompilation, as the build process creates new binaries.

## Setup Methods

### Method 1: File Capabilities (Recommended for Production)

File capabilities are stored in the binary's extended attributes and are the most secure approach for production deployments.

#### Setup

```bash
# After compilation, set capabilities on the binary
sudo setcap cap_net_admin+ep /path/to/nftables/priv/port_nftables

# Verify it worked
getcap /path/to/nftables/priv/port_nftables
# Output: /path/to/nftables/priv/port_nftables cap_net_admin=ep
```

#### Capability Flags Explained

- `cap_net_admin` - The capability being granted
- `+ep` - The flags:
  - `e` (effective) - Capability is active immediately
  - `p` (permitted) - Process has permission to use this capability

#### Advantages

- ✅ Process doesn't need to run as root
- ✅ Most secure - only one specific capability granted
- ✅ Transparent to the application
- ✅ Standard Linux security mechanism

#### Disadvantages

- ❌ Must be reapplied after each build
- ❌ Requires sudo to set up
- ❌ Some filesystems don't support extended attributes (e.g., NFS, some Docker volumes)

#### Automation

You can automate this in your deployment scripts:

```bash
#!/bin/bash
# deploy.sh

# Build the release
MIX_ENV=prod mix release

# Set capabilities
sudo setcap cap_net_admin+ep _build/prod/rel/my_app/lib/nftables-0.1.0/priv/port_nftables

# Verify
getcap _build/prod/rel/my_app/lib/nftables-0.1.0/priv/port_nftables || {
    echo "Failed to set capabilities!"
    exit 1
}

echo "Capabilities set successfully"
```

### Method 2: Running with Sudo (Development/Testing)

For development and testing, you can run the entire Elixir application with sudo.

```bash
sudo iex -S mix
```

#### Advantages

- ✅ Simple - no capability configuration needed
- ✅ Works immediately
- ✅ Good for quick testing

#### Disadvantages

- ❌ Entire Elixir VM runs as root (security risk)
- ❌ All capabilities available (not least privilege)
- ❌ Not suitable for production
- ❌ Can cause file permission issues

### Method 3: Ambient Capabilities (Advanced)

Ambient capabilities are inherited by child processes. This allows the Elixir VM to pass CAP_NET_ADMIN to the port process.

```bash
# Set ambient capability and run
sudo capsh --caps="cap_net_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
           --keep=1 --user=$USER --addamb=cap_net_admin -- \
           -c "iex -S mix"
```

#### Advantages

- ✅ Doesn't require setcap on binary
- ✅ Runs as regular user (not root)
- ✅ Capability inherited by children

#### Disadvantages

- ❌ Complex command line
- ❌ Less portable
- ❌ Harder to automate

### Method 4: Running Without Capabilities (Limited Functionality)

NFTex can run without CAP_NET_ADMIN, but with reduced functionality.

```bash
# Just run normally
iex -S mix
```

#### What Works

- ✅ All resource allocation operations (table_alloc, chain_alloc, etc.)
- ✅ Setting attributes on resources
- ✅ Building batches
- ✅ Tests pass (they don't require kernel operations)

#### What Doesn't Work

- ❌ Opening netlink sockets
- ❌ Sending batches to the kernel
- ❌ Any actual kernel nftables operations

You'll see this warning in the logs:
```
warning: Failed to apply capabilities to process (continuing without CAP_NET_ADMIN)
warning: Note: Netlink operations requiring CAP_NET_ADMIN will fail
```

And operations will fail with:
```elixir
{:error, "Permission denied (EACCES)"}
```

## Verification

### Check if Capabilities are Set on Binary

```bash
getcap priv/port_nftables
```

**Expected output**:
```
priv/port_nftables cap_net_admin=ep
```

**If not set**:
```
# (empty output or "No capabilities")
```

### Check if Process Has the Capability

While NFTex is running:

```bash
# Find the process ID
ps aux | grep port_nftables

# Check its capabilities
grep Cap /proc/<PID>/status

# Or use getpcaps
getpcaps <PID>
```

### Test Netlink Operations

From IEx:

```elixir
{:ok, pid} = NFTex.start_link()

# Try to open a netlink socket
case NFTex.Kernel.Netlink.socket_open(pid) do
  {:ok, socket_id} ->
    IO.puts("✓ CAP_NET_ADMIN is working!")
    NFTex.Kernel.Netlink.socket_close(pid, socket_id)

  {:error, reason} ->
    IO.puts("✗ Failed: #{reason}")
    IO.puts("  (Likely missing CAP_NET_ADMIN)")
end
```

## Troubleshooting

### Error: "Operation not permitted (EPERM)"

**Symptom**: Netlink operations fail with EPERM error.

**Cause**: Process doesn't have CAP_NET_ADMIN.

**Solutions**:
1. Check if capabilities are set on binary: `getcap priv/port_nftables`
2. If not set, run: `sudo setcap cap_net_admin+ep priv/port_nftables`
3. If you just recompiled, capabilities were removed - set them again
4. Check filesystem supports extended attributes: `mount | grep "$(df priv/port_nftables | tail -1 | awk '{print $1}')"`

### Error: "Failed to set capabilities on process"

**Symptom**: Zig process logs error during startup.

**Cause**: Process tried to set capabilities it doesn't have.

**Solutions**:
1. Set file capabilities as shown above
2. Run with sudo (development only)
3. Or accept limited functionality without kernel operations

### Capabilities Lost After Recompilation

**Symptom**: It worked before, now fails after `mix compile`.

**Cause**: Compilation creates a new binary, losing file capabilities.

**Solution**: Re-run `setcap` after each build:

```bash
# Add to your workflow
mix compile && sudo setcap cap_net_admin+ep priv/port_nftables
```

### Capabilities Not Supported on Filesystem

**Symptom**: `setcap` fails or capabilities aren't persisted.

**Cause**: Filesystem doesn't support extended attributes (NFS, some Docker volumes, etc.).

**Solutions**:
1. Use a local filesystem that supports extended attributes (ext4, xfs, btrfs)
2. In Docker, use a bind mount from host filesystem
3. Use ambient capabilities method instead
4. Or run with sudo (not recommended for production)

### Running in Docker

**Special considerations for Docker**:

```dockerfile
# Dockerfile
FROM elixir:1.19

# Install libcap tools
RUN apt-get update && apt-get install -y libcap2-bin

# Copy and build your app
WORKDIR /app
COPY . .
RUN mix deps.get && mix compile

# Set capabilities (requires --cap-add=SETFCAP when running)
RUN setcap cap_net_admin+ep priv/port_nftables

# Run as non-root user
USER nobody

CMD ["mix", "run", "--no-halt"]
```

Run the container with:
```bash
docker run --cap-add=NET_ADMIN --cap-add=SETFCAP my-nftex-app
```

## Production Deployment

### Systemd Service

Example systemd unit file:

```ini
[Unit]
Description=NFTex Application
After=network.target

[Service]
Type=simple
User=nftex
Group=nftex
WorkingDirectory=/opt/nftex
Environment="MIX_ENV=prod"

# Set capabilities before starting
ExecStartPre=/usr/sbin/setcap cap_net_admin+ep /opt/nftex/priv/port_nftables

# Start the application
ExecStart=/opt/nftex/bin/my_app start

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nftex

[Install]
WantedBy=multi-user.target
```

### Elixir Release

When building an Elixir release:

```bash
# Build release
MIX_ENV=prod mix release

# Set capabilities on the port binary in the release
sudo setcap cap_net_admin+ep _build/prod/rel/my_app/lib/nftables-0.1.0/priv/port_nftables

# The release can now run as a regular user
_build/prod/rel/my_app/bin/my_app start
```

### Security Checklist

- [ ] Use file capabilities, not sudo
- [ ] Run application as non-root user
- [ ] Set only CAP_NET_ADMIN, no other capabilities
- [ ] Use systemd security features (NoNewPrivileges, PrivateTmp, etc.)
- [ ] Monitor logs for capability warnings
- [ ] Keep libcap and kernel up to date
- [ ] Regularly audit capability grants

## Additional Resources

- [Linux Capabilities Man Page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [setcap Man Page](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [Linux Capability Overview](https://www.kernel.org/doc/html/latest/security/capabilities.html)
- [Systemd Security Hardening](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)

## Summary

**For Development**:
```bash
mix compile
sudo setcap cap_net_admin+ep priv/port_nftables
iex -S mix
```

**For Production**:
- Build release
- Set file capabilities on `priv/port_nftables`
- Run as non-root user with systemd
- Monitor for permission errors

**Without Capabilities**:
- Application runs but kernel operations fail
- Useful for testing non-kernel functionality
- Tests will pass
