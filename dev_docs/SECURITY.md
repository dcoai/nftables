# Security Policy

## Overview

NFTex provides Elixir bindings to Linux nftables via libnftables. As firewall management is a security-critical operation, this document outlines security considerations, best practices, and the vulnerability disclosure policy.

## Privilege Requirements

### CAP_NET_ADMIN Capability

NFTex requires the `CAP_NET_ADMIN` Linux capability to modify firewall rules. This is enforced at the native port level.

**Required Setup:**
```bash
# For the recommended main port:
sudo setcap cap_net_admin=ep priv/port_nftables

# Or for other ports:
sudo setcap cap_net_admin=ep priv/port_nftables
sudo setcap cap_net_admin=ep priv/port_nftables
```

**Security Implications:**
- `CAP_NET_ADMIN` allows modification of network configuration
- This is a powerful capability that should be carefully controlled
- Only grant this capability to trusted executables
- The port binary includes security checks for file permissions

### File Permissions

The port binary **MUST NOT** have world-readable, world-writable, or world-executable permissions when `CAP_NET_ADMIN` is set.

**Enforced Permissions:**
- Owner: read + execute (5)
- Group: read + execute (5) or no access (0)
- Other: **no access (0)**

**Valid:** `750` (rwxr-x---) or `700` (rwx------)
**Invalid:** `755` (rwxr-xr-x) - will be rejected

The native port will refuse to start if invalid permissions are detected with capabilities set.

## Security Best Practices

### 1. Input Validation

#### Table, Chain, and Set Names
- Always validate names before passing to NFTex
- Maximum length: typically 256 characters
- Avoid special characters that could cause issues
- Do not construct names from untrusted user input directly

```elixir
# BAD: Direct user input
user_table = params["table_name"]
Table.create(pid, %{name: user_table, family: :inet})

# GOOD: Validate and sanitize
defp validate_table_name(name) when is_binary(name) do
  if String.length(name) > 0 and String.length(name) <= 64 and
     String.match?(name, ~r/^[a-z][a-z0-9_]*$/) do
    {:ok, name}
  else
    {:error, :invalid_name}
  end
end
```

#### IP Addresses
- Use string format (`"192.168.1.100"`)
- Validate IP address format before use
- Use `:inet.parse_address/1` for validation

```elixir
# GOOD: Validate IP before use
case :inet.parse_address(String.to_charlist(user_ip)) do
  {:ok, {a, b, c, d}} ->
    ip_string = "#{a}.#{b}.#{c}.#{d}"
    Rule.block_ip(pid, "filter", "INPUT", ip_string)
  {:error, :einval} ->
    {:error, :invalid_ip}
end
```

#### Port Numbers
- Validate range: 0-65535
- RuleBuilder includes guard clauses for this
- Validate before passing to low-level functions

```elixir
# GOOD: RuleBuilder validates automatically
RuleBuilder.match_dest_port(builder, port)  # Guards ensure 0 <= port <= 65535

# If using low-level API, validate:
defp validate_port(port) when port >= 0 and port <= 65535, do: {:ok, port}
defp validate_port(_), do: {:error, :invalid_port}
```

### 2. Log Prefix Sanitization

Log prefixes are written to kernel logs. Sanitize them to prevent:
- Log injection
- Excessive log size
- Special characters causing issues

```elixir
# GOOD: Sanitize log prefixes
defp sanitize_log_prefix(prefix) do
  prefix
  |> String.slice(0, 127)  # Max length
  |> String.replace(~r/[^\x20-\x7E]/, "")  # Only printable ASCII
end

log_prefix = sanitize_log_prefix(user_input)
RuleBuilder.log(builder, log_prefix)
```

### 3. Rate Limiting

Always apply rate limiting to services exposed to the internet:

```elixir
# GOOD: Rate-limited SSH
Policy.allow_ssh(pid, rate_limit: 10)  # 10 connections per minute

# GOOD: Rate-limited web service
RuleBuilder.new(pid, "filter", "INPUT")
|> RuleBuilder.match_dest_port(80)
|> RuleBuilder.rate_limit(100, :second, burst: 200)
|> RuleBuilder.accept()
|> RuleBuilder.commit()
```

### 4. Default Deny Policy

Always use a default DROP policy for security:

```elixir
# GOOD: Default DROP, explicit ACCEPT
Chain.create(pid, %{
  table: "filter",
  name: "INPUT",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop  # Default deny
})

# Then add explicit ACCEPT rules
Policy.accept_loopback(pid)
Policy.accept_established(pid)
Policy.allow_ssh(pid, rate_limit: 10)
```

### 5. Established Connection Handling

Always accept established/related connections:

```elixir
# GOOD: Accept established connections early
Policy.accept_established(pid)

# Or with RuleBuilder:
RuleBuilder.new(pid, "filter", "INPUT")
|> RuleBuilder.match_ct_state([:established, :related])
|> RuleBuilder.accept()
|> RuleBuilder.commit()
```

### 6. Drop Invalid Packets

Drop packets with invalid connection tracking state:

```elixir
# GOOD: Drop invalid packets early
Policy.drop_invalid(pid)
```

## Common Security Pitfalls

### ❌ Don't: Unrestricted Rule Creation from User Input

```elixir
# BAD: Direct user input to firewall
def block_user_ip(pid, user_ip) do
  Rule.block_ip(pid, "filter", "INPUT", user_ip)
end
```

### ✅ Do: Validate and Sanitize All Input

```elixir
# GOOD: Validate before use
def block_user_ip(pid, user_ip) do
  with {:ok, validated_ip} <- validate_ip_address(user_ip),
       :ok <- check_not_local_ip(validated_ip),
       :ok <- rate_limit_rule_creation() do
    Rule.block_ip(pid, "filter", "INPUT", validated_ip)
  end
end
```

### ❌ Don't: Run NFTex as Root

```elixir
# BAD: Running as root unnecessarily
# Run with sudo when only CAP_NET_ADMIN is needed
```

### ✅ Do: Use Capabilities, Not Root

```bash
# GOOD: Set capability, run as unprivileged user
sudo setcap cap_net_admin=ep priv/port_nftables
chmod 750 priv/port_nftables
# Now run as regular user
```

### ❌ Don't: Allow Arbitrary Table/Chain Names

```elixir
# BAD: User controls table name directly
def create_user_table(pid, table_name) do
  Table.create(pid, %{name: table_name, family: :inet})
end
```

### ✅ Do: Use Predefined Tables/Chains

```elixir
# GOOD: Whitelist allowed tables
@allowed_tables ["filter", "nat", "mangle"]

def create_user_table(pid, table_name) when table_name in @allowed_tables do
  Table.create(pid, %{name: table_name, family: :inet})
end
```

### ❌ Don't: Construct Rules from Untrusted Sources

```elixir
# BAD: Rule template from user
def create_custom_rule(pid, user_rule_config) do
  # This is dangerous!
end
```

### ✅ Do: Use Predefined Rule Templates

```elixir
# GOOD: Predefined templates only
def apply_rule_template(pid, :block_ip, ip) do
  with {:ok, validated_ip} <- validate_ip(ip) do
    Rule.block_ip(pid, "filter", "INPUT", validated_ip)
  end
end
```

## Secure Configuration Examples

### Basic Secure Server

```elixir
# Secure baseline firewall
{:ok, pid} = NFTex.start_link()

# One-line secure setup
:ok = Policy.setup_basic_firewall(pid,
  allow_services: [:ssh],
  ssh_rate_limit: 10  # Prevent brute force
)

# Add custom service with rate limit
RuleBuilder.new(pid, "filter", "INPUT")
|> RuleBuilder.match_dest_port(8080)
|> RuleBuilder.rate_limit(100, :second, burst: 50)
|> RuleBuilder.log("API-ACCESS: ")
|> RuleBuilder.accept()
|> RuleBuilder.commit()
```

### Hardened Web Server

```elixir
{:ok, pid} = NFTex.start_link()

# Default deny
:ok = Policy.setup_basic_firewall(pid,
  allow_services: []  # No services by default
)

# HTTP with strict rate limiting
:ok = Policy.allow_http(pid, rate_limit: 100)

# HTTPS with rate limiting
:ok = Policy.allow_https(pid, rate_limit: 100)

# SSH with very strict rate limiting
:ok = Policy.allow_ssh(pid, rate_limit: 5, log: true)

# Drop and log port scans (common scanner ports)
for port <- [23, 135, 139, 445, 3389] do
  RuleBuilder.new(pid, "filter", "INPUT")
  |> RuleBuilder.match_dest_port(port)
  |> RuleBuilder.log("PORTSCAN-#{port}: ")
  |> RuleBuilder.drop()
  |> RuleBuilder.commit()
end
```

## Vulnerability Disclosure

### Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via:
- Email: [security contact email]
- GitHub Security Advisories: [repository security tab]

Include:
- Type of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Fix Timeline:** Depends on severity
  - Critical: 1-7 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: 4-8 weeks

### Disclosure Policy

- We will acknowledge your report
- We will investigate and work on a fix
- We will keep you informed of progress
- We will credit you in the security advisory (if desired)
- We will coordinate disclosure timing with you

## Security Checklist

When deploying NFTex in production:

- [ ] CAP_NET_ADMIN capability set correctly
- [ ] Port binary has secure permissions (750 or 700)
- [ ] Running as non-root user
- [ ] Default DROP policy enabled
- [ ] Loopback traffic accepted
- [ ] Established/related connections accepted
- [ ] Invalid packets dropped
- [ ] All services have rate limiting
- [ ] Logging enabled for security events
- [ ] Input validation on all user-provided data
- [ ] Table/chain names from whitelist only
- [ ] IP addresses validated before use
- [ ] Port numbers validated
- [ ] Log prefixes sanitized
- [ ] No direct user input to firewall rules
- [ ] Regular security updates applied
- [ ] Monitoring and alerting configured

## Security Features

### Built-In Security

NFTex includes several built-in security features:

1. **Permission Validation**
   - Port binary checks file permissions before starting
   - Refuses to run with insecure permissions when capabilities are set

2. **Capability Enforcement**
   - Requires CAP_NET_ADMIN
   - Will not run without proper capabilities

3. **Port Isolation**
   - Crashes in native port don't affect BEAM VM
   - Fault isolation prevents VM corruption

4. **Resource Cleanup**
   - Automatic cleanup of native resources
   - Prevents resource leaks

5. **Type Safety**
   - Elixir type specs throughout
   - Guard clauses for parameter validation

## Further Reading

- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [nftables Wiki](https://wiki.nftables.org/)
- [netfilter Documentation](https://www.netfilter.org/documentation/)
- [Best Practices for Firewall Rules](https://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO.html)

## Version History

- **v0.3.0:** Added comprehensive security documentation
- **v0.2.0:** Added permission validation
- **v0.1.0:** Initial release with CAP_NET_ADMIN requirement

## Contact

For security concerns: [security contact]
For general issues: GitHub Issues

---

**Last Updated:** November 5, 2025
