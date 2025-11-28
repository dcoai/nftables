#!/usr/bin/env elixir

# Firewall Rules Example
#
# This example demonstrates how to use NFTex to create firewall rules
# dynamically for blocking and allowing IP addresses.
#
# **Format**: This example uses JSON format for communication with libnftables.
#
# Requirements:
# - The NFTex port binary must have CAP_NET_ADMIN capability
# - Run: sudo setcap cap_net_admin=ep priv/port_nftables
# - A base chain must exist: nft add chain filter INPUT '{ type filter hook input priority 0; }'
#
# Usage:
#   mix run examples/03_firewall_rules.exs

# Start NFTex (JSON-based port)
{:ok, pid} = NFTex.start_link()
IO.puts("✓ NFTex started (JSON-based port)\n")

table = "filter"
chain = "INPUT"

IO.puts("===== DYNAMIC FIREWALL RULES EXAMPLE =====\n")

# Scenario: Block malicious IPs, allow trusted IPs (now using string format)

malicious_ips = [
  "192.168.1.111",
  "10.0.0.99",
  "172.16.5.50"
]

trusted_ips = [
  "192.168.1.10",  # Admin workstation
  "192.168.1.20"   # Monitoring server
]

## STEP 1: Block malicious IPs
IO.puts("Step 1: Blocking malicious IPs...")

for ip_string <- malicious_ips do
  case NFTex.Rule.block_ip(pid, table, chain, ip_string) do
    :ok ->
      IO.puts("  ✓ Blocked #{ip_string}")
    {:error, reason} ->
      IO.puts("  ✗ Failed to block #{ip_string}: #{reason}")
  end
end

IO.puts("\nMalicious IPs are now blocked. Packets from these addresses will be dropped.\n")

## STEP 2: Accept trusted IPs (higher priority - add first)
IO.puts("Step 2: Creating accept rules for trusted IPs...")

for ip_string <- trusted_ips do
  case NFTex.Rule.accept_ip(pid, table, chain, ip_string) do
    :ok ->
      IO.puts("  ✓ Accepted #{ip_string}")
    {:error, reason} ->
      IO.puts("  ✗ Failed to accept #{ip_string}: #{reason}")
  end
end

IO.puts("\nTrusted IPs are now explicitly allowed.\n")

## STEP 3: List all rules in the chain
IO.puts("Step 3: Listing current firewall rules...")

case NFTex.Rule.list(pid, table, chain, family: :inet) do
  {:ok, rules} ->
    IO.puts("✓ Total rules in #{table}/#{chain}: #{length(rules)}")
    IO.puts("\nLast 5 rules added:")
    rules
    |> Enum.sort_by(& &1.handle, :desc)
    |> Enum.take(5)
    |> Enum.each(fn rule ->
      IO.puts("  - Handle: #{rule.handle}, Table: #{rule.table}, Chain: #{rule.chain}")
    end)

  {:error, reason} ->
    IO.puts("✗ Failed to list rules: #{reason}")
end

IO.puts("\n" <> String.duplicate("=", 60))
IO.puts("✓✓✓ FIREWALL RULES EXAMPLE COMPLETE ✓✓✓")
IO.puts(String.duplicate("=", 60))
IO.puts("""

Summary:
  ✓ Blocked #{length(malicious_ips)} malicious IP addresses
  ✓ Allowed #{length(trusted_ips)} trusted IP addresses
  ✓ Rules are now active in the kernel

Key Features Demonstrated:
  1. NFTex.Rule.block_ip/4  - Simple API for blocking IPs
  2. NFTex.Rule.accept_ip/4 - Simple API for allowing IPs
  3. NFTex.Rule.list/4      - Query existing rules
  4. Automatic counter addition for traffic monitoring
  5. Dynamic rule creation without restart

Real-World Use Cases:
  - Intrusion detection system (IDS) integration
  - Rate limiting abusive clients
  - Geographic IP blocking
  - Dynamic allowlist/blocklist management
  - Security incident response

Next Steps:
  1. Integrate with your application's authentication system
  2. Add logging for blocked packets
  3. Implement automatic IP unblocking after timeout
  4. Create dashboard to monitor rule statistics
""")
