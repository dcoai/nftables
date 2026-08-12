#!/usr/bin/env elixir

# Firewall Rules Example
#
# Creating firewall rules dynamically to block and allow IP addresses.
#
# This example builds rules as data first, then submits them. Nothing
# touches the kernel until `NFTables.submit/2` is called, so you can
# inspect exactly what will be applied.
#
# Requirements:
# - The port binary must have CAP_NET_ADMIN:
#     sudo setcap cap_net_admin=ep deps/nftables_port/priv/port_nftables
# - A base chain must exist:
#     nft add chain filter INPUT '{ type filter hook input priority 0; }'
#
# Usage:
#   mix run examples/03_firewall_rules.exs

import NFTables.Expr.IP, only: [source_ip: 2]
import NFTables.Expr.Actions, only: [counter: 1]
import NFTables.Expr.Verdict, only: [accept: 1, drop: 1]

alias NFTables.{Decoder, Local, Query}

{:ok, pid} = NFTables.Port.start_link()
IO.puts("✓ NFTables port started\n")

table = "filter"
chain = "INPUT"

IO.puts("===== DYNAMIC FIREWALL RULES EXAMPLE =====\n")

malicious_ips = [
  "192.168.1.111",
  "10.0.0.99",
  "172.16.5.50"
]

trusted_ips = [
  # Admin workstation
  "192.168.1.10",
  # Monitoring server
  "192.168.1.20"
]

## STEP 1: Build the rules (pure — no kernel interaction yet)
IO.puts("Step 1: Building rules...")

block_rules = Enum.map(malicious_ips, fn ip -> source_ip(ip) |> counter() |> drop() end)
accept_rules = Enum.map(trusted_ips, fn ip -> source_ip(ip) |> counter() |> accept() end)

IO.puts("  ✓ #{length(block_rules)} block rules, #{length(accept_rules)} accept rules\n")

## STEP 2: Submit them
#
# Order matters: nftables evaluates a chain top to bottom and the first
# terminal verdict wins. The accept rules are inserted rather than
# appended so they are evaluated before the drops — otherwise a trusted
# address that also matched a block rule would never reach its accept.
IO.puts("Step 2: Applying to the kernel...")

config =
  NFTables.add(table: table, chain: chain, family: :inet)
  |> NFTables.add(rules: block_rules)
  |> NFTables.insert(rules: accept_rules)

case NFTables.submit(config, pid: pid) do
  :ok ->
    IO.puts("  ✓ Blocked: #{Enum.join(malicious_ips, ", ")}")
    IO.puts("  ✓ Allowed: #{Enum.join(trusted_ips, ", ")}\n")

  {:error, reason} ->
    IO.puts("  ✗ Failed: #{inspect(reason)}\n")
end

## STEP 3: Read the rules back
#
# Query builds a command, Local submits it, Decoder turns the response
# into Elixir data. The three stages are separate on purpose.
IO.puts("Step 3: Listing current rules...")

case Query.list_rules(table, chain, family: :inet) |> Local.submit(pid: pid) |> Decoder.decode() do
  {:ok, %{rules: rules}} ->
    IO.puts("  ✓ Total rules in #{table}/#{chain}: #{length(rules)}")
    IO.puts("\n  Last 5 rules added:")

    rules
    |> Enum.sort_by(& &1.handle, :desc)
    |> Enum.take(5)
    |> Enum.each(fn rule ->
      IO.puts("    - handle #{rule.handle}  #{rule.table}/#{rule.chain}")
    end)

  {:ok, _} ->
    IO.puts("  (no rules found in #{table}/#{chain})")

  {:error, reason} ->
    IO.puts("  ✗ Failed to list rules: #{inspect(reason)}")
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
  1. Expressions are data     - source_ip(ip) |> counter() |> drop()
  2. Build then submit        - nothing applies until NFTables.submit/2
  3. Batch application        - all rules land in one atomic operation
  4. insert vs add            - insert/2 places rules ahead of existing ones
  5. Query -> submit -> decode - the read pipeline

Real-World Use Cases:
  - Intrusion detection system (IDS) integration
  - Rate limiting abusive clients
  - Geographic IP blocking
  - Dynamic allowlist/blocklist management
  - Security incident response

Next Steps:
  1. Integrate with your application's authentication system
  2. Add logging for blocked packets with Expr.Actions.log/3
  3. Implement automatic IP unblocking after a timeout
  4. Move the blocklist into a named set — see 04_ip_blocklist.exs
""")
