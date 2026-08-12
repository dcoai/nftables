#!/usr/bin/env elixir

# IP Blocklist Example
#
# Managing a named set of blocked addresses. A set is the right structure
# for a blocklist: one rule matches against the whole set, and addresses
# are added and removed without touching the ruleset itself.
#
# Requirements:
# - The port binary must have CAP_NET_ADMIN:
#     sudo setcap cap_net_admin=ep deps/nftables_port/priv/port_nftables
#
# Usage:
#   mix run examples/04_ip_blocklist.exs

import NFTables.Expr.Sets, only: [set: 3]
import NFTables.Expr.Verdict, only: [drop: 1]

alias NFTables.{Decoder, Local, Query}

{:ok, pid} = NFTables.Port.start_link()
IO.puts("✓ NFTables port started\n")

table = "filter"
blocklist = "banned_ips"

## Step 1: Create the set
IO.puts("Creating blocklist set...")

create =
  NFTables.add(table: table, family: :inet)
  |> NFTables.add(set: blocklist, type: :ipv4_addr)

case NFTables.submit(create, pid: pid) do
  :ok -> IO.puts("✓ Created set '#{blocklist}' in table '#{table}'")
  {:error, reason} -> IO.puts("Note: set may already exist (#{inspect(reason)})")
end

## Step 2: Confirm it exists
#
# There is no dedicated exists?/4 — query the sets and look for it. The
# read pipeline is always the same three stages: build, submit, decode.
IO.puts("\nChecking if set exists...")

exists? =
  case Query.list_sets(family: :inet) |> Local.submit(pid: pid) |> Decoder.decode() do
    {:ok, %{sets: sets}} -> Enum.any?(sets, &(&1.name == blocklist and &1.table == table))
    _ -> false
  end

if exists? do
  IO.puts("✓ Set '#{blocklist}' exists")
else
  IO.puts("✗ Set '#{blocklist}' does not exist")
  System.halt(1)
end

## Step 3: Add addresses
#
# In a real deployment these would arrive from an intrusion detection
# system, a feed, or your own rate-limiting logic.
IO.puts("\nAdding IPs to blocklist...")

blocked_ips = [
  # Example attacker
  "192.168.1.100",
  # Example scanner
  "10.0.0.50",
  # TEST-NET-3 (documentation range)
  "203.0.113.42"
]

add_elements =
  NFTables.add(table: table, family: :inet)
  |> NFTables.add(element: blocked_ips, set: blocklist)

case NFTables.submit(add_elements, pid: pid) do
  :ok ->
    IO.puts("✓ Added #{length(blocked_ips)} IPs:")
    Enum.each(blocked_ips, &IO.puts("  - #{&1}"))

  {:error, reason} ->
    IO.puts("✗ Failed to add IPs: #{inspect(reason)}")
end

## Step 4: Put the set to work
#
# The set is inert until a rule matches against it. One rule covers every
# address in the set, now and in future — this is why a set beats one
# rule per address.
IO.puts("\nAdding the rule that uses the set...")

rule =
  NFTables.add(table: table, chain: "INPUT", family: :inet)
  |> NFTables.add(rule: set(blocklist, :saddr) |> drop())

case NFTables.submit(rule, pid: pid) do
  :ok -> IO.puts("✓ Traffic from any address in '#{blocklist}' is now dropped")
  {:error, reason} -> IO.puts("✗ Failed to add rule: #{inspect(reason)}")
end

## Step 5: Read the set back
list_elements = fn label ->
  IO.puts("\n#{label}")

  case Query.list_set_elements(table, blocklist) |> Local.submit(pid: pid) |> Decoder.decode() do
    {:ok, %{sets: [%{elements: elements} | _]}} ->
      IO.puts("✓ #{length(elements)} address(es):")
      Enum.each(elements, &IO.puts("  - #{inspect(&1)}"))

    {:ok, _} ->
      IO.puts("  (set is empty)")

    {:error, reason} ->
      IO.puts("✗ Failed to list elements: #{inspect(reason)}")
  end
end

list_elements.("Current blocklist:")

## Step 6: Remove a false positive
#
# Removing an element takes effect immediately. The rule is untouched —
# that is the point of matching against a set.
IO.puts("\nRemoving false positive...")

remove =
  NFTables.delete(table: table, family: :inet)
  |> NFTables.delete(element: ["192.168.1.100"], set: blocklist)

case NFTables.submit(remove, pid: pid) do
  :ok -> IO.puts("✓ Removed 192.168.1.100 from blocklist")
  {:error, reason} -> IO.puts("✗ Failed to remove IP: #{inspect(reason)}")
end

list_elements.("Updated blocklist:")

## Step 7: Show every set in the table
IO.puts("\nAll sets in '#{table}':")

case Query.list_sets(family: :inet) |> Local.submit(pid: pid) |> Decoder.decode() do
  {:ok, %{sets: sets}} ->
    sets
    |> Enum.filter(&(&1.table == table))
    |> tap(&IO.puts("✓ Found #{length(&1)} set(s):"))
    |> Enum.each(&IO.puts("  - #{&1.name} (type: #{inspect(&1[:type])})"))

  {:ok, _} ->
    IO.puts("  (none)")

  {:error, reason} ->
    IO.puts("✗ Failed to list sets: #{inspect(reason)}")
end

IO.puts("""

Summary:
  ✓ Created a named set and matched one rule against it
  ✓ Added and removed elements without changing the ruleset

Why a set rather than one rule per address:
  - The ruleset stays a fixed size as the blocklist grows
  - Lookup is a hash, not a linear scan of rules
  - Updates need no rule changes, so nothing is re-evaluated

Next Steps:
  1. Add `timeout:` when creating the set for auto-expiring entries
  2. Use a meter to populate the set automatically — see advanced_features.exs
  3. Feed it from your application's own abuse detection
""")
