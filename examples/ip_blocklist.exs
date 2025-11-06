#!/usr/bin/env elixir

# IP Blocklist Example
#
# This example demonstrates how to use NFTex to create and manage
# an IP address blocklist using nftables sets.
#
# **Format Demonstration**: This example uses the JSN: format (JSON strings)
# with UnifiedPort to explicitly show JSON-based communication.
# Other examples use ETF: format (Elixir maps/terms).
#
# Requirements:
# - The NFTex port binary must have CAP_NET_ADMIN capability
# - Run: sudo setcap cap_net_admin=ep priv/libnf_unified
#
# Usage:
#   mix run examples/ip_blocklist.exs

# Start NFTex with UnifiedPort (demonstrating JSN: format with JSON strings)
{:ok, pid} = NFTex.start_link(port: NFTex.UnifiedPort)
IO.puts("✓ NFTex started (UnifiedPort with JSN: format - JSON strings)\n")

# Configuration
table = "filter"
blocklist_name = "banned_ips"

# Step 1: Create the blocklist set (if it doesn't exist)
IO.puts("Creating blocklist set...")

# Try to create the set (will fail if it already exists, which is fine)
# Demonstrate JSN: format - send JSON string prefixed with "JSN:"
json_cmd = Jason.encode!(%{
  "nftables" => [
    %{
      "add" => %{
        "set" => %{
          "family" => "inet",
          "table" => table,
          "name" => blocklist_name,
          "type" => "ipv4_addr"
        }
      }
    }
  ]
})

# Send with JSN: prefix to explicitly indicate JSON format
case NFTex.UnifiedPort.call(pid, "JSN:#{json_cmd}") do
  {:ok, _response} ->
    IO.puts("✓ Created set '#{blocklist_name}' in table '#{table}' (via JSN: format)")

  {:error, reason} ->
    # Set might already exist
    IO.puts("Note: Set may already exist (#{reason})")
end

# Step 2: Check if the set exists
IO.puts("\nChecking if set exists...")
if NFTex.Set.exists?(pid, table, blocklist_name, :inet) do
  IO.puts("✓ Set '#{blocklist_name}' exists")
else
  IO.puts("✗ Set '#{blocklist_name}' does not exist")
  exit(1)
end

# Step 3: Add suspicious IPs to the blocklist
IO.puts("\nAdding IPs to blocklist...")

# Example: Block some IP addresses (now using string format)
# In a real scenario, these might come from an intrusion detection system
blocked_ips = [
  "192.168.1.100",  # Example attacker
  "10.0.0.50",      # Example scanner
  "203.0.113.42"    # TEST-NET-3 (example)
]

case NFTex.Set.add_elements(pid, table, blocklist_name, :inet, blocked_ips) do
  :ok ->
    IO.puts("✓ Added #{length(blocked_ips)} IPs to blocklist:")
    for ip_str <- blocked_ips do
      IO.puts("  - #{ip_str}")
    end

  {:error, reason} ->
    IO.puts("✗ Failed to add IPs: #{reason}")
end

# Step 4: List all blocked IPs
IO.puts("\nCurrent blocklist:")

case NFTex.Set.list_elements(pid, table, blocklist_name) do
  {:ok, elements} ->
    IO.puts("✓ Blocked IPs (#{length(elements)} total):")
    for elem <- Enum.sort_by(elements, & &1.key_ip) do
      IO.puts("  - #{elem.key_ip} (flags: #{elem.flags})")
    end

  {:error, reason} ->
    IO.puts("✗ Failed to list elements: #{reason}")
end

# Step 5: Remove an IP from the blocklist
# (Maybe it was a false positive)
IO.puts("\nRemoving false positive...")

ip_to_unblock = ["192.168.1.100"]

case NFTex.Set.delete_elements(pid, table, blocklist_name, :inet, ip_to_unblock) do
  :ok ->
    IO.puts("✓ Removed 192.168.1.100 from blocklist")

  {:error, reason} ->
    IO.puts("✗ Failed to remove IP: #{reason}")
end

# Step 6: Verify the IP was removed
IO.puts("\nUpdated blocklist:")

case NFTex.Set.list_elements(pid, table, blocklist_name) do
  {:ok, elements} ->
    IO.puts("✓ Blocked IPs (#{length(elements)} remaining):")
    for elem <- Enum.sort_by(elements, & &1.key_ip) do
      IO.puts("  - #{elem.key_ip}")
    end

  {:error, reason} ->
    IO.puts("✗ Failed to list elements: #{reason}")
end

# Step 7: Show all sets in the filter table
IO.puts("\nAll sets in '#{table}' table:")

case NFTex.Set.list(pid, family: :inet) do
  {:ok, sets} ->
    filter_sets = Enum.filter(sets, fn s -> s.table == table end)
    IO.puts("✓ Found #{length(filter_sets)} sets:")
    for set <- filter_sets do
      IO.puts("  - #{set.name} (key_len: #{set.key_len} bytes)")
    end

  {:error, reason} ->
    IO.puts("✗ Failed to list sets: #{reason}")
end

IO.puts("\n" <> String.duplicate("=", 60))
IO.puts("Example complete!")
IO.puts(String.duplicate("=", 60))
IO.puts("""

Next steps:
  1. Create nftables rules to use this set:
     nft add rule filter input ip saddr @banned_ips drop

  2. Integrate with your application to dynamically update the blocklist

  3. Use NFTex.Set.add_elements/5 to block new IPs in real-time

  4. Use NFTex.Set.delete_elements/5 to unblock IPs
""")
