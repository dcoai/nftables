#!/usr/bin/env elixir

# Query Tables Example
#
# This example demonstrates how to use NFTables.Query to inspect
# your current nftables configuration.
#
# **Format**: This example uses JSON format for communication with libnftables.
#
# Requirements:
# - The NFTables port binary must have CAP_NET_ADMIN capability
# - Run: sudo setcap cap_net_admin=ep priv/port_nftables
#
# Usage:
#   mix run examples/06_query_tables.exs

# Start NFTables (JSON-based port)
{:ok, pid} = NFTables.start_link()
IO.puts("NFTables Query Examples (JSON-based port)\n")
IO.puts(String.duplicate("=", 60))

# Query 1: List all tables
IO.puts("\n1. LISTING ALL TABLES (inet family)")
IO.puts(String.duplicate("-", 60))

case NFTables.Query.list_tables(pid, family: :inet) do
  {:ok, tables} ->
    IO.puts("Found #{length(tables)} tables:")
    for table <- tables do
      IO.puts("  📋 #{table.name}")
      IO.puts("     Family: #{table.family}")
      IO.puts("     Flags: #{table.flags}")
    end

  {:error, reason} ->
    IO.puts("Error: #{reason}")
end

# Query 2: List all chains
IO.puts("\n2. LISTING ALL CHAINS (inet family)")
IO.puts(String.duplicate("-", 60))

case NFTables.Query.list_chains(pid, family: :inet) do
  {:ok, chains} ->
    IO.puts("Found #{length(chains)} chains:")

    # Filter out unparsed chains and group by table
    parsed_chains = Enum.filter(chains, &Map.has_key?(&1, :table))
    chains_by_table = Enum.group_by(parsed_chains, & &1.table)

    for {table, table_chains} <- chains_by_table do
      IO.puts("\n  Table: #{table}")
      for chain <- table_chains do
        if chain.base_chain do
          IO.puts("    ⛓️  #{chain.name} (base chain)")
          IO.puts("       Hook: #{chain.hook}, Priority: #{chain.priority}, Policy: #{chain.policy}")
        else
          IO.puts("    ⛓️  #{chain.name} (regular chain)")
        end
      end
    end

    # Show unparsed chains
    unparsed = Enum.filter(chains, &Map.has_key?(&1, :raw))
    if length(unparsed) > 0 do
      IO.puts("\n  (#{length(unparsed)} chains with unparsed data)")
    end

  {:error, reason} ->
    IO.puts("Error: #{reason}")
end

# Query 3: List all sets
IO.puts("\n3. LISTING ALL SETS (inet family)")
IO.puts(String.duplicate("-", 60))

case NFTables.Query.list_sets(pid, family: :inet) do
  {:ok, sets} ->
    IO.puts("Found #{length(sets)} sets:")

    # Group sets by table
    sets_by_table = Enum.group_by(sets, & &1.table)

    for {table, table_sets} <- sets_by_table do
      IO.puts("\n  Table: #{table}")
      for set <- table_sets do
        IO.puts("    📦 #{set.name}")
        IO.puts("       Key type: #{set.key_type}, Key length: #{set.key_len} bytes")
      end
    end

  {:error, reason} ->
    IO.puts("Error: #{reason}")
end

# Query 4: List rules
IO.puts("\n4. LISTING ALL RULES (inet family)")
IO.puts(String.duplicate("-", 60))

case NFTables.Query.list_rules(pid, family: :inet) do
  {:ok, rules} ->
    IO.puts("Found #{length(rules)} rules:")

    # Group rules by table and chain
    for rule <- rules do
      IO.puts("  📜 Table: #{rule.table}, Chain: #{rule.chain}")
      IO.puts("     Handle: #{rule.handle}, Position: #{rule.position}")
    end

  {:error, reason} ->
    IO.puts("Error: #{reason}")
end

# Query 5: Examine a specific set's elements
IO.puts("\n5. EXAMINING SET ELEMENTS")
IO.puts(String.duplicate("-", 60))

# Find a set to examine
case NFTables.Query.list_sets(pid, family: :inet) do
  {:ok, [first_set | _]} ->
    IO.puts("Examining set: #{first_set.name} in table #{first_set.table}")

    case NFTables.Query.list_set_elements(pid, first_set.table, first_set.name, family: :inet) do
      {:ok, []} ->
        IO.puts("  (empty set)")

      {:ok, elements} ->
        IO.puts("  Found #{length(elements)} elements:")
        for elem <- Enum.take(elements, 5) do
          IO.puts("    - Key: #{elem.key_hex} (IP: #{elem.key_ip}), Flags: #{elem.flags}")
        end
        if length(elements) > 5 do
          IO.puts("    ... and #{length(elements) - 5} more")
        end

      {:error, reason} ->
        IO.puts("  Error listing elements: #{reason}")
    end

  {:ok, []} ->
    IO.puts("No sets found to examine")

  {:error, reason} ->
    IO.puts("Error: #{reason}")
end

IO.puts("\n" <> String.duplicate("=", 60))
IO.puts("Query examples complete!")
IO.puts(String.duplicate("=", 60))
IO.puts("""

Tip: You can use these query functions to:
  - Audit your firewall configuration
  - Monitor set contents
  - Verify rules are correctly installed
  - Build management dashboards
""")
