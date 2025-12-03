#!/usr/bin/env elixir

# Basic Firewall Example
#
# This example demonstrates a complete, secure firewall setup with:
# - Default DROP policy (deny all by default)
# - Accept loopback traffic
# - Accept established/related connections
# - Drop invalid packets
# - Allow SSH with rate limiting (10/minute)
# - Optional HTTP/HTTPS services
#
# **Format**: This example uses JSON format for communication with libnftables.
#
# Usage:
#   mix run examples/02_basic_firewall.exs
#
# Requirements:
#   - Root privileges (CAP_NET_ADMIN)
#   - libnftables installed
#   - Run: sudo setcap cap_net_admin=ep priv/port_nftables

Mix.install([{:nftables, path: "."}])

defmodule BasicFirewall do
  @moduledoc """
  Complete basic firewall setup with secure defaults.
  """

  alias NFTables.{Table, Chain, Policy, Builder}

  def run do
    IO.puts("Setting up basic firewall...")
    IO.puts("Warning: This will modify your system firewall rules!")
    IO.puts("")

    case get_confirmation() do
      true -> setup_firewall()
      false -> IO.puts("Cancelled.")
    end
  end

  defp get_confirmation do
    IO.write("Continue? [y/N]: ")
    response = IO.gets("") |> String.trim() |> String.downcase()
    response == "y"
  end

  defp setup_firewall do
    # Start NFTables (JSON-based port)
    {:ok, pid} = NFTables.Port.start_link()

    IO.puts("✓ NFTables started (JSON-based port)")

    # Clean slate - delete existing filter table if it exists
    case Table.delete(pid, "filter", :inet) do
      :ok -> IO.puts("✓ Removed existing filter table")
      {:error, _} -> :ok
    end

    # Option 1: Use high-level Policy.setup_basic_firewall/2
    IO.puts("\n=== Option 1: Using Policy.setup_basic_firewall ===")

    case Policy.setup_basic_firewall(pid,
      allow_services: [:ssh],
      ssh_rate_limit: 10
    ) do
      :ok ->
        IO.puts("✓ Basic firewall configured!")
        IO.puts("  - Loopback: ACCEPT")
        IO.puts("  - Established/Related: ACCEPT")
        IO.puts("  - Invalid packets: DROP")
        IO.puts("  - SSH: ACCEPT (rate limited: 10/min)")
        IO.puts("  - Default policy: DROP")
      {:error, reason} ->
        IO.puts("✗ Failed: #{inspect(reason)}")
    end

    # Option 2: Manual setup with more control
    IO.puts("\n=== Option 2: Manual setup (commented out) ===")
    IO.puts("# To use manual setup, uncomment the code below:")

    IO.puts("""

    # # 1. Create filter table
    # :ok = Table.add(pid, %{name: "filter", family: :inet})
    #
    # # 2. Create INPUT chain with DROP policy
    # :ok = Chain.add(pid, %{
    #   table: "filter",
    #   name: "INPUT",
    #   family: :inet,
    #   type: :filter,
    #   hook: :input,
    #   priority: 0,
    #   policy: :drop  # DROP by default
    # })
    #
    # # 3. Apply policy rules (composable - all in one transaction)
    # :ok =
    #   NFTables.add(table: "filter")
    #   |> Policy.accept_loopback()
    #   |> Policy.accept_established()
    #   |> Policy.drop_invalid()
    #   |> Policy.allow_ssh(rate_limit: 10, log: true)
    #   |> NFTables.submit(pid: pid)
    #
    # # 4. Optionally allow web services
    # # :ok =
    # #   NFTables.add(table: "filter")
    # #   |> Policy.allow_http()
    # #   |> Policy.allow_https()
    # #   |> NFTables.submit(pid: pid)
    """)

    # Display current rules
    IO.puts("\n=== Current firewall rules ===")
    display_rules(pid)

    IO.puts("\n✓ Firewall setup complete!")
    IO.puts("\nTo view rules with nft command:")
    IO.puts("  sudo nft list ruleset")
    IO.puts("\nTo remove this firewall:")
    IO.puts("  sudo nft delete table inet filter")
  end

  defp display_rules(pid) do
    case NFTables.Query.list_chains(pid, family: :inet) do
      {:ok, chains} ->
        for chain <- chains do
          IO.puts("Chain #{chain.name} (table: #{chain.table})")
          if hook = Map.get(chain, :hook) do
            IO.puts("  Hook: #{hook}")
            IO.puts("  Priority: #{Map.get(chain, :priority, 0)}")
            IO.puts("  Policy: #{Map.get(chain, :policy, :accept)}")
          end
        end
      {:error, reason} ->
        IO.puts("Failed to list chains: #{inspect(reason)}")
    end
  end
end

# Run the example
BasicFirewall.run()
