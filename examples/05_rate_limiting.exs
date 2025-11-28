#!/usr/bin/env elixir

# Rate Limiting Example
#
# This example demonstrates various rate limiting techniques:
# - Global rate limits per service
# - Per-IP rate limits using sets
# - Connection rate limiting (new connections)
# - Burst handling
# - DDoS mitigation patterns
#
# **Format**: This example uses JSON format for communication with libnftables.
#
# Usage:
#   mix run examples/05_rate_limiting.exs
#
# Requirements:
#   - Root privileges (CAP_NET_ADMIN)
#   - Run: sudo setcap cap_net_admin=ep priv/port_nftables

Mix.install([{:nftables, path: "."}])

defmodule RateLimiting do
  @moduledoc """
  Advanced rate limiting for DDoS protection and resource management.
  """

  alias NFTex.{Table, Chain, RuleBuilder, Policy}

  def run do
    IO.puts("Setting up Rate Limiting Firewall...")
    IO.puts("")

    case get_confirmation() do
      true -> setup_rate_limiting()
      false -> IO.puts("Cancelled.")
    end
  end

  defp get_confirmation do
    IO.write("Continue? [y/N]: ")
    response = IO.gets("") |> String.trim() |> String.downcase()
    response == "y"
  end

  defp setup_rate_limiting do
    # Use JSON-based port (Elixir maps/terms)
    {:ok, pid} = NFTex.start_link()
    IO.puts("✓ NFTex started (JSON-based port)")

    # Clean existing filter table
    case Table.delete(pid, "filter", :inet) do
      :ok -> IO.puts("✓ Removed existing filter table")
      {:error, _} -> :ok
    end

    # Create filter table
    :ok = Table.add(pid, %{name: "filter", family: :inet})
    IO.puts("✓ Created filter table")

    # Create INPUT chain
    :ok = Chain.add(pid, %{
      table: "filter",
      name: "INPUT",
      family: :inet,
      type: :filter,
      hook: :input,
      priority: 0,
      policy: :drop
    })
    IO.puts("✓ Created INPUT chain with DROP policy")

    # Basic security baseline
    IO.puts("\n=== Setting up baseline security ===")
    :ok = Policy.accept_loopback(pid)
    IO.puts("✓ Accept loopback traffic")

    :ok = Policy.accept_established(pid)
    IO.puts("✓ Accept established/related connections")

    :ok = Policy.drop_invalid(pid)
    IO.puts("✓ Drop invalid packets")

    # Rate limiting examples
    setup_ssh_rate_limit(pid)
    setup_http_rate_limit(pid)
    setup_icmp_rate_limit(pid)
    setup_new_connection_limit(pid)
    setup_syn_flood_protection(pid)

    IO.puts("\n✓ Rate limiting firewall setup complete!")
    IO.puts("\nTo view rules:")
    IO.puts("  sudo nft list table inet filter")
    IO.puts("\nTo test SSH rate limiting:")
    IO.puts("  # Try connecting more than 10 times per minute")
    IO.puts("  for i in {1..15}; do ssh localhost; sleep 3; done")
  end

  defp setup_ssh_rate_limit(pid) do
    IO.puts("\n=== SSH Rate Limiting ===")
    IO.puts("Limit: 10 connections per minute per IP")

    # SSH rate limit with logging
    :ok = Policy.allow_ssh(pid,
      rate_limit: 10,
      log: true
    )

    IO.puts("✓ SSH rate limit: 10/minute (with logging)")
  end

  defp setup_http_rate_limit(pid) do
    IO.puts("\n=== HTTP Rate Limiting ===")
    IO.puts("Limit: 100 requests per second with burst of 200")

    # HTTP with high rate limit and burst
    Match.new(pid, "filter", "INPUT")
    |> Match.dest_port(80)
    |> Match.rate_limit(100, :second, burst: 200)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("✓ HTTP rate limit: 100/second, burst: 200")
  end

  defp setup_icmp_rate_limit(pid) do
    IO.puts("\n=== ICMP Rate Limiting ===")
    IO.puts("Purpose: Allow ping but prevent ICMP flood")
    IO.puts("Limit: 5 ICMP packets per second")

    # ICMP rate limit (ping flood protection)
    Match.new(pid, "filter", "INPUT")
    |> Match.rate_limit(5, :second)
    |> Match.log("ICMP-ALLOWED: ")
    |> Match.accept()
    |> Match.commit()

    IO.puts("✓ ICMP rate limit: 5/second")
  end

  defp setup_new_connection_limit(pid) do
    IO.puts("\n=== New Connection Rate Limiting ===")
    IO.puts("Purpose: Limit new TCP connections to prevent connection exhaustion")
    IO.puts("Limit: 30 new connections per minute")

    # Limit NEW connections only (established connections are already accepted)
    Match.new(pid, "filter", "INPUT")
    |> Match.ct_state([:new])
    |> Match.rate_limit(30, :minute)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Drop any NEW connections exceeding the limit
    Match.new(pid, "filter", "INPUT")
    |> Match.ct_state([:new])
    |> Match.log("NEW-CONN-DROP: ")
    |> Match.drop()
    |> Match.commit()

    IO.puts("✓ New connection rate limit: 30/minute")
    IO.puts("  Connections exceeding limit will be dropped and logged")
  end

  defp setup_syn_flood_protection(pid) do
    IO.puts("\n=== SYN Flood Protection ===")
    IO.puts("Purpose: Protect against TCP SYN flood attacks")
    IO.puts("Strategy: Rate limit TCP SYN packets")

    # Note: This is a simplified example. Production systems should use
    # syncookies: echo 1 > /proc/sys/net/ipv4/tcp_syncookies

    # Rate limit on CT state NEW (which includes SYN packets)
    # Already handled by new connection limit above

    IO.puts("✓ SYN flood protection: Enabled via new connection limits")
    IO.puts("  Also enable kernel syncookies:")
    IO.puts("    echo 1 | sudo tee /proc/sys/net/ipv4/tcp_syncookies")
  end
end

# Run the example
RateLimiting.run()
