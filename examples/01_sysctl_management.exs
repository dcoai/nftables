#!/usr/bin/env elixir

# Sysctl Network Parameter Management Example
#
# This example demonstrates how to safely manage Linux kernel network
# parameters via NFTables's sysctl API.
#
# Features:
# - Read/write network kernel parameters
# - High-level helpers for common operations
# - Parameter whitelist security
# - Value validation
#
# Usage:
#   mix run examples/01_sysctl_management.exs
#
# Requirements:
#   - Root privileges or CAP_NET_ADMIN capability
#   - Run: sudo setcap cap_net_admin=ep priv/port_nftables
#
# Note: This example will READ parameters but only WRITES if you
#       explicitly confirm. Original values are restored.

Mix.install([{:nftables, path: "."}])

defmodule SysctlManagement do
  @moduledoc """
  Demonstrates sysctl network parameter management with NFTables.
  """

  alias NFTables.{Sysctl, Sysctl.Network}

  def run do
    IO.puts("=== NFTables Sysctl Management Example ===\n")

    # Start NFTables
    {:ok, pid} = NFTables.Port.start_link()
    IO.puts("✓ NFTables started\n")

    # 1. Read current network parameters
    demo_read_parameters(pid)

    # 2. High-level helpers (read-only demo)
    demo_high_level_helpers(pid)

    # 3. Composite operations (optional write demo)
    demo_composite_operations(pid)

    IO.puts("\n=== Example complete! ===")
  end

  defp demo_read_parameters(pid) do
    IO.puts("=== 1. Reading Current Network Parameters ===\n")

    params = [
      {"net.ipv4.ip_forward", "IPv4 forwarding"},
      {"net.ipv4.tcp_syncookies", "TCP SYN cookies (DDoS protection)"},
      {"net.ipv4.conf.all.rp_filter", "Reverse path filtering (anti-spoofing)"},
      {"net.ipv4.conf.all.accept_redirects", "Accept ICMP redirects"},
      {"net.ipv4.icmp_echo_ignore_all", "Ignore ping requests"},
      {"net.ipv6.conf.all.forwarding", "IPv6 forwarding"}
    ]

    for {param, description} <- params do
      case Sysctl.get(pid, param) do
        {:ok, value} ->
          IO.puts("✓ #{description}")
          IO.puts("  Parameter: #{param}")
          IO.puts("  Current value: #{value}\n")

        {:error, reason} ->
          IO.puts("✗ #{description}")
          IO.puts("  Parameter: #{param}")
          IO.puts("  Error: #{reason}\n")
      end
    end

    # Try reading connection tracking max (might not be available on all systems)
    case Sysctl.get(pid, "net.netfilter.nf_conntrack_max") do
      {:ok, value} ->
        IO.puts("✓ Connection tracking maximum")
        IO.puts("  Parameter: net.netfilter.nf_conntrack_max")
        IO.puts("  Current value: #{value}\n")

      {:error, _} ->
        IO.puts("ℹ Connection tracking not available on this system\n")
    end
  end

  defp demo_high_level_helpers(pid) do
    IO.puts("=== 2. High-Level Helper Functions ===\n")

    # Check IPv4 forwarding status
    case Network.ipv4_forwarding_enabled?(pid) do
      {:ok, enabled} ->
        status = if enabled, do: "ENABLED", else: "DISABLED"
        IO.puts("IPv4 Forwarding: #{status}")

      {:error, _} ->
        IO.puts("IPv4 Forwarding: Unable to check")
    end

    # Get connection tracking max
    case Network.get_conntrack_max(pid) do
      {:ok, max} ->
        IO.puts("Connection Tracking Max: #{max}")

      {:error, _} ->
        IO.puts("Connection Tracking Max: Not available")
    end

    IO.puts("")
  end

  defp demo_composite_operations(pid) do
    IO.puts("=== 3. Composite Operations (Router & Security Hardening) ===\n")
    IO.puts("This section demonstrates:")
    IO.puts("  • Network.configure_router/2 - Configure router settings")
    IO.puts("  • Network.harden_security/1 - Apply security hardening\n")

    IO.puts("⚠️  WARNING: These operations will MODIFY system parameters!")
    IO.puts("Do you want to run the write demo? (original values will be restored)")
    IO.write("Continue? [y/N]: ")

    case IO.gets("") |> String.trim() |> String.downcase() do
      "y" ->
        run_write_demo(pid)

      _ ->
        IO.puts("\nSkipped write demo.")
        IO.puts("\nTo manually test composite operations:")
        IO.puts("""

        # Configure as router
        :ok = Network.configure_router(pid,
          ipv4_forwarding: true,
          ipv6_forwarding: true,
          syncookies: true,
          send_redirects: false
        )

        # Harden security settings
        :ok = Network.harden_security(pid)

        # Individual operations
        :ok = Network.enable_ipv4_forwarding(pid)
        :ok = Network.enable_syncookies(pid)
        :ok = Network.set_conntrack_max(pid, 131072)
        :ok = Network.ignore_ping(pid)  # Stealth mode
        """)
    end
  end

  defp run_write_demo(pid) do
    IO.puts("\n=== Running Write Demo ===\n")

    # Store original values
    original_values = store_original_values(pid)

    # Demo: Enable IPv4 forwarding
    IO.puts("1. Enabling IPv4 forwarding...")
    case Network.enable_ipv4_forwarding(pid) do
      :ok ->
        {:ok, value} = Sysctl.get(pid, "net.ipv4.ip_forward")
        IO.puts("   ✓ IPv4 forwarding set to: #{value}")

      {:error, reason} ->
        IO.puts("   ✗ Failed: #{reason}")
    end

    # Demo: Enable SYN cookies
    IO.puts("\n2. Enabling TCP SYN cookies (DDoS protection)...")
    case Network.enable_syncookies(pid) do
      :ok ->
        {:ok, value} = Sysctl.get(pid, "net.ipv4.tcp_syncookies")
        IO.puts("   ✓ TCP SYN cookies set to: #{value}")

      {:error, reason} ->
        IO.puts("   ✗ Failed: #{reason}")
    end

    # Demo: Harden security
    IO.puts("\n3. Applying security hardening...")
    case Network.harden_security(pid) do
      :ok ->
        IO.puts("   ✓ Security hardening applied:")
        IO.puts("      - Reverse path filtering: enabled")
        IO.puts("      - Source routing: disabled")
        IO.puts("      - ICMP redirects: disabled")
        IO.puts("      - SYN cookies: enabled")

      {:error, reason} ->
        IO.puts("   ✗ Failed: #{reason}")
    end

    # Restore original values
    IO.puts("\n4. Restoring original values...")
    restore_original_values(pid, original_values)
    IO.puts("   ✓ Original values restored")
  end

  defp store_original_values(pid) do
    params = [
      "net.ipv4.ip_forward",
      "net.ipv4.tcp_syncookies",
      "net.ipv4.conf.all.rp_filter",
      "net.ipv4.conf.default.rp_filter",
      "net.ipv4.conf.all.accept_source_route",
      "net.ipv4.conf.default.accept_source_route",
      "net.ipv4.conf.all.send_redirects",
      "net.ipv4.conf.default.send_redirects",
      "net.ipv4.conf.all.accept_redirects",
      "net.ipv4.conf.default.accept_redirects",
      "net.ipv6.conf.all.accept_redirects",
      "net.ipv6.conf.default.accept_redirects"
    ]

    Enum.map(params, fn param ->
      case Sysctl.get(pid, param) do
        {:ok, value} -> {param, value}
        {:error, _} -> {param, nil}
      end
    end)
    |> Enum.filter(fn {_param, value} -> value != nil end)
  end

  defp restore_original_values(pid, original_values) do
    for {param, value} <- original_values do
      Sysctl.set(pid, param, value)
    end
  end
end

# Run the example
SysctlManagement.run()
