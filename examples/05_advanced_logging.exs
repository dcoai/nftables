#!/usr/bin/env elixir

# Advanced Logging Example
#
# This example demonstrates various logging techniques:
# - Kernel log integration
# - Netlink logging (ulogd) for external tools
# - Connection tracking logs
# - Traffic analysis and statistics
# - Log levels and prefixes
#
# Usage:
#   mix run examples/05_advanced_logging.exs
#
# Requirements:
#   - Root privileges (CAP_NET_ADMIN)
#   - Optional: ulogd2 for netlink logging
#
# Setup ulogd (optional):
#   apt-get install ulogd2
#   systemctl start ulogd2

Mix.install([{:nftex, path: "."}])

defmodule AdvancedLogging do
  @moduledoc """
  Advanced logging configurations for traffic analysis and audit.
  """

  alias NFTex.{Table, Chain, RuleBuilder, Policy, ExpressionBuilder}
  alias NFTex.Port

  def run do
    IO.puts("Setting up Advanced Logging Firewall...")
    IO.puts("")
    IO.puts("This example demonstrates:")
    IO.puts("  1. Kernel log integration (dmesg/journalctl)")
    IO.puts("  2. Netlink logging (ulogd)")
    IO.puts("  3. Connection tracking logs")
    IO.puts("  4. Traffic statistics")
    IO.puts("")

    case get_confirmation() do
      true -> setup_logging()
      false -> IO.puts("Cancelled.")
    end
  end

  defp get_confirmation do
    IO.write("Continue? [y/N]: ")
    response = IO.gets("") |> String.trim() |> String.downcase()
    response == "y"
  end

  defp setup_logging do
    {:ok, pid} = NFTex.start_link()
    IO.puts("✓ NFTex started")

    # Clean existing tables
    Table.delete(pid, "filter", :inet)
    Table.delete(pid, "logging", :inet)

    # Create filter table for main firewall
    :ok = Table.create(pid, %{name: "filter", family: :inet})
    IO.puts("✓ Created filter table")

    # Create separate logging table for traffic analysis
    :ok = Table.create(pid, %{name: "logging", family: :inet})
    IO.puts("✓ Created logging table")

    # Setup main filter chains
    setup_filter_chains(pid)

    # Setup logging chains
    setup_logging_chains(pid)

    # Logging examples
    log_dropped_traffic(pid)
    log_accepted_traffic(pid)
    log_new_connections(pid)
    log_port_scans(pid)
    setup_ulogd_integration(pid)
    setup_traffic_statistics(pid)

    IO.puts("\n✓ Advanced logging firewall setup complete!")
    IO.puts("\n=== Viewing Logs ===")
    IO.puts("\nKernel logs (dmesg):")
    IO.puts("  sudo dmesg | grep NFT")
    IO.puts("\nJournalctl (systemd):")
    IO.puts("  sudo journalctl -f -k | grep NFT")
    IO.puts("\nAll firewall logs:")
    IO.puts("  sudo journalctl -f | grep -E 'SSH|HTTP|SCAN|DROP'")
  end

  defp setup_filter_chains(pid) do
    # INPUT chain with DROP policy
    :ok = Chain.create(pid, %{
      table: "filter",
      name: "INPUT",
      family: :inet,
      type: :filter,
      hook: :input,
      priority: 0,
      policy: :drop
    })

    # Basic security
    Policy.accept_loopback(pid)
    Policy.accept_established(pid)
    Policy.drop_invalid(pid)

    IO.puts("✓ Created INPUT chain with baseline security")
  end

  defp setup_logging_chains(pid) do
    # PREROUTING chain for logging all incoming traffic
    :ok = Chain.create(pid, %{
      table: "logging",
      name: "PREROUTING",
      family: :inet,
      type: :filter,
      hook: :prerouting,
      priority: -400,  # Very early
      policy: :accept
    })

    IO.puts("✓ Created logging PREROUTING chain")
  end

  defp log_dropped_traffic(pid) do
    IO.puts("\n=== Logging Dropped Traffic ===")

    # Add counter and log before DROP policy takes effect
    # This catches all traffic that doesn't match any ACCEPT rule
    RuleBuilder.new(pid, "filter", "INPUT")
    |> RuleBuilder.counter()
    |> RuleBuilder.log("NFT-DROP: ", level: :warning)
    |> RuleBuilder.commit()

    # Note: The actual DROP happens via the chain policy

    IO.puts("✓ Dropped traffic will be logged with WARNING level")
    IO.puts("  Prefix: NFT-DROP:")
  end

  defp log_accepted_traffic(pid) do
    IO.puts("\n=== Logging Accepted Traffic ===")

    # SSH with detailed logging
    RuleBuilder.new(pid, "filter", "INPUT")
    |> RuleBuilder.match_dest_port(22)
    |> RuleBuilder.rate_limit(10, :minute)
    |> RuleBuilder.counter()
    |> RuleBuilder.log("NFT-SSH-ACCEPT: ", level: :info)
    |> RuleBuilder.accept()
    |> RuleBuilder.commit()

    # HTTP with logging
    RuleBuilder.new(pid, "filter", "INPUT")
    |> RuleBuilder.match_dest_port(80)
    |> RuleBuilder.counter()
    |> RuleBuilder.log("NFT-HTTP-ACCEPT: ", level: :info)
    |> RuleBuilder.accept()
    |> RuleBuilder.commit()

    # HTTPS with logging
    RuleBuilder.new(pid, "filter", "INPUT")
    |> RuleBuilder.match_dest_port(443)
    |> RuleBuilder.counter()
    |> RuleBuilder.log("NFT-HTTPS-ACCEPT: ", level: :info)
    |> RuleBuilder.accept()
    |> RuleBuilder.commit()

    IO.puts("✓ Accepted traffic logged at INFO level")
    IO.puts("  SSH: NFT-SSH-ACCEPT:")
    IO.puts("  HTTP: NFT-HTTP-ACCEPT:")
    IO.puts("  HTTPS: NFT-HTTPS-ACCEPT:")
  end

  defp log_new_connections(pid) do
    IO.puts("\n=== Logging New Connections ===")
    IO.puts("Purpose: Track all new TCP connections for audit")

    # Log all NEW TCP connections in the logging table
    with {:ok, rule_id} <- Port.call(pid, {:rule_alloc}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :table, "logging"}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :chain, "PREROUTING"}),
         :ok <- Port.call(pid, {:rule_set_u32, rule_id, :family, 2}),

         # Match NEW connections
         {:ok, ct_id} <- ExpressionBuilder.ct_state(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, ct_id}),
         {:ok, cmp_id} <- ExpressionBuilder.cmp_eq(pid, 1, <<0x08>>),  # NEW
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_id}),

         # Counter
         {:ok, counter_id} <- ExpressionBuilder.counter(pid),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, counter_id}),

         # Log
         {:ok, log_id} <- ExpressionBuilder.log(pid, prefix: "NFT-NEW-CONN: ", level: :notice),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, log_id}),

         :ok <- Port.call(pid, {:rule_send_to_kernel, rule_id, :add}),
         :ok <- Port.call(pid, {:rule_free, rule_id}) do

      IO.puts("✓ New connections logged at NOTICE level")
      IO.puts("  Prefix: NFT-NEW-CONN:")
    end
  end

  defp log_port_scans(pid) do
    IO.puts("\n=== Logging Potential Port Scans ===")
    IO.puts("Purpose: Detect and log connection attempts to uncommon ports")

    # Log connection attempts to high ports (potential port scans)
    # This is a simplified example - production systems should use more sophisticated detection

    uncommon_ports = [23, 135, 139, 445, 1433, 3306, 3389, 5432, 8080, 8888]

    Enum.each(uncommon_ports, fn port ->
      RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_dest_port(port)
      |> RuleBuilder.match_ct_state([:new])
      |> RuleBuilder.log("NFT-PORTSCAN: port=#{port} ", level: :alert)
      |> RuleBuilder.commit()
    end)

    IO.puts("✓ Port scan detection enabled for #{length(uncommon_ports)} common targets")
    IO.puts("  Prefix: NFT-PORTSCAN:")
    IO.puts("  Level: ALERT")
    IO.puts("  Ports monitored: #{inspect(uncommon_ports)}")
  end

  defp setup_ulogd_integration(pid) do
    IO.puts("\n=== Netlink Logging (ulogd) Integration ===")
    IO.puts("Purpose: Send logs to ulogd for database storage, analysis, or SIEM")

    # Send dropped packets to ulogd group 1
    RuleBuilder.new(pid, "logging", "PREROUTING")
    |> RuleBuilder.rate_limit(100, :second, burst: 50)  # Rate limit to prevent log flood
    |> add_ulogd_expression(1, "NFT-ULOG-DROP: ")
    |> RuleBuilder.commit()

    IO.puts("✓ Netlink logging configured")
    IO.puts("  Group: 1")
    IO.puts("  Rate: 100/second, burst: 50")
    IO.puts("")
    IO.puts("To receive these logs, configure ulogd2:")
    IO.puts("  1. Edit /etc/ulogd.conf")
    IO.puts("  2. Enable NFLOG plugin for group 1")
    IO.puts("  3. Configure output (MySQL, PostgreSQL, SQLite, etc.)")
    IO.puts("  4. Restart: systemctl restart ulogd2")
  end

  defp add_ulogd_expression(builder, group, prefix) do
    # Add ulogd logging expression manually
    # This sends logs to netlink group for ulogd processing
    Map.update!(builder, :expressions, fn exprs ->
      exprs ++ [fn pid ->
        ExpressionBuilder.log(pid, prefix: prefix, group: group, snaplen: 128)
      end]
    end)
  end

  defp setup_traffic_statistics(pid) do
    IO.puts("\n=== Traffic Statistics ===")
    IO.puts("Purpose: Count packets/bytes by protocol for analysis")

    # These counters can be queried later for statistics
    # Note: Counter objects would be better for this, but we're using inline counters

    # Count TCP traffic
    RuleBuilder.new(pid, "logging", "PREROUTING")
    |> RuleBuilder.counter()
    |> RuleBuilder.commit()

    IO.puts("✓ Traffic counters enabled")
    IO.puts("")
    IO.puts("To view statistics:")
    IO.puts("  sudo nft list table inet logging")
    IO.puts("")
    IO.puts("For detailed per-connection statistics, use:")
    IO.puts("  conntrack -L")
    IO.puts("  conntrack -S  (statistics)")
  end
end

# Run the example
AdvancedLogging.run()
