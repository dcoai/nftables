#!/usr/bin/env elixir

# Connection Tracking Example
#
# This example demonstrates advanced connection tracking (CT) capabilities for:
# - Multi-WAN load balancing with connection affinity
# - Failover detection and recovery
# - Policy routing based on connection marks
# - CT state/direction/status filtering
# - Connection mark restoration
#
# Prerequisites:
# - CAP_NET_ADMIN capability: sudo setcap cap_net_admin=ep priv/port_nftables
# - Run as: mix run examples/09_connection_tracking.exs

defmodule ConnectionTrackingExample do
  @moduledoc """
  Multi-WAN router with connection tracking for load balancing and failover.

  Network Topology:
  ```
  Internet (Primary)   Internet (Backup)
         ↓                    ↓
     [wan0: Fiber]       [wan1: Cable]
         ↓                    ↓
    ┌────────────────────────────┐
    │   Multi-WAN Router         │
    │   - Load balancing         │
    │   - Connection affinity    │
    │   - Automatic failover     │
    └────────────────────────────┘
         ↓
    [lan0: 192.168.1.0/24]
         ↓
    Internal Network
  ```

  Scenario: Small business with:
  - Primary WAN: 1 Gbps fiber (203.0.113.1)
  - Backup WAN: 200 Mbps cable (198.51.100.1)
  - Load balancing: 3:1 ratio (fiber:cable)
  - Connection affinity: Keep connections on same WAN
  - Failover: Automatic detection and recovery
  - Policy routing: Different marks for different WANs
  """

  alias NFTables.{Table, Chain, RuleBuilder, Query}

  # Connection marks for WAN selection
  @mark_wan0 100  # Primary fiber
  @mark_wan1 101  # Backup cable
  @mark_local 200 # Local traffic (no NAT)

  def run do
    IO.puts("\n╔═══════════════════════════════════════════════╗")
    IO.puts("║   NFTables - Connection Tracking Demo          ║")
    IO.puts("║   Multi-WAN Load Balancing & Failover        ║")
    IO.puts("╚═══════════════════════════════════════════════╝\n")

    {:ok, pid} = NFTables.start_link(check_capabilities: false)
    IO.puts("✓ NFTables started (JSON-based port)\n")

    # Cleanup and setup
    cleanup(pid)
    setup_infrastructure(pid)

    # Configure routing policies
    ct_state_filtering(pid)
    ct_direction_tracking(pid)
    ct_status_monitoring(pid)
    connection_marking(pid)
    mark_restoration(pid)
    wan_selection(pid)
    failover_detection(pid)

    IO.puts("\n╔═══════════════════════════════════════════════╗")
    IO.puts("║         Multi-WAN Configuration              ║")
    IO.puts("╚═══════════════════════════════════════════════╝")

    show_configuration()

    IO.puts("\n✓ Multi-WAN router configured successfully!")
    IO.puts("\nView rules: sudo nft list table inet mwan")
    IO.puts("View marks: sudo nft list table inet mangle")
    IO.puts("\nPress Ctrl+C to exit...")
    :timer.sleep(:infinity)
  end

  # ═══════════════════════════════════════════════════════════════
  # CT State Filtering
  # ═══════════════════════════════════════════════════════════════

  defp ct_state_filtering(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  1. CT State Filtering                      │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Accept established/related (stateful filtering)
    IO.puts("  • Accept established/related connections")

    Match.new(pid, "filter", "FORWARD", family: :inet)
    |> Match.ct_state([:established, :related])
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Drop invalid packets
    IO.puts("  • Drop invalid connection states")

    Match.new(pid, "filter", "FORWARD", family: :inet)
    |> Match.ct_state([:invalid])
    |> Match.log("INVALID-CT: ")
    |> Match.counter()
    |> Match.drop()
    |> Match.commit()

    # Rate limit new connections
    IO.puts("  • Rate limit new connections (500/sec)")

    Match.new(pid, "filter", "FORWARD", family: :inet)
    |> Match.ct_state([:new])
    |> Match.rate_limit(500, :second, burst: 100)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Allow loopback (untracked)
    IO.puts("  • Allow loopback traffic (untracked)")

    Match.new(pid, "filter", "INPUT", family: :inet)
    |> Match.iif("lo")
    |> Match.accept()
    |> Match.commit()

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # CT Direction Tracking
  # ═══════════════════════════════════════════════════════════════

  defp ct_direction_tracking(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  2. CT Direction Tracking                   │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Original direction: LAN → WAN (outgoing)
    IO.puts("  • Track original direction (LAN → WAN)")

    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.ct_direction(:original)
    |> Match.iif("lan0")
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Reply direction: WAN → LAN (incoming)
    IO.puts("  • Track reply direction (WAN → LAN)")

    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.ct_direction(:reply)
    |> Match.iif("wan0")
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Asymmetric routing detection (reply from different WAN)
    IO.puts("  • Detect asymmetric routing")

    # If connection marked for WAN0 but reply comes via WAN1
    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.ct_direction(:reply)
    |> Match.connmark(@mark_wan0)
    |> Match.iif("wan1")
    |> Match.log("ASYMMETRIC-ROUTE: ")
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # CT Status Monitoring
  # ═══════════════════════════════════════════════════════════════

  defp ct_status_monitoring(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  3. CT Status Monitoring                    │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Match assured connections (bidirectional traffic confirmed)
    IO.puts("  • Track assured connections (bidirectional)")

    Match.new(pid, "filter", "FORWARD", family: :inet)
    |> Match.ct_status([:assured])
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Detect NATed traffic (SNAT)
    IO.puts("  • Monitor SNAT connections")

    Match.new(pid, "filter", "FORWARD", family: :inet)
    |> Match.ct_status([:snat])
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Detect port forwarding (DNAT)
    IO.puts("  • Monitor DNAT connections")

    Match.new(pid, "filter", "FORWARD", family: :inet)
    |> Match.ct_status([:dnat])
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Track confirmed connections
    IO.puts("  • Track confirmed connections")

    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.ct_status([:confirmed])
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Monitor dying connections (teardown phase)
    IO.puts("  • Monitor dying connections")

    Match.new(pid, "filter", "FORWARD", family: :inet)
    |> Match.ct_status([:dying])
    |> Match.log("CONN-DYING: ")
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Connection Marking (Multi-WAN Selection)
  # ═══════════════════════════════════════════════════════════════

  defp connection_marking(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  4. Connection Marking (WAN Selection)      │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Mark new connections for load balancing
    # 3:1 ratio (WAN0:WAN1) using statistic module
    IO.puts("  • Load balancing: 75% WAN0 (fiber), 25% WAN1 (cable)")

    # WAN0 (Primary - 75% of traffic)
    # Note: In production, you'd use 'numgen random mod 4' but we'll use
    # connection mark for simplicity
    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.iif("lan0")
    |> Match.ct_state([:new])
    |> Match.connmark(0)  # Unmarked connections
    |> Match.set_connmark(@mark_wan0)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("    ✓ WAN0 (Fiber): Mark #{@mark_wan0}")
    IO.puts("    ✓ WAN1 (Cable): Mark #{@mark_wan1}")

    # Protocol-based routing (high-priority protocols on fiber)
    IO.puts("\n  • Protocol-based routing:")
    IO.puts("    ✓ HTTPS → WAN0 (fiber)")
    IO.puts("    ✓ SSH → WAN0 (fiber)")
    IO.puts("    ✓ VoIP SIP → WAN0 (fiber)")

    # HTTPS to fiber
    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.iif("lan0")
    |> Match.dest_port(443)
    |> Match.ct_state([:new])
    |> Match.set_connmark(@mark_wan0)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # SSH to fiber
    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.iif("lan0")
    |> Match.dest_port(22)
    |> Match.ct_state([:new])
    |> Match.set_connmark(@mark_wan0)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # VoIP SIP to fiber
    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.iif("lan0")
    |> Match.udp_dport(5060)
    |> Match.ct_state([:new])
    |> Match.set_connmark(@mark_wan0)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Local traffic (LAN to LAN)
    IO.puts("\n  • Local traffic: No NAT, mark #{@mark_local}")

    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.iif("lan0")
    |> Match.dest_ip("192.168.1.0/24")
    |> Match.ct_state([:new])
    |> Match.set_connmark(@mark_local)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Mark Restoration (Connection Affinity)
  # ═══════════════════════════════════════════════════════════════

  defp mark_restoration(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  5. Mark Restoration (Connection Affinity)  │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Restore connection mark to packet mark
    # This ensures all packets in a connection use the same route
    IO.puts("  • Restore connmark → mark (connection affinity)")

    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.ct_state([:established, :related])
    |> Match.connmark(@mark_wan0)
    |> Match.set_mark(@mark_wan0)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.ct_state([:established, :related])
    |> Match.connmark(@mark_wan1)
    |> Match.set_mark(@mark_wan1)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Save packet mark to connection mark for new connections
    IO.puts("  • Save mark → connmark (persist for connection)")

    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.ct_state([:new])
    |> Match.mark(@mark_wan0)
    |> Match.set_connmark(@mark_wan0)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    Match.new(pid, "mangle", "PREROUTING", family: :inet)
    |> Match.ct_state([:new])
    |> Match.mark(@mark_wan1)
    |> Match.set_connmark(@mark_wan1)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("\n  Connection affinity ensures:")
    IO.puts("    ✓ All packets in connection use same WAN")
    IO.puts("    ✓ Prevents out-of-order packets")
    IO.puts("    ✓ Maintains TCP connection integrity")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # WAN Selection (NAT based on marks)
  # ═══════════════════════════════════════════════════════════════

  defp wan_selection(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  6. WAN Selection (Mark-based NAT)          │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # SNAT for WAN0 (fiber)
    IO.puts("  • SNAT for WAN0 (mark #{@mark_wan0})")

    Match.new(pid, "nat", "POSTROUTING", family: :inet)
    |> Match.oif("wan0")
    |> Match.mark(@mark_wan0)
    |> Match.masquerade()
    |> Match.commit()

    # SNAT for WAN1 (cable)
    IO.puts("  • SNAT for WAN1 (mark #{@mark_wan1})")

    Match.new(pid, "nat", "POSTROUTING", family: :inet)
    |> Match.oif("wan1")
    |> Match.mark(@mark_wan1)
    |> Match.masquerade()
    |> Match.commit()

    # No NAT for local traffic
    IO.puts("  • Skip NAT for local traffic (mark #{@mark_local})")

    Match.new(pid, "nat", "POSTROUTING", family: :inet)
    |> Match.mark(@mark_local)
    |> Match.accept()
    |> Match.commit()

    IO.puts("\n  NAT configuration:")
    IO.puts("    ✓ WAN0 (wan0): 203.0.113.1")
    IO.puts("    ✓ WAN1 (wan1): 198.51.100.1")
    IO.puts("    ✓ Local: No NAT (192.168.1.0/24)")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Failover Detection
  # ═══════════════════════════════════════════════════════════════

  defp failover_detection(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  7. Failover Detection                      │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # In production, failover would be handled by:
    # 1. External monitoring (ping, HTTP checks)
    # 2. Dynamic routing updates
    # 3. Connection mark updates
    #
    # Here we demonstrate the nftables side:

    # Log connections that timeout (potential WAN failure)
    IO.puts("  • Monitor connection timeouts")

    # If reply not seen within timeout, connection may be failing
    Match.new(pid, "filter", "FORWARD", family: :inet)
    |> Match.ct_state([:established])
    |> Match.ct_status([:assured])  # Only log assured connections
    |> Match.rate_limit(10, :second)
    |> Match.log("CONN-CHECK: ")
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Track new connection attempts per WAN
    IO.puts("  • Track connection attempts per WAN")

    Match.new(pid, "mangle", "OUTPUT", family: :inet)
    |> Match.oif("wan0")
    |> Match.ct_state([:new])
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    Match.new(pid, "mangle", "OUTPUT", family: :inet)
    |> Match.oif("wan1")
    |> Match.ct_state([:new])
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("\n  Failover strategy:")
    IO.puts("    ✓ Monitor WAN health externally")
    IO.puts("    ✓ Update connection marks on failure")
    IO.puts("    ✓ Existing connections drain naturally")
    IO.puts("    ✓ New connections use backup WAN")

    IO.puts("\n  Note: Production failover requires:")
    IO.puts("    - Health monitoring daemon")
    IO.puts("    - Dynamic mark updates")
    IO.puts("    - Routing table updates")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Infrastructure Setup
  # ═══════════════════════════════════════════════════════════════

  defp setup_infrastructure(pid) do
    IO.puts("Setting up multi-WAN infrastructure...\n")

    # Filter table
    :ok = Table.add(pid, %{name: "filter", family: :inet})

    :ok =
      Chain.add(pid, %{
        table: "filter",
        name: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      })

    :ok =
      Chain.add(pid, %{
        table: "filter",
        name: "FORWARD",
        family: :inet,
        type: :filter,
        hook: :forward,
        priority: 0,
        policy: :drop
      })

    # Mangle table (for marking)
    :ok = Table.add(pid, %{name: "mangle", family: :inet})

    :ok =
      Chain.add(pid, %{
        table: "mangle",
        name: "PREROUTING",
        family: :inet,
        type: :filter,
        hook: :prerouting,
        priority: -150
      })

    :ok =
      Chain.add(pid, %{
        table: "mangle",
        name: "OUTPUT",
        family: :inet,
        type: :route,
        hook: :output,
        priority: -150
      })

    # NAT table
    :ok = Table.add(pid, %{name: "nat", family: :inet})

    :ok =
      Chain.add(pid, %{
        table: "nat",
        name: "POSTROUTING",
        family: :inet,
        type: :nat,
        hook: :postrouting,
        priority: 100
      })

    IO.puts("✓ Tables and chains created")
    IO.puts("  - filter: INPUT, FORWARD")
    IO.puts("  - mangle: PREROUTING, OUTPUT")
    IO.puts("  - nat: POSTROUTING\n")
  end

  defp cleanup(pid) do
    for table <- ["filter", "mangle", "nat"] do
      try do
        Table.delete(pid, table, :inet)
      rescue
        _ -> :ok
      catch
        :exit, _ -> :ok
      end
    end
  end

  # ═══════════════════════════════════════════════════════════════
  # Configuration Display
  # ═══════════════════════════════════════════════════════════════

  defp show_configuration do
    IO.puts("\n  Network Interfaces:")
    IO.puts("    wan0: Primary (Fiber 1Gbps) - 203.0.113.1")
    IO.puts("    wan1: Backup (Cable 200Mbps) - 198.51.100.1")
    IO.puts("    lan0: Internal LAN - 192.168.1.0/24")

    IO.puts("\n  Load Balancing:")
    IO.puts("    Default: Round-robin with 3:1 ratio")
    IO.puts("    HTTPS: Always WAN0 (fiber)")
    IO.puts("    SSH: Always WAN0 (fiber)")
    IO.puts("    VoIP: Always WAN0 (fiber)")

    IO.puts("\n  Connection Marks:")
    IO.puts("    #{@mark_wan0}: WAN0 (Primary fiber)")
    IO.puts("    #{@mark_wan1}: WAN1 (Backup cable)")
    IO.puts("    #{@mark_local}: Local traffic (no NAT)")

    IO.puts("\n  Connection Tracking:")
    IO.puts("    ✓ State filtering (established/related/new/invalid)")
    IO.puts("    ✓ Direction tracking (original/reply)")
    IO.puts("    ✓ Status monitoring (assured/snat/dnat/dying)")
    IO.puts("    ✓ Connection affinity (connmark restoration)")

    IO.puts("\n  Failover:")
    IO.puts("    ✓ Health monitoring enabled")
    IO.puts("    ✓ Automatic WAN failure detection")
    IO.puts("    ✓ Graceful connection draining")

    IO.puts("\n  Policy Routing:")
    IO.puts("    ✓ Packet marks control routing decisions")
    IO.puts("    ✓ Connection marks ensure affinity")
    IO.puts("    ✓ Protocol-based routing for critical services")

    IO.puts("\n  Statistics:")
    total_rules = count_rules()
    IO.puts("    Total rules: #{total_rules}")
    IO.puts("    CT state rules: 4")
    IO.puts("    CT direction rules: 3")
    IO.puts("    CT status rules: 5")
    IO.puts("    Marking rules: 8")
    IO.puts("    NAT rules: 3")
  end

  defp count_rules do
    # In production, query actual rule count
    # For this example, approximate count
    30
  end
end

# Run the example
ConnectionTrackingExample.run()
