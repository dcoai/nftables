#!/usr/bin/env elixir

# Advanced NFTex Features Demo
#
# This example demonstrates the new match expressions, NAT operations,
# and connection tracking features added to NFTex.
#
# Prerequisites:
# - CAP_NET_ADMIN capability set on the port binary
# - Run as: mix run examples/advanced_features.exs

defmodule AdvancedFeaturesDemo do
  @moduledoc """
  Demonstrates advanced NFTex features including:
  - Extended match expressions (TCP flags, packet length, TTL, MAC, marks, DSCP)
  - NAT operations (masquerade, port forwarding, static NAT)
  - Advanced connection tracking (direction, status, marks)
  - Packet modification (set marks)
  """

  alias NFTex.{Table, Chain, RuleBuilder, NAT}

  def run do
    IO.puts("\n=== Advanced NFTex Features Demo ===\n")

    # Start NFTex with Port (JSON-based communication)
    {:ok, pid} = NFTex.start_link(check_capabilities: false)
    IO.puts("✓ NFTex started\n")

    # Clean up any existing test tables
    cleanup(pid)

    # Demo each feature area
    demo_match_expressions(pid)
    demo_nat_operations(pid)
    demo_connection_tracking(pid)
    demo_packet_modification(pid)

    IO.puts("\n=== Demo Complete ===")
    IO.puts("Tables created: filter, nat")
    IO.puts("Use 'nft list ruleset' to view rules")

    # Keep process alive for inspection
    IO.puts("\nPress Ctrl+C to exit and clean up...")
    :timer.sleep(:infinity)
  rescue
    error ->
      IO.puts("Error: #{inspect(error)}")
      :ok
  end

  defp demo_match_expressions(pid) do
    IO.puts("## Extended Match Expressions\n")

    # Create filter table and chain
    :ok = Table.add(pid, %{name: "filter", family: :inet})
    :ok =
      Chain.add(pid, %{
        table: "filter",
        name: "INPUT",
        family: :inet
      })

    IO.puts("1. TCP Flags - Block SYN flood")

    Match.new(pid, "filter", "INPUT")
    |> Match.tcp_flags([:syn], [:syn, :ack, :rst, :fin])
    |> Match.rate_limit(100, :second, burst: 20)
    |> Match.drop()
    |> Match.commit()

    IO.puts("   ✓ Rule: Drop excessive SYN packets (>100/sec)")

    IO.puts("\n2. Packet Length - Block jumbo frames")

    Match.new(pid, "filter", "INPUT")
    |> Match.length(:gt, 9000)
    |> Match.log("JUMBO: ")
    |> Match.drop()
    |> Match.commit()

    IO.puts("   ✓ Rule: Drop packets > 9000 bytes")

    IO.puts("\n3. TTL - Block TTL=1 (traceroute)")

    Match.new(pid, "filter", "INPUT")
    |> Match.ttl(:eq, 1)
    |> Match.log("TTL1: ")
    |> Match.drop()
    |> Match.commit()

    IO.puts("   ✓ Rule: Drop packets with TTL=1")

    IO.puts("\n4. MAC Address - Allow specific MAC")

    Match.new(pid, "filter", "INPUT")
    |> Match.source_mac("aa:bb:cc:dd:ee:ff")
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Accept from MAC aa:bb:cc:dd:ee:ff")

    IO.puts("\n5. DSCP - Prioritize VoIP traffic")

    Match.new(pid, "filter", "INPUT")
    |> Match.dscp(46)
    # Expedited Forwarding
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Accept DSCP 46 (EF - VoIP)")

    IO.puts("\n6. UDP Ports - DNS traffic")

    Match.new(pid, "filter", "INPUT")
    |> Match.udp_dport(53)
    |> Match.rate_limit(1000, :second)
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Rate-limit DNS queries (1000/sec)")

    IO.puts("\n7. Fragmentation - Block fragments")

    Match.new(pid, "filter", "INPUT")
    |> Match.fragmented(true)
    |> Match.log("FRAG: ")
    |> Match.drop()
    |> Match.commit()

    IO.puts("   ✓ Rule: Drop fragmented packets")

    IO.puts("")
  end

  defp demo_nat_operations(pid) do
    IO.puts("## NAT Operations\n")

    # Create NAT table and chains
    :ok = Table.add(pid, %{name: "nat", family: :inet})

    :ok =
      Chain.add(pid, %{
        table: "nat",
        name: "prerouting",
        family: :inet
      })

    :ok =
      Chain.add(pid, %{
        table: "nat",
        name: "postrouting",
        family: :inet
      })

    IO.puts("1. Internet Sharing (Masquerade)")

    :ok = NAT.setup_masquerade(pid, "eth0")
    IO.puts("   ✓ Masquerade on eth0 (internet sharing)")

    IO.puts("\n2. Port Forwarding (DNAT)")

    :ok = NAT.port_forward(pid, 80, "192.168.1.100", 8080)
    IO.puts("   ✓ Forward port 80 → 192.168.1.100:8080")

    :ok = NAT.port_forward(pid, 443, "192.168.1.100", 8443)
    IO.puts("   ✓ Forward port 443 → 192.168.1.100:8443")

    :ok = NAT.port_forward(pid, 53, "192.168.1.1", 53, protocol: :udp)
    IO.puts("   ✓ Forward UDP port 53 → 192.168.1.1:53")

    IO.puts("\n3. Static 1:1 NAT")

    :ok = NAT.static_nat(pid, "203.0.113.100", "192.168.1.100")
    IO.puts("   ✓ 1:1 NAT: 203.0.113.100 ↔ 192.168.1.100")

    IO.puts("\n4. Source NAT for subnet")

    :ok = NAT.source_nat(pid, "10.0.0.0/24", "203.0.113.1")
    IO.puts("   ✓ SNAT: 10.0.0.0/24 → 203.0.113.1")

    IO.puts("\n5. Transparent Proxy (Redirect)")

    :ok = NAT.redirect_port(pid, 80, 3128)
    IO.puts("   ✓ Redirect port 80 → 3128 (transparent proxy)")

    IO.puts("")
  end

  defp demo_connection_tracking(pid) do
    IO.puts("## Advanced Connection Tracking\n")

    IO.puts("1. CT Direction - Match original direction")

    Match.new(pid, "filter", "INPUT")
    |> Match.ct_direction(:original)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Accept original direction")

    IO.puts("\n2. CT Status - Match assured connections")

    Match.new(pid, "filter", "INPUT")
    |> Match.ct_status([:assured, :seen_reply])
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Accept assured connections")

    IO.puts("\n3. CT Status - Detect NATed traffic")

    Match.new(pid, "filter", "INPUT")
    |> Match.ct_status([:snat])
    |> Match.log("SNAT-CONN: ")
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Log SNAT connections")

    IO.puts("\n4. Connection Mark - Match marked connections")

    Match.new(pid, "filter", "INPUT")
    |> Match.connmark(100)
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Accept connections with mark 100")

    IO.puts("")
  end

  defp demo_packet_modification(pid) do
    IO.puts("## Packet Modification\n")

    IO.puts("1. Set Packet Mark - Policy routing")

    Match.new(pid, "filter", "INPUT")
    |> Match.source_ip("192.168.1.0/24")
    |> Match.set_mark(100)
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Mark packets from 192.168.1.0/24 with 100")

    IO.puts("\n2. Set Connection Mark - Persist across packets")

    Match.new(pid, "filter", "INPUT")
    |> Match.dest_port(80)
    |> Match.ct_state([:new])
    |> Match.set_connmark(200)
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Mark new HTTP connections with 200")

    IO.puts("\n3. Packet Mark - QoS classification")

    Match.new(pid, "filter", "INPUT")
    |> Match.dscp(46)
    # VoIP
    |> Match.set_mark(1)
    # High priority
    |> Match.accept()
    |> Match.commit()

    IO.puts("   ✓ Rule: Mark VoIP packets with priority 1")

    IO.puts("")
  end

  defp cleanup(pid) do
    # Best effort cleanup
    try do
      Table.delete(pid, "filter", :inet)
      Table.delete(pid, "nat", :inet)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end
end

# Run the demo
AdvancedFeaturesDemo.run()
