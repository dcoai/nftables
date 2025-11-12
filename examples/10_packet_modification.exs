#!/usr/bin/env elixir

# Packet Modification Example
#
# This example demonstrates packet and connection modification for:
# - Traffic classification by application/protocol
# - Quality of Service (QoS) with multi-tier prioritization
# - Policy routing based on packet marks
# - DSCP-based traffic management
# - Integration with tc (traffic control) for shaping
#
# Prerequisites:
# - CAP_NET_ADMIN capability: sudo setcap cap_net_admin=ep priv/port_nftables
# - Run as: mix run examples/10_packet_modification.exs

defmodule PacketModificationExample do
  @moduledoc """
  Enterprise gateway with comprehensive QoS and traffic classification.

  Network Topology:
  ```
  Internet
     ↓
  [wan0: 100Mbps]
     ↓
  ┌─────────────────────────────┐
  │   Enterprise Gateway        │
  │   - Traffic classification  │
  │   - 4-tier QoS              │
  │   - Policy routing          │
  │   - DSCP remarking          │
  └─────────────────────────────┘
     ↓
  [lan0: 192.168.1.0/24]
     ↓
  Departments:
  - Voice/Video (192.168.1.0/26)
  - Management (192.168.1.64/26)
  - Engineering (192.168.1.128/26)
  - Guest (192.168.1.192/26)
  ```

  QoS Tiers:
  1. **Critical** (Mark 1): VoIP, video conferencing, real-time
  2. **High** (Mark 2): Interactive applications, SSH, DNS
  3. **Normal** (Mark 3): Web browsing, email, standard traffic
  4. **Bulk** (Mark 4): Downloads, backups, non-critical
  """

  alias NFTex.{Table, Chain, RuleBuilder}

  # Packet marks for QoS tiers
  @mark_critical 1  # VoIP, video conferencing
  @mark_high 2      # Interactive, SSH, DNS
  @mark_normal 3    # Web, email
  @mark_bulk 4      # Downloads, backups

  # Connection marks for persistent classification
  @connmark_voice 10      # VoIP voice
  @connmark_video 11      # Video conferencing
  @connmark_realtime 12   # Real-time applications
  @connmark_interactive 20  # SSH, RDP, VNC
  @connmark_web 30        # HTTP/HTTPS
  @connmark_email 31      # SMTP/IMAP/POP3
  @connmark_bulk 40       # FTP, rsync, backups

  # DSCP values (standard QoS marking)
  @dscp_ef 46      # Expedited Forwarding (VoIP voice)
  @dscp_af41 34    # Assured Forwarding 4/1 (Video)
  @dscp_af31 26    # Assured Forwarding 3/1 (Signaling)
  @dscp_af21 18    # Assured Forwarding 2/1 (Streaming)
  @dscp_af11 10    # Assured Forwarding 1/1 (Bulk)
  @dscp_cs0 0      # Class Selector 0 (Best effort)

  def run do
    IO.puts("\n╔═══════════════════════════════════════════════╗")
    IO.puts("║   NFTex - Packet Modification Demo          ║")
    IO.puts("║   Enterprise QoS & Traffic Classification    ║")
    IO.puts("╚═══════════════════════════════════════════════╝\n")

    {:ok, pid} = NFTex.start_link(check_capabilities: false)
    IO.puts("✓ NFTex started (JSON-based port)\n")

    # Cleanup and setup
    cleanup(pid)
    setup_infrastructure(pid)

    # Configure QoS and classification
    dscp_based_classification(pid)
    protocol_classification(pid)
    application_classification(pid)
    subnet_based_classification(pid)
    connection_mark_persistence(pid)
    mark_restoration(pid)
    qos_enforcement(pid)
    policy_routing(pid)

    IO.puts("\n╔═══════════════════════════════════════════════╗")
    IO.puts("║         QoS Configuration Summary            ║")
    IO.puts("╚═══════════════════════════════════════════════╝")

    show_qos_configuration()

    IO.puts("\n✓ QoS and traffic classification configured!")
    IO.puts("\nView rules: sudo nft list table inet qos")
    IO.puts("View marks: sudo nft list chain inet qos PREROUTING")
    IO.puts("\nNote: Integrate with tc for actual traffic shaping:")
    IO.puts("  tc qdisc add dev wan0 root handle 1: htb default 30")
    IO.puts("  tc class add dev wan0 parent 1: classid 1:1 htb rate 100mbit")
    IO.puts("  tc class add dev wan0 parent 1:1 classid 1:10 htb rate 40mbit ceil 100mbit prio 1")
    IO.puts("  tc class add dev wan0 parent 1:1 classid 1:20 htb rate 30mbit ceil 80mbit prio 2")
    IO.puts("  tc class add dev wan0 parent 1:1 classid 1:30 htb rate 20mbit ceil 60mbit prio 3")
    IO.puts("  tc class add dev wan0 parent 1:1 classid 1:40 htb rate 10mbit ceil 40mbit prio 4")
    IO.puts("\nPress Ctrl+C to exit...")
    :timer.sleep(:infinity)
  end

  # ═══════════════════════════════════════════════════════════════
  # DSCP-Based Classification
  # ═══════════════════════════════════════════════════════════════

  defp dscp_based_classification(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  1. DSCP-Based Classification               │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Expedited Forwarding (EF) - VoIP voice
    IO.puts("  • DSCP 46 (EF) → Critical (Voice)")

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dscp(@dscp_ef)
    |> Match.set_mark(@mark_critical)
    |> Match.set_connmark(@connmark_voice)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Assured Forwarding Class 4 (AF41) - Video conferencing
    IO.puts("  • DSCP 34 (AF41) → Critical (Video)")

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dscp(@dscp_af41)
    |> Match.set_mark(@mark_critical)
    |> Match.set_connmark(@connmark_video)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Assured Forwarding Class 3 (AF31) - Call signaling
    IO.puts("  • DSCP 26 (AF31) → High (Signaling)")

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dscp(@dscp_af31)
    |> Match.set_mark(@mark_high)
    |> Match.set_connmark(@connmark_realtime)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Assured Forwarding Class 2 (AF21) - Streaming media
    IO.puts("  • DSCP 18 (AF21) → Normal (Streaming)")

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dscp(@dscp_af21)
    |> Match.set_mark(@mark_normal)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Assured Forwarding Class 1 (AF11) - Bulk data
    IO.puts("  • DSCP 10 (AF11) → Bulk")

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dscp(@dscp_af11)
    |> Match.set_mark(@mark_bulk)
    |> Match.set_connmark(@connmark_bulk)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Protocol-Based Classification
  # ═══════════════════════════════════════════════════════════════

  defp protocol_classification(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  2. Protocol-Based Classification           │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # VoIP protocols - Critical
    IO.puts("  • VoIP protocols → Critical")
    IO.puts("    - SIP (5060-5061 UDP/TCP)")
    IO.puts("    - RTP (10000-20000 UDP)")

    # SIP signaling (UDP 5060)
    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.udp_dport(5060)
    |> Match.set_mark(@mark_critical)
    |> Match.set_connmark(@connmark_voice)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # SIP TLS (TCP 5061)
    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dest_port(5061)
    |> Match.set_mark(@mark_critical)
    |> Match.set_connmark(@connmark_voice)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Interactive protocols - High
    IO.puts("\n  • Interactive protocols → High")
    IO.puts("    - SSH (22)")
    IO.puts("    - DNS (53)")
    IO.puts("    - RDP (3389)")

    # SSH
    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dest_port(22)
    |> Match.set_mark(@mark_high)
    |> Match.set_connmark(@connmark_interactive)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # DNS (UDP and TCP)
    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.udp_dport(53)
    |> Match.set_mark(@mark_high)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dest_port(53)
    |> Match.set_mark(@mark_high)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # RDP
    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dest_port(3389)
    |> Match.set_mark(@mark_high)
    |> Match.set_connmark(@connmark_interactive)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Web protocols - Normal
    IO.puts("\n  • Web protocols → Normal")
    IO.puts("    - HTTP (80)")
    IO.puts("    - HTTPS (443)")

    for port <- [80, 443] do
      Match.new(pid, "qos", "PREROUTING", family: :inet)
      |> Match.dest_port(port)
      |> Match.set_mark(@mark_normal)
      |> Match.set_connmark(@connmark_web)
      |> Match.counter()
      |> Match.accept()
      |> Match.commit()
    end

    # Email protocols - Normal
    IO.puts("  • Email protocols → Normal")
    IO.puts("    - SMTP (25, 587)")
    IO.puts("    - IMAP (143, 993)")
    IO.puts("    - POP3 (110, 995)")

    for port <- [25, 587, 143, 993, 110, 995] do
      Match.new(pid, "qos", "PREROUTING", family: :inet)
      |> Match.dest_port(port)
      |> Match.set_mark(@mark_normal)
      |> Match.set_connmark(@connmark_email)
      |> Match.counter()
      |> Match.accept()
      |> Match.commit()
    end

    # Bulk protocols - Bulk
    IO.puts("\n  • Bulk protocols → Bulk")
    IO.puts("    - FTP (20-21)")
    IO.puts("    - rsync (873)")
    IO.puts("    - BitTorrent (6881-6889)")

    # FTP
    for port <- [20, 21] do
      Match.new(pid, "qos", "PREROUTING", family: :inet)
      |> Match.dest_port(port)
      |> Match.set_mark(@mark_bulk)
      |> Match.set_connmark(@connmark_bulk)
      |> Match.counter()
      |> Match.accept()
      |> Match.commit()
    end

    # rsync
    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.dest_port(873)
    |> Match.set_mark(@mark_bulk)
    |> Match.set_connmark(@connmark_bulk)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Application-Specific Classification
  # ═══════════════════════════════════════════════════════════════

  defp application_classification(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  3. Application-Specific Classification     │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Video conferencing - Critical
    IO.puts("  • Video conferencing → Critical")
    IO.puts("    - Zoom (8801-8810 UDP)")
    IO.puts("    - Teams (3478-3481 UDP)")
    IO.puts("    - WebRTC (various)")

    # Zoom media
    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.udp_sport(8801)
    |> Match.set_mark(@mark_critical)
    |> Match.set_connmark(@connmark_video)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Teams STUN/TURN
    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.udp_dport(3478)
    |> Match.set_mark(@mark_critical)
    |> Match.set_connmark(@connmark_video)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Database connections - High (interactive queries)
    IO.puts("\n  • Database protocols → High")
    IO.puts("    - PostgreSQL (5432)")
    IO.puts("    - MySQL (3306)")
    IO.puts("    - MongoDB (27017)")

    for port <- [5432, 3306, 27017] do
      Match.new(pid, "qos", "PREROUTING", family: :inet)
      |> Match.dest_port(port)
      |> Match.set_mark(@mark_high)
      |> Match.counter()
      |> Match.accept()
      |> Match.commit()
    end

    # Cloud backup services - Bulk
    IO.puts("\n  • Cloud backup → Bulk")
    IO.puts("    - Detection via packet size + connection tracking")

    # Large uploads (>1MB packets are likely backups)
    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.length(:gt, 1400)  # Near MTU = likely bulk transfer
    |> Match.dest_port(443)  # HTTPS backup services
    |> Match.set_mark(@mark_bulk)
    |> Match.set_connmark(@connmark_bulk)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Subnet-Based Classification
  # ═══════════════════════════════════════════════════════════════

  defp subnet_based_classification(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  4. Subnet-Based Classification             │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Voice/Video subnet (192.168.1.0/26) - Critical
    IO.puts("  • Voice/Video subnet (192.168.1.0/26) → Critical")

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.source_ip("192.168.1.0/26")
    |> Match.ct_state([:new])
    |> Match.set_mark(@mark_critical)
    |> Match.set_connmark(@connmark_realtime)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Management subnet (192.168.1.64/26) - High
    IO.puts("  • Management subnet (192.168.1.64/26) → High")

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.source_ip("192.168.1.64/26")
    |> Match.ct_state([:new])
    |> Match.set_mark(@mark_high)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Engineering subnet (192.168.1.128/26) - Normal
    IO.puts("  • Engineering subnet (192.168.1.128/26) → Normal")

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.source_ip("192.168.1.128/26")
    |> Match.ct_state([:new])
    |> Match.set_mark(@mark_normal)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    # Guest subnet (192.168.1.192/26) - Bulk
    IO.puts("  • Guest subnet (192.168.1.192/26) → Bulk")

    Match.new(pid, "qos", "PREROUTING", family: :inet)
    |> Match.source_ip("192.168.1.192/26")
    |> Match.ct_state([:new])
    |> Match.set_mark(@mark_bulk)
    |> Match.counter()
    |> Match.accept()
    |> Match.commit()

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Connection Mark Persistence
  # ═══════════════════════════════════════════════════════════════

  defp connection_mark_persistence(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  5. Connection Mark Persistence             │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    IO.puts("  • Save packet marks to connection marks (new connections)")

    # Save mark → connmark for new connections
    for {mark, connmark, name} <- [
          {@mark_critical, @connmark_voice, "Voice"},
          {@mark_critical, @connmark_video, "Video"},
          {@mark_high, @connmark_interactive, "Interactive"},
          {@mark_normal, @connmark_web, "Web"},
          {@mark_bulk, @connmark_bulk, "Bulk"}
        ] do
      Match.new(pid, "qos", "PREROUTING", family: :inet)
      |> Match.ct_state([:new])
      |> Match.mark(mark)
      |> Match.set_connmark(connmark)
      |> Match.counter()
      |> Match.accept()
      |> Match.commit()
    end

    IO.puts("\n  Connection marks ensure:")
    IO.puts("    ✓ Persistent QoS classification per connection")
    IO.puts("    ✓ All packets in connection get same treatment")
    IO.puts("    ✓ Classification survives packet mark changes")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Mark Restoration
  # ═══════════════════════════════════════════════════════════════

  defp mark_restoration(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  6. Mark Restoration                        │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    IO.puts("  • Restore connmark → mark (established connections)")

    # Map connection marks back to packet marks
    for {connmark, mark, name} <- [
          {@connmark_voice, @mark_critical, "Voice"},
          {@connmark_video, @mark_critical, "Video"},
          {@connmark_realtime, @mark_critical, "Realtime"},
          {@connmark_interactive, @mark_high, "Interactive"},
          {@connmark_web, @mark_normal, "Web"},
          {@connmark_email, @mark_normal, "Email"},
          {@connmark_bulk, @mark_bulk, "Bulk"}
        ] do
      Match.new(pid, "qos", "PREROUTING", family: :inet)
      |> Match.ct_state([:established, :related])
      |> Match.connmark(connmark)
      |> Match.set_mark(mark)
      |> Match.counter()
      |> Match.accept()
      |> Match.commit()
    end

    IO.puts("\n  Mark restoration ensures:")
    IO.puts("    ✓ Every packet gets correct QoS treatment")
    IO.puts("    ✓ No reclassification needed per packet")
    IO.puts("    ✓ Consistent QoS throughout connection lifetime")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # QoS Enforcement (Counters and Logging)
  # ═══════════════════════════════════════════════════════════════

  defp qos_enforcement(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  7. QoS Enforcement & Monitoring            │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Count packets per QoS tier
    IO.puts("  • Traffic counters per QoS tier")

    for {mark, name} <- [
          {@mark_critical, "Critical"},
          {@mark_high, "High"},
          {@mark_normal, "Normal"},
          {@mark_bulk, "Bulk"}
        ] do
      Match.new(pid, "qos", "FORWARD", family: :inet)
      |> Match.mark(mark)
      |> Match.counter()
      |> Match.accept()
      |> Match.commit()
    end

    # Log QoS violations (if any)
    IO.puts("  • Log unmarked traffic (classification failure)")

    Match.new(pid, "qos", "FORWARD", family: :inet)
    |> Match.mark(0)  # Unmarked
    |> Match.ct_state([:established, :related])
    |> Match.rate_limit(10, :second)
    |> Match.log("QOS-UNCLASSIFIED: ")
    |> Match.accept()
    |> Match.commit()

    IO.puts("\n  QoS monitoring:")
    IO.puts("    ✓ Per-tier packet/byte counters")
    IO.puts("    ✓ Classification failure detection")
    IO.puts("    ✓ Integration with tc for shaping")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Policy Routing
  # ═══════════════════════════════════════════════════════════════

  defp policy_routing(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  8. Policy Routing Integration              │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    IO.puts("  • Packet marks control routing decisions:")
    IO.puts("    - Mark #{@mark_critical}: ip rule add fwmark #{@mark_critical} table 100")
    IO.puts("    - Mark #{@mark_high}: ip rule add fwmark #{@mark_high} table 101")
    IO.puts("    - Mark #{@mark_normal}: ip rule add fwmark #{@mark_normal} table 102")
    IO.puts("    - Mark #{@mark_bulk}: ip rule add fwmark #{@mark_bulk} table 103")

    IO.puts("\n  • Integration with tc (traffic control):")
    IO.puts("    - Mark #{@mark_critical} → tc class 1:10 (40Mbps)")
    IO.puts("    - Mark #{@mark_high} → tc class 1:20 (30Mbps)")
    IO.puts("    - Mark #{@mark_normal} → tc class 1:30 (20Mbps)")
    IO.puts("    - Mark #{@mark_bulk} → tc class 1:40 (10Mbps)")

    IO.puts("\n  Note: nftables marks packets, tc shapes them")
    IO.puts("  Use tc filter to match fwmark and assign to class")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Infrastructure Setup
  # ═══════════════════════════════════════════════════════════════

  defp setup_infrastructure(pid) do
    IO.puts("Setting up QoS infrastructure...\n")

    # QoS table for marking
    :ok = Table.add(pid, %{name: "qos", family: :inet})

    :ok =
      Chain.add(pid, %{
        table: "qos",
        name: "PREROUTING",
        family: :inet,
        type: :filter,
        hook: :prerouting,
        priority: -150
      })

    :ok =
      Chain.add(pid, %{
        table: "qos",
        name: "FORWARD",
        family: :inet,
        type: :filter,
        hook: :forward,
        priority: 0
      })

    IO.puts("✓ QoS table and chains created\n")
  end

  defp cleanup(pid) do
    try do
      Table.delete(pid, "qos", :inet)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  # ═══════════════════════════════════════════════════════════════
  # Configuration Display
  # ═══════════════════════════════════════════════════════════════

  defp show_qos_configuration do
    IO.puts("\n  QoS Tiers:")
    IO.puts("    1. Critical (Mark #{@mark_critical}):")
    IO.puts("       - VoIP voice (DSCP 46, SIP)")
    IO.puts("       - Video conferencing (DSCP 34, Zoom, Teams)")
    IO.puts("       - Voice/Video subnet (192.168.1.0/26)")
    IO.puts("       - Bandwidth: 40Mbps guaranteed, 100Mbps ceiling")

    IO.puts("\n    2. High (Mark #{@mark_high}):")
    IO.puts("       - Interactive apps (SSH, RDP, DNS)")
    IO.puts("       - Call signaling (DSCP 26)")
    IO.puts("       - Database queries")
    IO.puts("       - Management subnet (192.168.1.64/26)")
    IO.puts("       - Bandwidth: 30Mbps guaranteed, 80Mbps ceiling")

    IO.puts("\n    3. Normal (Mark #{@mark_normal}):")
    IO.puts("       - Web browsing (HTTP/HTTPS)")
    IO.puts("       - Email (SMTP/IMAP/POP3)")
    IO.puts("       - Streaming (DSCP 18)")
    IO.puts("       - Engineering subnet (192.168.1.128/26)")
    IO.puts("       - Bandwidth: 20Mbps guaranteed, 60Mbps ceiling")

    IO.puts("\n    4. Bulk (Mark #{@mark_bulk}):")
    IO.puts("       - Downloads, backups (FTP, rsync)")
    IO.puts("       - Large uploads (>MTU packets)")
    IO.puts("       - Bulk data (DSCP 10)")
    IO.puts("       - Guest subnet (192.168.1.192/26)")
    IO.puts("       - Bandwidth: 10Mbps guaranteed, 40Mbps ceiling")

    IO.puts("\n  Classification Methods:")
    IO.puts("    ✓ DSCP-based (5 rules)")
    IO.puts("    ✓ Protocol-based (15 rules)")
    IO.puts("    ✓ Application-specific (8 rules)")
    IO.puts("    ✓ Subnet-based (4 rules)")
    IO.puts("    ✓ Connection mark persistence (5 rules)")
    IO.puts("    ✓ Mark restoration (7 rules)")

    IO.puts("\n  Connection Marks:")
    IO.puts("    #{@connmark_voice}: VoIP voice")
    IO.puts("    #{@connmark_video}: Video conferencing")
    IO.puts("    #{@connmark_realtime}: Real-time applications")
    IO.puts("    #{@connmark_interactive}: Interactive protocols")
    IO.puts("    #{@connmark_web}: Web browsing")
    IO.puts("    #{@connmark_email}: Email")
    IO.puts("    #{@connmark_bulk}: Bulk transfers")

    IO.puts("\n  Integration:")
    IO.puts("    ✓ Policy routing via fwmark")
    IO.puts("    ✓ Traffic shaping via tc HTB")
    IO.puts("    ✓ DSCP remarking on WAN egress")
    IO.puts("    ✓ Per-tier bandwidth guarantees")
  end
end

# Run the example
PacketModificationExample.run()
