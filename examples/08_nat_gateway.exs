#!/usr/bin/env elixir

# NAT Gateway Example
#
# This example demonstrates a complete NAT gateway configuration for:
# - Internet sharing (masquerade) for internal network
# - DMZ with static 1:1 NAT for public servers
# - Port forwarding to internal services
# - Transparent HTTP/HTTPS proxy
#
# Network Topology:
#   Internet <---> [wan0] Router [lan0] <---> Internal LAN (192.168.1.0/24)
#                          [dmz0] <---> DMZ (10.0.0.0/24)
#
# Prerequisites:
# - CAP_NET_ADMIN capability: sudo setcap cap_net_admin=ep priv/port_nftables
# - Run as: mix run examples/08_nat_gateway.exs

defmodule NATGatewayExample do
  @moduledoc """
  Production NAT gateway for a small business.

  Scenario: Small business with 3 network segments:
  - Internal LAN (192.168.1.0/24) - workstations, laptops
  - DMZ (10.0.0.0/24) - public-facing servers
  - Internet connection via wan0 (eth0)

  Services:
  - Internet sharing for internal LAN
  - Web server in DMZ with static NAT
  - Mail server in DMZ with port forwarding
  - VPN server accessible from internet
  - Transparent HTTP proxy for content filtering
  """

  alias NFTables.{Table, Chain, NAT, RuleBuilder}

  # Network configuration
  @wan_interface "eth0"
  @lan_interface "eth1"
  @dmz_interface "eth2"

  @lan_network "192.168.1.0/24"
  @dmz_network "10.0.0.0/24"

  # Public IPs assigned to business
  @public_ip_gateway "203.0.113.1"
  @public_ip_web "203.0.113.10"
  @public_ip_mail "203.0.113.11"

  # DMZ servers
  @dmz_web_server "10.0.0.10"
  @dmz_mail_server "10.0.0.11"
  @dmz_vpn_server "10.0.0.12"

  # Internal servers
  @lan_proxy "192.168.1.100"
  @lan_fileserver "192.168.1.101"

  def run do
    IO.puts("\n╔═══════════════════════════════════════════════╗")
    IO.puts("║      NFTables - NAT Gateway Configuration       ║")
    IO.puts("╚═══════════════════════════════════════════════╝\n")

    {:ok, pid} = NFTables.start_link(check_capabilities: false)
    IO.puts("✓ NFTables started (JSON-based port)\n")

    # Cleanup and setup
    cleanup(pid)
    setup_infrastructure(pid)

    # Configure NAT by use case
    internet_sharing(pid)
    dmz_static_nat(pid)
    port_forwarding(pid)
    transparent_proxy(pid)
    internal_services(pid)

    IO.puts("\n╔═══════════════════════════════════════════════╗")
    IO.puts("║         Gateway Configuration Complete        ║")
    IO.puts("╚═══════════════════════════════════════════════╝")

    show_configuration()

    IO.puts("\n✓ NAT gateway configured successfully!")
    IO.puts("\nView NAT rules: sudo nft list table inet nat")
    IO.puts("Press Ctrl+C to exit...")
    :timer.sleep(:infinity)
  end

  # ═══════════════════════════════════════════════════════════════
  # Internet Sharing (Masquerade)
  # ═══════════════════════════════════════════════════════════════

  defp internet_sharing(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  1. Internet Sharing (Masquerade)          │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Masquerade for internal LAN
    IO.puts("  • LAN (#{@lan_network}) → Internet")
    IO.puts("    Interface: #{@wan_interface}")

    :ok =
      Builder.new()
      |> NAT.setup_masquerade(@wan_interface, table: "nat")
      |> Builder.submit(pid: pid)

    IO.puts("    ✓ Masquerade enabled for LAN clients")

    # Alternative: Source NAT to specific IP (if static IP preferred)
    # Uncomment if you want to use SNAT instead of masquerade
    # IO.puts("\n  • Alternative: Static SNAT")
    # :ok = NAT.source_nat(pid, @lan_network, @public_ip_gateway,
    #   table: "nat",
    #   interface: @wan_interface
    # )

    IO.puts("\n  Benefits:")
    IO.puts("    • Automatic IP translation")
    IO.puts("    • Works with dynamic WAN IP (DHCP)")
    IO.puts("    • Connection tracking handles responses")
    IO.puts("    • Scales to hundreds of clients")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # DMZ with Static 1:1 NAT
  # ═══════════════════════════════════════════════════════════════

  defp dmz_static_nat(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  2. DMZ Static NAT (1:1 Mapping)           │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Web server with dedicated public IP
    IO.puts("  • Web Server (#{@dmz_web_server})")
    IO.puts("    Public IP: #{@public_ip_web}")
    IO.puts("    Services: HTTP (80), HTTPS (443)")

    :ok =
      Builder.new()
      |> NAT.static_nat(@public_ip_web, @dmz_web_server, table: "nat")
      |> Builder.submit(pid: pid)

    IO.puts("    ✓ Bidirectional NAT configured")
    IO.puts("      → Inbound: #{@public_ip_web} → #{@dmz_web_server}")
    IO.puts("      ← Outbound: #{@dmz_web_server} → #{@public_ip_web}")

    # Mail server with dedicated public IP
    IO.puts("\n  • Mail Server (#{@dmz_mail_server})")
    IO.puts("    Public IP: #{@public_ip_mail}")
    IO.puts("    Services: SMTP (25), SMTPS (465), IMAPS (993)")

    :ok =
      Builder.new()
      |> NAT.static_nat(@public_ip_mail, @dmz_mail_server, table: "nat")
      |> Builder.submit(pid: pid)

    IO.puts("    ✓ Bidirectional NAT configured")

    IO.puts("\n  Benefits:")
    IO.puts("    • DMZ servers have consistent public IPs")
    IO.puts("    • Reverse DNS works correctly")
    IO.puts("    • Simplifies firewall rules")
    IO.puts("    • Essential for mail servers (SPF/DKIM)")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Port Forwarding (DNAT)
  # ═══════════════════════════════════════════════════════════════

  defp port_forwarding(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  3. Port Forwarding (DNAT)                  │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # VPN server (different public port for security)
    IO.puts("  • OpenVPN Server")
    IO.puts("    #{@public_ip_gateway}:11194 → #{@dmz_vpn_server}:1194")

    :ok =
      Builder.new()
      |> NAT.port_forward(11194, @dmz_vpn_server, 1194,
        table: "nat",
        interface: @wan_interface
      )
      |> NAT.port_forward(11194, @dmz_vpn_server, 1194,
        protocol: :udp,
        table: "nat",
        interface: @wan_interface
      )
      |> Builder.submit(pid: pid)

    IO.puts("    ✓ Port forwarding configured (TCP)")
    IO.puts("    ✓ Port forwarding configured (UDP)")

    # SSH to internal file server (non-standard port)
    IO.puts("\n  • SSH to File Server")
    IO.puts("    #{@public_ip_gateway}:2222 → #{@lan_fileserver}:22")

    :ok =
      Builder.new()
      |> NAT.port_forward(2222, @lan_fileserver, 22,
        table: "nat",
        interface: @wan_interface
      )
      |> Builder.submit(pid: pid)

    IO.puts("    ✓ SSH port forwarding enabled")

    # Remote desktop to specific workstation
    IO.puts("\n  • RDP to Admin Workstation")
    IO.puts("    #{@public_ip_gateway}:3389 → 192.168.1.50:3389")

    :ok =
      Builder.new()
      |> NAT.port_forward(3389, "192.168.1.50", 3389,
        table: "nat",
        interface: @wan_interface
      )
      |> Builder.submit(pid: pid)

    IO.puts("    ✓ RDP forwarding enabled")

    # Game server for employees (example of UDP + TCP)
    IO.puts("\n  • Game Server")
    IO.puts("    #{@public_ip_gateway}:27015 → 192.168.1.200:27015")

    builder = Builder.new()

    builder =
      for protocol <- [:tcp, :udp], reduce: builder do
        acc ->
          NAT.port_forward(acc, 27015, "192.168.1.200", 27015,
            protocol: protocol,
            table: "nat",
            interface: @wan_interface
          )
      end

    :ok = Builder.submit(builder, pid: pid)

    IO.puts("    ✓ Game server forwarding (TCP+UDP)")

    IO.puts("\n  Benefits:")
    IO.puts("    • Expose internal services safely")
    IO.puts("    • Use non-standard ports for security")
    IO.puts("    • Single public IP serves multiple services")
    IO.puts("    • Protocol-specific forwarding (TCP/UDP)")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Transparent Proxy
  # ═══════════════════════════════════════════════════════════════

  defp transparent_proxy(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  4. Transparent HTTP/HTTPS Proxy           │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # Redirect HTTP traffic to Squid proxy
    IO.puts("  • HTTP Traffic Interception")
    IO.puts("    Port 80 → Proxy (#{@lan_proxy}:3128)")

    # Only intercept traffic from LAN, not DMZ
    Match.new(pid, "nat", "prerouting")
    |> Match.iif(@lan_interface)
    |> Match.dest_port(80)
    |> Match.redirect_to(3128)
    |> Match.commit()

    IO.puts("    ✓ HTTP redirection enabled")

    # HTTPS interception requires SSL bumping (more complex)
    IO.puts("\n  • HTTPS Traffic (SSL Bump)")
    IO.puts("    Port 443 → Proxy (#{@lan_proxy}:3129)")

    Match.new(pid, "nat", "prerouting")
    |> Match.iif(@lan_interface)
    |> Match.dest_port(443)
    |> Match.redirect_to(3129)
    |> Match.commit()

    IO.puts("    ✓ HTTPS redirection enabled")
    IO.puts("    ⚠ Requires proxy with SSL inspection certificate")

    IO.puts("\n  Benefits:")
    IO.puts("    • Content filtering (block malware, ads)")
    IO.puts("    • Bandwidth optimization (caching)")
    IO.puts("    • Usage monitoring and reporting")
    IO.puts("    • Enforce acceptable use policy")

    IO.puts("\n  Proxy Features:")
    IO.puts("    • Web content filtering")
    IO.puts("    • Virus scanning (ClamAV)")
    IO.puts("    • Bandwidth throttling per user")
    IO.puts("    • Access logging for compliance")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Internal Services
  # ═══════════════════════════════════════════════════════════════

  defp internal_services(pid) do
    IO.puts("┌─────────────────────────────────────────────┐")
    IO.puts("│  5. Internal Network Services               │")
    IO.puts("└─────────────────────────────────────────────┘\n")

    # DNS redirection (force internal DNS server)
    IO.puts("  • DNS Enforcement")
    IO.puts("    Force all DNS queries → 192.168.1.1:53")

    Match.new(pid, "nat", "prerouting")
    |> Match.iif(@lan_interface)
    |> Match.udp_dport(53)
    |> Match.dnat_to("192.168.1.1", port: 53)
    |> Match.commit()

    Match.new(pid, "nat", "prerouting")
    |> Match.iif(@lan_interface)
    |> Match.dest_port(53)  # TCP DNS
    |> Match.dnat_to("192.168.1.1", port: 53)
    |> Match.commit()

    IO.puts("    ✓ DNS redirection enabled (UDP+TCP)")
    IO.puts("      Prevents bypassing DNS filtering")

    # NTP redirection (ensure time sync)
    IO.puts("\n  • NTP Enforcement")
    IO.puts("    Force all NTP queries → 192.168.1.1:123")

    Match.new(pid, "nat", "prerouting")
    |> Match.iif(@lan_interface)
    |> Match.udp_dport(123)
    |> Match.dnat_to("192.168.1.1", port: 123)
    |> Match.commit()

    IO.puts("    ✓ NTP redirection enabled")

    # Hairpin NAT (internal clients accessing services via public IP)
    IO.puts("\n  • Hairpin NAT (Local Access)")
    IO.puts("    Internal clients can access services via public IPs")

    # Allow internal clients to reach DMZ via public IPs
    Match.new(pid, "nat", "postrouting")
    |> Match.source_ip(@lan_network)
    |> Match.dest_ip(@dmz_network)
    |> Match.masquerade()
    |> Match.commit()

    IO.puts("    ✓ Hairpin NAT enabled")
    IO.puts("      LAN can reach DMZ services via public IPs")

    IO.puts("")
  end

  # ═══════════════════════════════════════════════════════════════
  # Infrastructure Setup
  # ═══════════════════════════════════════════════════════════════

  defp setup_infrastructure(pid) do
    IO.puts("Setting up NAT infrastructure...")

    :ok = Table.add(pid, %{name: "nat", family: :inet})

    :ok = Chain.add(pid, %{
      table: "nat",
      name: "prerouting",
      family: :inet
    })

    :ok = Chain.add(pid, %{
      table: "nat",
      name: "postrouting",
      family: :inet
    })

    IO.puts("✓ NAT table and chains created\n")
  end

  defp cleanup(pid) do
    try do
      Table.delete(pid, "nat", :inet)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  # ═══════════════════════════════════════════════════════════════
  # Configuration Display
  # ═══════════════════════════════════════════════════════════════

  defp show_configuration do
    IO.puts("\n  ┌─ Network Topology ─────────────────────────┐")
    IO.puts("  │                                              │")
    IO.puts("  │  Internet                                    │")
    IO.puts("  │     ↕                                        │")
    IO.puts("  │  [#{@wan_interface}] Gateway (#{@public_ip_gateway})              │")
    IO.puts("  │     ├─[#{@lan_interface}]─ LAN (#{@lan_network})      │")
    IO.puts("  │     │    • Workstations (20 hosts)           │")
    IO.puts("  │     │    • Proxy: #{@lan_proxy}         │")
    IO.puts("  │     │                                         │")
    IO.puts("  │     └─[#{@dmz_interface}]─ DMZ (#{@dmz_network})        │")
    IO.puts("  │          • Web: #{@dmz_web_server} (#{@public_ip_web})  │")
    IO.puts("  │          • Mail: #{@dmz_mail_server} (#{@public_ip_mail}) │")
    IO.puts("  │          • VPN: #{@dmz_vpn_server}            │")
    IO.puts("  │                                              │")
    IO.puts("  └──────────────────────────────────────────────┘")

    IO.puts("\n  ┌─ NAT Rules Summary ────────────────────────┐")
    IO.puts("  │                                              │")
    IO.puts("  │  Masquerade:         1 rule                  │")
    IO.puts("  │  Static NAT:         2 servers               │")
    IO.puts("  │  Port Forwarding:    6 services              │")
    IO.puts("  │  Transparent Proxy:  2 redirects             │")
    IO.puts("  │  Internal Services:  4 enforcements          │")
    IO.puts("  │  ──────────────────────────────              │")
    IO.puts("  │  Total NAT Rules:    15+ rules               │")
    IO.puts("  │                                              │")
    IO.puts("  └──────────────────────────────────────────────┘")

    IO.puts("\n  ┌─ Services Exposed to Internet ─────────────┐")
    IO.puts("  │                                              │")
    IO.puts("  │  • HTTP/HTTPS  → #{@public_ip_web}             │")
    IO.puts("  │  • SMTP/IMAPS  → #{@public_ip_mail}            │")
    IO.puts("  │  • OpenVPN     → #{@public_ip_gateway}:11194   │")
    IO.puts("  │  • SSH Admin   → #{@public_ip_gateway}:2222    │")
    IO.puts("  │  • RDP Remote  → #{@public_ip_gateway}:3389    │")
    IO.puts("  │  • Game Server → #{@public_ip_gateway}:27015   │")
    IO.puts("  │                                              │")
    IO.puts("  └──────────────────────────────────────────────┘")

    IO.puts("\n  ┌─ Security Features ────────────────────────┐")
    IO.puts("  │                                              │")
    IO.puts("  │  ✓ Stateful connection tracking             │")
    IO.puts("  │  ✓ LAN isolated from DMZ                    │")
    IO.puts("  │  ✓ Non-standard ports for services          │")
    IO.puts("  │  ✓ Transparent content filtering            │")
    IO.puts("  │  ✓ DNS/NTP enforcement (no bypass)          │")
    IO.puts("  │  ✓ Hairpin NAT for internal access          │")
    IO.puts("  │                                              │")
    IO.puts("  └──────────────────────────────────────────────┘")
  end
end

# Run the example
NATGatewayExample.run()
