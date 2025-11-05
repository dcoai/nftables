#!/usr/bin/env elixir

# NAT Gateway Example
#
# This example demonstrates setting up a NAT gateway for internet sharing:
# - SNAT/Masquerade for internal network
# - Port forwarding (DNAT) for services
# - DMZ setup for exposed servers
#
# Usage:
#   mix run examples/02_nat_gateway.exs
#
# Requirements:
#   - Root privileges (CAP_NET_ADMIN)
#   - Multiple network interfaces (e.g., eth0 = WAN, eth1 = LAN)
#   - IP forwarding enabled: echo 1 > /proc/sys/net/ipv4/ip_forward

Mix.install([{:nftex, path: "."}])

defmodule NATGateway do
  @moduledoc """
  NAT Gateway setup for internet sharing and port forwarding.
  """

  alias NFTex.{Table, Chain, RuleBuilder, ExpressionBuilder}
  alias NFTex.Port

  @wan_interface "eth0"  # Internet-facing interface
  @lan_interface "eth1"  # Local network interface
  @lan_network <<192, 168, 1, 0>>
  @lan_netmask <<255, 255, 255, 0>>

  def run do
    IO.puts("Setting up NAT Gateway...")
    IO.puts("Configuration:")
    IO.puts("  WAN interface: #{@wan_interface}")
    IO.puts("  LAN interface: #{@lan_interface}")
    IO.puts("  LAN network: 192.168.1.0/24")
    IO.puts("")

    case get_confirmation() do
      true -> setup_nat_gateway()
      false -> IO.puts("Cancelled.")
    end
  end

  defp get_confirmation do
    IO.write("Continue? [y/N]: ")
    response = IO.gets("") |> String.trim() |> String.downcase()
    response == "y"
  end

  defp setup_nat_gateway do
    {:ok, pid} = NFTex.start_link()
    IO.puts("✓ NFTex started")

    # Clean existing nat table
    case Table.delete(pid, "nat", :inet) do
      :ok -> IO.puts("✓ Removed existing nat table")
      {:error, _} -> :ok
    end

    # Create NAT table
    :ok = Table.create(pid, %{name: "nat", family: :inet})
    IO.puts("✓ Created nat table")

    # Create POSTROUTING chain for SNAT/Masquerade
    :ok = Chain.create(pid, %{
      table: "nat",
      name: "POSTROUTING",
      family: :inet,
      type: :nat,
      hook: :postrouting,
      priority: 100,
      policy: :accept
    })
    IO.puts("✓ Created POSTROUTING chain")

    # Create PREROUTING chain for DNAT
    :ok = Chain.create(pid, %{
      table: "nat",
      name: "PREROUTING",
      family: :inet,
      type: :nat,
      hook: :prerouting,
      priority: -100,
      policy: :accept
    })
    IO.puts("✓ Created PREROUTING chain")

    # Setup masquerading for LAN
    setup_masquerade(pid)

    # Setup port forwarding examples
    setup_port_forwarding(pid)

    # Setup DMZ
    setup_dmz(pid)

    IO.puts("\n✓ NAT Gateway setup complete!")
    IO.puts("\nTo view NAT rules:")
    IO.puts("  sudo nft list table inet nat")
    IO.puts("\nDon't forget to enable IP forwarding:")
    IO.puts("  echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
  end

  defp setup_masquerade(pid) do
    IO.puts("\n=== Setting up masquerading ===")

    # Masquerade traffic from LAN going out WAN
    # This allows LAN devices to share the internet connection
    with {:ok, rule_id} <- Port.call(pid, {:rule_alloc}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :table, "nat"}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :chain, "POSTROUTING"}),
         :ok <- Port.call(pid, {:rule_set_u32, rule_id, :family, 2}),

         # Match outgoing interface (WAN)
         {:ok, meta_id} <- ExpressionBuilder.meta_oifname(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, meta_id}),
         {:ok, cmp_id} <- ExpressionBuilder.cmp_eq(pid, 1, @wan_interface),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_id}),

         # Masquerade (SNAT with dynamic IP)
         {:ok, nat_id} <- ExpressionBuilder.nat_masquerade(pid),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, nat_id}),

         :ok <- Port.call(pid, {:rule_send_to_kernel, rule_id, :add}),
         :ok <- Port.call(pid, {:rule_free, rule_id}) do

      IO.puts("✓ Masquerade: LAN → WAN (#{@wan_interface})")
      :ok
    else
      {:error, reason} ->
        IO.puts("✗ Failed to setup masquerade: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp setup_port_forwarding(pid) do
    IO.puts("\n=== Setting up port forwarding ===")

    # Example 1: Forward external port 8080 to internal server 192.168.1.10:80 (web server)
    forward_port(pid, 8080, <<192, 168, 1, 10>>, 80, "Web Server")

    # Example 2: Forward external port 2222 to internal server 192.168.1.20:22 (SSH)
    forward_port(pid, 2222, <<192, 168, 1, 20>>, 22, "SSH Server")
  end

  defp forward_port(pid, external_port, internal_ip, internal_port, description) do
    with {:ok, rule_id} <- Port.call(pid, {:rule_alloc}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :table, "nat"}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :chain, "PREROUTING"}),
         :ok <- Port.call(pid, {:rule_set_u32, rule_id, :family, 2}),

         # Match incoming interface (WAN)
         {:ok, meta_id} <- ExpressionBuilder.meta_iifname(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, meta_id}),
         {:ok, cmp_iface_id} <- ExpressionBuilder.cmp_eq(pid, 1, @wan_interface),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_iface_id}),

         # Match destination port
         {:ok, payload_id} <- ExpressionBuilder.payload_dport(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, payload_id}),
         {:ok, cmp_port_id} <- ExpressionBuilder.cmp_eq(pid, 1, <<external_port::16-big>>),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_port_id}),

         # DNAT to internal server
         {:ok, nat_id} <- ExpressionBuilder.nat_dnat(pid, internal_ip, internal_port),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, nat_id}),

         :ok <- Port.call(pid, {:rule_send_to_kernel, rule_id, :add}),
         :ok <- Port.call(pid, {:rule_free, rule_id}) do

      [a, b, c, d] = :binary.bin_to_list(internal_ip)
      IO.puts("✓ Port forward: #{external_port} → #{a}.#{b}.#{c}.#{d}:#{internal_port} (#{description})")
      :ok
    else
      {:error, reason} ->
        IO.puts("✗ Failed to setup port forward: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp setup_dmz(pid) do
    IO.puts("\n=== Setting up DMZ ===")
    IO.puts("DMZ: Expose server 192.168.1.100 to all incoming traffic")

    # DMZ: Forward ALL traffic to a specific internal IP
    dmz_host = <<192, 168, 1, 100>>

    with {:ok, rule_id} <- Port.call(pid, {:rule_alloc}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :table, "nat"}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :chain, "PREROUTING"}),
         :ok <- Port.call(pid, {:rule_set_u32, rule_id, :family, 2}),

         # Match incoming interface (WAN)
         {:ok, meta_id} <- ExpressionBuilder.meta_iifname(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, meta_id}),
         {:ok, cmp_id} <- ExpressionBuilder.cmp_eq(pid, 1, @wan_interface),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_id}),

         # DNAT all traffic to DMZ host
         {:ok, nat_id} <- ExpressionBuilder.nat_dnat_ip(pid, dmz_host),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, nat_id}),

         :ok <- Port.call(pid, {:rule_send_to_kernel, rule_id, :add}),
         :ok <- Port.call(pid, {:rule_free, rule_id}) do

      IO.puts("✓ DMZ: All traffic → 192.168.1.100")
      IO.puts("  Warning: This exposes the server to all incoming connections!")
      :ok
    else
      {:error, reason} ->
        IO.puts("✗ Failed to setup DMZ: #{inspect(reason)}")
        {:error, reason}
    end
  end
end

# Run the example
NATGateway.run()
