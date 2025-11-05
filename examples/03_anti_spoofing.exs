#!/usr/bin/env elixir

# Anti-Spoofing Example
#
# This example demonstrates anti-spoofing techniques:
# - Reverse Path Filtering (RPF) using FIB expression
# - Bogon filtering (invalid/reserved IP addresses)
# - Martian packet detection
# - Private network filtering on WAN interface
#
# Usage:
#   mix run examples/03_anti_spoofing.exs
#
# Requirements:
#   - Root privileges (CAP_NET_ADMIN)

Mix.install([{:nftex, path: "."}])

defmodule AntiSpoofing do
  @moduledoc """
  Anti-spoofing firewall rules to prevent IP address spoofing attacks.
  """

  alias NFTex.{Table, Chain, RuleBuilder, ExpressionBuilder}
  alias NFTex.Port

  @wan_interface "eth0"

  # Bogon addresses (should never appear on public internet)
  @bogon_networks [
    # Private networks (RFC 1918)
    {<<10, 0, 0, 0>>, <<255, 0, 0, 0>>},           # 10.0.0.0/8
    {<<172, 16, 0, 0>>, <<255, 240, 0, 0>>},       # 172.16.0.0/12
    {<<192, 168, 0, 0>>, <<255, 255, 0, 0>>},      # 192.168.0.0/16

    # Loopback (RFC 1122)
    {<<127, 0, 0, 0>>, <<255, 0, 0, 0>>},          # 127.0.0.0/8

    # Link-local (RFC 3927)
    {<<169, 254, 0, 0>>, <<255, 255, 0, 0>>},      # 169.254.0.0/16

    # Multicast (RFC 5771)
    {<<224, 0, 0, 0>>, <<240, 0, 0, 0>>},          # 224.0.0.0/4

    # Reserved (RFC 6890)
    {<<240, 0, 0, 0>>, <<240, 0, 0, 0>>},          # 240.0.0.0/4

    # Broadcast
    {<<255, 255, 255, 255>>, <<255, 255, 255, 255>>}  # 255.255.255.255/32
  ]

  def run do
    IO.puts("Setting up Anti-Spoofing Firewall...")
    IO.puts("WAN interface: #{@wan_interface}")
    IO.puts("")

    case get_confirmation() do
      true -> setup_anti_spoofing()
      false -> IO.puts("Cancelled.")
    end
  end

  defp get_confirmation do
    IO.write("Continue? [y/N]: ")
    response = IO.gets("") |> String.trim() |> String.downcase()
    response == "y"
  end

  defp setup_anti_spoofing do
    {:ok, pid} = NFTex.start_link()
    IO.puts("✓ NFTex started")

    # Clean existing filter table
    case Table.delete(pid, "filter", :inet) do
      :ok -> IO.puts("✓ Removed existing filter table")
      {:error, _} -> :ok
    end

    # Create filter table
    :ok = Table.create(pid, %{name: "filter", family: :inet})
    IO.puts("✓ Created filter table")

    # Create PREROUTING chain for early filtering
    :ok = Chain.create(pid, %{
      table: "filter",
      name: "PREROUTING",
      family: :inet,
      type: :filter,
      hook: :prerouting,
      priority: -300,  # Very early in the chain
      policy: :accept
    })
    IO.puts("✓ Created PREROUTING chain")

    # Setup anti-spoofing rules
    setup_reverse_path_filter(pid)
    setup_bogon_filter(pid)
    setup_martian_filter(pid)

    IO.puts("\n✓ Anti-spoofing firewall setup complete!")
    IO.puts("\nTo view rules:")
    IO.puts("  sudo nft list table inet filter")
  end

  defp setup_reverse_path_filter(pid) do
    IO.puts("\n=== Setting up Reverse Path Filter (RPF) ===")
    IO.puts("Purpose: Drop packets with source IPs that couldn't have arrived on this interface")

    # Use FIB (Forwarding Information Base) to check if the source IP
    # could legitimately arrive on the input interface
    with {:ok, rule_id} <- Port.call(pid, {:rule_alloc}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :table, "filter"}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :chain, "PREROUTING"}),
         :ok <- Port.call(pid, {:rule_set_u32, rule_id, :family, 2}),

         # Get expected output interface for source IP
         # FIB lookup: "Which interface would we use to reach this source IP?"
         {:ok, fib_id} <- ExpressionBuilder.fib(pid, 1, :oif, [:saddr, :iif]),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, fib_id}),

         # Load actual input interface
         {:ok, meta_id} <- ExpressionBuilder.meta_iif(pid, 2),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, meta_id}),

         # Compare: if expected != actual, packet is spoofed
         {:ok, cmp_id} <- ExpressionBuilder.cmp_neq(pid, 1, 2),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_id}),

         # Log spoofed packets
         {:ok, log_id} <- ExpressionBuilder.log(pid, prefix: "RPF-DROP: ", level: :warning),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, log_id}),

         # Drop spoofed packets
         {:ok, verdict_id} <- ExpressionBuilder.verdict_drop(pid),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, verdict_id}),

         :ok <- Port.call(pid, {:rule_send_to_kernel, rule_id, :add}),
         :ok <- Port.call(pid, {:rule_free, rule_id}) do

      IO.puts("✓ RPF: Enabled (strict mode)")
      IO.puts("  Packets with spoofed source IPs will be logged and dropped")
      :ok
    else
      {:error, reason} ->
        IO.puts("✗ Failed to setup RPF: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp setup_bogon_filter(pid) do
    IO.puts("\n=== Setting up Bogon Filter ===")
    IO.puts("Purpose: Drop packets from invalid/reserved IP addresses on WAN")

    count = Enum.reduce(@bogon_networks, 0, fn {network, mask}, acc ->
      case drop_bogon_network(pid, network, mask) do
        :ok -> acc + 1
        _ -> acc
      end
    end)

    IO.puts("✓ Bogon filter: #{count} networks blocked on #{@wan_interface}")
  end

  defp drop_bogon_network(pid, network, mask) do
    with {:ok, rule_id} <- Port.call(pid, {:rule_alloc}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :table, "filter"}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :chain, "PREROUTING"}),
         :ok <- Port.call(pid, {:rule_set_u32, rule_id, :family, 2}),

         # Match WAN interface
         {:ok, meta_id} <- ExpressionBuilder.meta_iifname(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, meta_id}),
         {:ok, cmp_iface_id} <- ExpressionBuilder.cmp_eq(pid, 1, @wan_interface),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_iface_id}),

         # Load source IP
         {:ok, payload_id} <- ExpressionBuilder.payload_ipv4_saddr(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, payload_id}),

         # Apply network mask
         {:ok, bitwise_id} <- ExpressionBuilder.bitwise(pid, 1, 1, 4, :and, mask),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, bitwise_id}),

         # Compare with network address
         {:ok, cmp_id} <- ExpressionBuilder.cmp_eq(pid, 1, network),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_id}),

         # Log bogon packets
         [a, b, c, d] = :binary.bin_to_list(network)
         [ma, mb, mc, md] = :binary.bin_to_list(mask)
         prefix = "BOGON-DROP: #{a}.#{b}.#{c}.#{d}/#{mask_to_cidr(mask)} ",
         {:ok, log_id} <- ExpressionBuilder.log(pid, prefix: prefix, level: :info),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, log_id}),

         # Drop bogon packets
         {:ok, verdict_id} <- ExpressionBuilder.verdict_drop(pid),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, verdict_id}),

         :ok <- Port.call(pid, {:rule_send_to_kernel, rule_id, :add}),
         :ok <- Port.call(pid, {:rule_free, rule_id}) do
      :ok
    else
      {:error, _reason} -> :error
    end
  end

  defp setup_martian_filter(pid) do
    IO.puts("\n=== Setting up Martian Packet Filter ===")
    IO.puts("Purpose: Drop packets with invalid source/destination combinations")

    # Drop packets with source 0.0.0.0
    drop_martian_source(pid, <<0, 0, 0, 0>>, "0.0.0.0")

    # Drop packets with destination 127.0.0.0/8 on non-loopback interfaces
    drop_martian_loopback_external(pid)

    IO.puts("✓ Martian packet filter enabled")
  end

  defp drop_martian_source(pid, ip, description) do
    with {:ok, rule_id} <- Port.call(pid, {:rule_alloc}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :table, "filter"}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :chain, "PREROUTING"}),
         :ok <- Port.call(pid, {:rule_set_u32, rule_id, :family, 2}),

         # Match source IP
         {:ok, payload_id} <- ExpressionBuilder.payload_ipv4_saddr(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, payload_id}),
         {:ok, cmp_id} <- ExpressionBuilder.cmp_eq(pid, 1, ip),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_id}),

         # Log
         {:ok, log_id} <- ExpressionBuilder.log(pid, prefix: "MARTIAN-SRC: #{description} ", level: :info),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, log_id}),

         # Drop
         {:ok, verdict_id} <- ExpressionBuilder.verdict_drop(pid),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, verdict_id}),

         :ok <- Port.call(pid, {:rule_send_to_kernel, rule_id, :add}),
         :ok <- Port.call(pid, {:rule_free, rule_id}) do
      :ok
    end
  end

  defp drop_martian_loopback_external(pid) do
    with {:ok, rule_id} <- Port.call(pid, {:rule_alloc}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :table, "filter"}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :chain, "PREROUTING"}),
         :ok <- Port.call(pid, {:rule_set_u32, rule_id, :family, 2}),

         # Match non-loopback interface
         {:ok, meta_id} <- ExpressionBuilder.meta_iifname(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, meta_id}),
         {:ok, cmp_iface_id} <- ExpressionBuilder.cmp_neq(pid, 1, "lo"),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_iface_id}),

         # Match destination 127.0.0.0/8
         {:ok, payload_id} <- ExpressionBuilder.payload_ipv4_daddr(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, payload_id}),
         {:ok, bitwise_id} <- ExpressionBuilder.bitwise(pid, 1, 1, 4, :and, <<255, 0, 0, 0>>),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, bitwise_id}),
         {:ok, cmp_id} <- ExpressionBuilder.cmp_eq(pid, 1, <<127, 0, 0, 0>>),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_id}),

         # Log
         {:ok, log_id} <- ExpressionBuilder.log(pid, prefix: "MARTIAN-DST: 127.0.0.0/8 on non-lo ", level: :info),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, log_id}),

         # Drop
         {:ok, verdict_id} <- ExpressionBuilder.verdict_drop(pid),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, verdict_id}),

         :ok <- Port.call(pid, {:rule_send_to_kernel, rule_id, :add}),
         :ok <- Port.call(pid, {:rule_free, rule_id}) do
      :ok
    end
  end

  defp mask_to_cidr(mask) do
    mask
    |> :binary.bin_to_list()
    |> Enum.reduce(0, fn byte, acc ->
      acc + count_bits(byte)
    end)
  end

  defp count_bits(0), do: 0
  defp count_bits(byte) do
    byte
    |> Integer.to_string(2)
    |> String.graphemes()
    |> Enum.count(&(&1 == "1"))
  end
end

# Run the example
AntiSpoofing.run()
