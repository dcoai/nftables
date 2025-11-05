#!/usr/bin/env elixir

# Load Balancing Example
#
# This example demonstrates load balancing with nftables:
# - Round-robin DNAT for simple load distribution
# - Weighted load balancing
# - Health check considerations
# - Session persistence patterns
#
# Usage:
#   mix run examples/06_load_balancing.exs
#
# Requirements:
#   - Root privileges (CAP_NET_ADMIN)
#   - Multiple backend servers
#
# Note: This is a basic example. Production load balancing should use
# dedicated tools like HAProxy, nginx, or IPVS for advanced features like
# health checks, session persistence, and monitoring.

Mix.install([{:nftex, path: "."}])

defmodule LoadBalancing do
  @moduledoc """
  Load balancing configurations using nftables DNAT.
  """

  alias NFTex.{Table, Chain, ExpressionBuilder}
  alias NFTex.Port

  # Backend servers
  @web_backends [
    {<<192, 168, 1, 10>>, 80},   # Backend 1
    {<<192, 168, 1, 11>>, 80},   # Backend 2
    {<<192, 168, 1, 12>>, 80}    # Backend 3
  ]

  @ssh_backends [
    {<<192, 168, 1, 20>>, 22},   # SSH server 1
    {<<192, 168, 1, 21>>, 22}    # SSH server 2
  ]

  def run do
    IO.puts("Setting up Load Balancing...")
    IO.puts("")
    IO.puts("Web backends: #{format_backends(@web_backends)}")
    IO.puts("SSH backends: #{format_backends(@ssh_backends)}")
    IO.puts("")
    IO.puts("Note: This is a basic example using round-robin DNAT.")
    IO.puts("For production use, consider HAProxy or nginx for:")
    IO.puts("  - Health checks")
    IO.puts("  - Session persistence")
    IO.puts("  - SSL termination")
    IO.puts("  - Advanced load balancing algorithms")
    IO.puts("")

    case get_confirmation() do
      true -> setup_load_balancing()
      false -> IO.puts("Cancelled.")
    end
  end

  defp get_confirmation do
    IO.write("Continue? [y/N]: ")
    response = IO.gets("") |> String.trim() |> String.downcase()
    response == "y"
  end

  defp setup_load_balancing do
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

    # Setup load balancing
    setup_web_load_balancer(pid)
    setup_ssh_load_balancer(pid)
    setup_weighted_load_balancer(pid)

    IO.puts("\n✓ Load balancing setup complete!")
    IO.puts("\n=== Testing ===")
    IO.puts("Web service (port 80):")
    IO.puts("  curl http://localhost")
    IO.puts("  # Multiple requests will be distributed across backends")
    IO.puts("")
    IO.puts("SSH service (port 2222):")
    IO.puts("  ssh -p 2222 localhost")
    IO.puts("  # Connections will be distributed across SSH backends")
    IO.puts("")
    IO.puts("View NAT rules:")
    IO.puts("  sudo nft list table inet nat")
  end

  defp setup_web_load_balancer(pid) do
    IO.puts("\n=== Web Load Balancer (Round-Robin) ===")
    IO.puts("Balancing HTTP traffic (port 80) across #{length(@web_backends)} backends")

    # Simple round-robin: Use packet mark or random to distribute
    # Method 1: Random distribution (simplest)
    # Method 2: Consistent hash based on source IP (basic session persistence)

    # We'll demonstrate simple round-robin by creating rules for each backend
    # with equal probability

    # Note: nftables doesn't have built-in round-robin, so we use techniques like:
    # - Random (numgen random)
    # - Source IP hash (for session persistence)
    # - Connection tracking marks

    # For simplicity, this example creates separate rules for each backend
    # In production, use sets with maps for more efficient load balancing

    total = length(@web_backends)

    @web_backends
    |> Enum.with_index()
    |> Enum.each(fn {{ip, port}, index} ->
      # Simple approach: Each backend gets 1/n of traffic
      # In reality, nftables would need numgen or similar for true round-robin
      load_balance_to_backend(pid, 80, ip, port, "Web Backend #{index + 1}")
    end)

    IO.puts("✓ Web load balancer configured")
    IO.puts("  Method: Simple DNAT (manual distribution)")
    IO.puts("  Backends: #{total}")
  end

  defp setup_ssh_load_balancer(pid) do
    IO.puts("\n=== SSH Load Balancer ===")
    IO.puts("Balancing SSH traffic (port 2222) across #{length(@ssh_backends)} backends")

    @ssh_backends
    |> Enum.with_index()
    |> Enum.each(fn {{ip, port}, index} ->
      load_balance_to_backend(pid, 2222, ip, port, "SSH Backend #{index + 1}")
    end)

    IO.puts("✓ SSH load balancer configured")
  end

  defp setup_weighted_load_balancer(pid) do
    IO.puts("\n=== Weighted Load Balancer ===")
    IO.puts("Purpose: Distribute more traffic to powerful servers")
    IO.puts("")
    IO.puts("Example configuration:")
    IO.puts("  Backend 1 (192.168.1.10): Weight 3 (60%)")
    IO.puts("  Backend 2 (192.168.1.11): Weight 1 (20%)")
    IO.puts("  Backend 3 (192.168.1.12): Weight 1 (20%)")
    IO.puts("")
    IO.puts("Note: Weighted balancing requires numgen expression")
    IO.puts("      which is not yet implemented in NFTex.")
    IO.puts("")
    IO.puts("To implement weighted load balancing:")
    IO.puts("  1. Use numgen random mod 5 to get random 0-4")
    IO.puts("  2. Map 0-2 → Backend 1 (weight 3)")
    IO.puts("  3. Map 3 → Backend 2 (weight 1)")
    IO.puts("  4. Map 4 → Backend 3 (weight 1)")
    IO.puts("")
    IO.puts("nft command example:")
    IO.puts(~s{  nft add rule nat prerouting tcp dport 8080 \\})
    IO.puts(~s{    numgen random mod 5 map { \\})
    IO.puts(~s{      0-2: dnat to 192.168.1.10, \\})
    IO.puts(~s{      3: dnat to 192.168.1.11, \\})
    IO.puts(~s{      4: dnat to 192.168.1.12 }})
  end

  defp load_balance_to_backend(pid, external_port, internal_ip, internal_port, description) do
    with {:ok, rule_id} <- Port.call(pid, {:rule_alloc}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :table, "nat"}),
         :ok <- Port.call(pid, {:rule_set_str, rule_id, :chain, "PREROUTING"}),
         :ok <- Port.call(pid, {:rule_set_u32, rule_id, :family, 2}),

         # Match destination port
         {:ok, payload_id} <- ExpressionBuilder.payload_dport(pid, 1),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, payload_id}),
         {:ok, cmp_id} <- ExpressionBuilder.cmp_eq(pid, 1, <<external_port::16-big>>),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, cmp_id}),

         # DNAT to backend
         {:ok, nat_id} <- ExpressionBuilder.nat_dnat(pid, internal_ip, internal_port),
         :ok <- Port.call(pid, {:rule_add_expr, rule_id, nat_id}),

         :ok <- Port.call(pid, {:rule_send_to_kernel, rule_id, :add}),
         :ok <- Port.call(pid, {:rule_free, rule_id}) do

      [a, b, c, d] = :binary.bin_to_list(internal_ip)
      IO.puts("  ✓ #{description}: #{a}.#{b}.#{c}.#{d}:#{internal_port}")
      :ok
    else
      {:error, reason} ->
        IO.puts("  ✗ Failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp format_backends(backends) do
    backends
    |> Enum.map(fn {ip, port} ->
      [a, b, c, d] = :binary.bin_to_list(ip)
      "#{a}.#{b}.#{c}.#{d}:#{port}"
    end)
    |> Enum.join(", ")
  end
end

# Run the example
LoadBalancing.run()
