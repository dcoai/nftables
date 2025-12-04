defmodule NFTables.NATTest do
  use ExUnit.Case, async: false
  require Logger

  @moduletag :integration
  @moduletag :nat
  @moduletag :slow

  alias NFTables.{Builder, NAT}
  import NFTables.QueryHelpers

  setup do
    # Start NFTables
    {:ok, pid} = NFTables.Port.start_link(port: NFTables.Port, check_capabilities: false)

    # Clean up any existing test tables
    cleanup_tables(pid)

    # Create NAT table and chains using Builder
        NFTables.add(table: "nftables_test_nat", family: :inet)
    |> NFTables.add(
      table: "nftables_test_nat",
      chain: "prerouting",
      family: :inet
    )
    |> NFTables.add(
      table: "nftables_test_nat",
      chain: "postrouting",
      family: :inet
    )
    |> NFTables.submit(pid: pid)

    on_exit(fn ->
      if Process.alive?(pid) do
        cleanup_tables(pid)
        NFTables.Port.stop(pid)
      end
    end)

    {:ok, pid: pid}
  end

  describe "masquerade/2" do
    test "sets up masquerade on interface", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.setup_masquerade("eth0", table: "nftables_test_nat")
        |> NFTables.submit(pid: pid)

      assert :ok = result

      # Verify rule was created
      {:ok, rules} = list_rules(pid, "nftables_test_nat", "postrouting", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "port_forward/5" do
    test "creates port forwarding rule", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.port_forward(80, "192.168.1.100", 8080, table: "nftables_test_nat")
        |> NFTables.submit(pid: pid)

      assert :ok = result

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end

    test "supports UDP protocol", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.port_forward(53, "192.168.1.1", 53,
          protocol: :udp,
          table: "nftables_test_nat"
        )
        |> NFTables.submit(pid: pid)

      assert :ok = result

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end

    test "supports interface filtering", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.port_forward(22, "192.168.1.10", 22,
          interface: "wan0",
          table: "nftables_test_nat"
        )
        |> NFTables.submit(pid: pid)

      assert :ok = result

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "static_nat/4" do
    test "creates bidirectional NAT", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.static_nat("203.0.113.1", "192.168.1.100", table: "nftables_test_nat")
        |> NFTables.submit(pid: pid)

      assert :ok = result

      # Should create rules in both directions
      {:ok, pre_rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      {:ok, post_rules} = list_rules(pid, "nftables_test_nat", "postrouting", family: :inet)

      assert length(pre_rules) > 0
      assert length(post_rules) > 0
    end
  end

  describe "source_nat/4" do
    test "creates SNAT rule", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.source_nat("192.168.1.0/24", "203.0.113.1", table: "nftables_test_nat")
        |> NFTables.submit(pid: pid)

      assert :ok = result

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "postrouting", family: :inet)
      assert length(rules) > 0
    end

    test "supports single IP", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.source_nat("192.168.1.100", "203.0.113.1", table: "nftables_test_nat")
        |> NFTables.submit(pid: pid)

      assert :ok = result

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "postrouting", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "destination_nat/4" do
    test "creates DNAT rule", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.destination_nat("203.0.113.1", "192.168.1.100", table: "nftables_test_nat")
        |> NFTables.submit(pid: pid)

      assert :ok = result

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "redirect_port/4" do
    test "creates port redirect rule", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.redirect_port(80, 3128, table: "nftables_test_nat")
        |> NFTables.submit(pid: pid)

      assert :ok = result

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end

    test "supports UDP protocol", %{pid: pid} do
      result =
        Builder.new()
        |> NAT.redirect_port(53, 5353, protocol: :udp, table: "nftables_test_nat")
        |> NFTables.submit(pid: pid)

      assert :ok = result

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end
  end

  # Helper functions

  defp cleanup_tables(pid) do
    try do
            NFTables.delete(table: "nftables_test_nat", family: :inet)
      |> NFTables.submit(pid: pid)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end
end
