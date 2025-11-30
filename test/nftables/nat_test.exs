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
    {:ok, pid} = NFTables.start_link(port: NFTables.Port, check_capabilities: false)

    # Clean up any existing test tables
    cleanup_tables(pid)

    # Create NAT table and chains using Builder
    Builder.new()
    |> Builder.add(table: "nftables_test_nat", family: :inet)
    |> Builder.add(
      table: "nftables_test_nat",
      chain: "prerouting",
      family: :inet
    )
    |> Builder.add(
      table: "nftables_test_nat",
      chain: "postrouting",
      family: :inet
    )
    |> Builder.execute(pid)

    on_exit(fn ->
      if Process.alive?(pid) do
        cleanup_tables(pid)
        NFTables.stop(pid)
      end
    end)

    {:ok, pid: pid}
  end

  describe "masquerade/2" do
    test "sets up masquerade on interface", %{pid: pid} do
      assert :ok = NAT.setup_masquerade(pid, "eth0", table: "nftables_test_nat")

      # Verify rule was created
      {:ok, rules} = list_rules(pid, "nftables_test_nat", "postrouting", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "port_forward/5" do
    test "creates port forwarding rule", %{pid: pid} do
      assert :ok = NAT.port_forward(pid, 80, "192.168.1.100", 8080, table: "nftables_test_nat")

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end

    test "supports UDP protocol", %{pid: pid} do
      assert :ok =
               NAT.port_forward(pid, 53, "192.168.1.1", 53,
                 protocol: :udp,
                 table: "nftables_test_nat"
               )

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end

    test "supports interface filtering", %{pid: pid} do
      assert :ok =
               NAT.port_forward(pid, 22, "192.168.1.10", 22,
                 interface: "wan0",
                 table: "nftables_test_nat"
               )

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "static_nat/4" do
    test "creates bidirectional NAT", %{pid: pid} do
      assert :ok = NAT.static_nat(pid, "203.0.113.1", "192.168.1.100", table: "nftables_test_nat")

      # Should create rules in both directions
      {:ok, pre_rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      {:ok, post_rules} = list_rules(pid, "nftables_test_nat", "postrouting", family: :inet)

      assert length(pre_rules) > 0
      assert length(post_rules) > 0
    end
  end

  describe "source_nat/4" do
    test "creates SNAT rule", %{pid: pid} do
      assert :ok = NAT.source_nat(pid, "192.168.1.0/24", "203.0.113.1", table: "nftables_test_nat")

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "postrouting", family: :inet)
      assert length(rules) > 0
    end

    test "supports single IP", %{pid: pid} do
      assert :ok = NAT.source_nat(pid, "192.168.1.100", "203.0.113.1", table: "nftables_test_nat")

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "postrouting", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "destination_nat/4" do
    test "creates DNAT rule", %{pid: pid} do
      assert :ok = NAT.destination_nat(pid, "203.0.113.1", "192.168.1.100", table: "nftables_test_nat")

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "redirect_port/4" do
    test "creates port redirect rule", %{pid: pid} do
      assert :ok = NAT.redirect_port(pid, 80, 3128, table: "nftables_test_nat")

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end

    test "supports UDP protocol", %{pid: pid} do
      assert :ok = NAT.redirect_port(pid, 53, 5353, protocol: :udp, table: "nftables_test_nat")

      {:ok, rules} = list_rules(pid, "nftables_test_nat", "prerouting", family: :inet)
      assert length(rules) > 0
    end
  end

  # Helper functions

  defp cleanup_tables(pid) do
    try do
      Builder.new()
      |> Builder.delete(table: "nftables_test_nat", family: :inet)
      |> Builder.execute(pid)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end
end
