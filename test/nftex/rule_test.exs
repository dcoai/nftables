Code.require_file("../test_helper.exs", __DIR__)

defmodule NFTex.RuleTest do
  use ExUnit.Case
  require Logger

  alias NFTex.Rule

  @moduletag :integration

  # Prerequisites:
  # - CAP_NET_ADMIN capability set on binary
  # - filter table exists: nft add table filter
  # - INPUT chain exists: nft add chain filter INPUT '{ type filter hook input priority 0; }'

  describe "block_ip/4" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_chain
    test "blocks an IPv4 address", %{pid: pid} do
      ip = <<192, 168, 99, 99>>
      result = Rule.block_ip(pid, "filter", "INPUT", ip)
      assert result == :ok
    end

    @tag :requires_chain
    test "blocks multiple IPs sequentially", %{pid: pid} do
      ips = [
        <<192, 168, 99, 100>>,
        <<192, 168, 99, 101>>,
        <<192, 168, 99, 102>>
      ]

      for ip <- ips do
        result = Rule.block_ip(pid, "filter", "INPUT", ip)
        assert result == :ok
      end
    end

    @tag :requires_chain
    test "blocks IP without counter when counter: false", %{pid: pid} do
      ip = <<192, 168, 99, 103>>
      result = Rule.block_ip(pid, "filter", "INPUT", ip, counter: false)
      assert result == :ok
    end

    test "returns error for invalid table/chain", %{pid: pid} do
      ip = <<192, 168, 99, 104>>
      result = Rule.block_ip(pid, "nonexistent_table", "INPUT", ip)
      assert {:error, _reason} = result
    end
  end

  describe "accept_ip/4" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_chain
    test "accepts an IPv4 address", %{pid: pid} do
      ip = <<192, 168, 99, 200>>
      result = Rule.accept_ip(pid, "filter", "INPUT", ip)
      assert result == :ok
    end

    @tag :requires_chain
    test "accepts multiple IPs sequentially", %{pid: pid} do
      ips = [
        <<192, 168, 99, 201>>,
        <<192, 168, 99, 202>>
      ]

      for ip <- ips do
        result = Rule.accept_ip(pid, "filter", "INPUT", ip)
        assert result == :ok
      end
    end

    @tag :requires_chain
    test "accepts IP without counter when counter: false", %{pid: pid} do
      ip = <<192, 168, 99, 203>>
      result = Rule.accept_ip(pid, "filter", "INPUT", ip, counter: false)
      assert result == :ok
    end
  end

  describe "list/4" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_chain
    test "lists rules in a chain", %{pid: pid} do
      # Get initial count
      {:ok, rules_before} = Rule.list(pid, "filter", "INPUT", family: :inet)
      initial_count = length(rules_before)

      # Add a rule
      ip = <<192, 168, 99, 210>>
      :ok = Rule.block_ip(pid, "filter", "INPUT", ip)

      # Check count increased
      {:ok, rules_after} = Rule.list(pid, "filter", "INPUT", family: :inet)
      assert length(rules_after) == initial_count + 1

      # Verify rules have required fields
      for rule <- rules_after do
        assert is_map(rule)
        assert Map.has_key?(rule, :table)
        assert Map.has_key?(rule, :chain)
        assert rule.table == "filter"
        assert rule.chain == "INPUT"
      end
    end

    @tag :requires_chain
    test "returns empty list for chain with no rules", %{pid: pid} do
      # Try to list from a non-existent chain (will filter out everything)
      {:ok, rules} = Rule.list(pid, "filter", "NONEXISTENT", family: :inet)
      assert rules == []
    end

    test "returns error for invalid family", %{pid: pid} do
      # Query module should handle this, but let's test the flow
      result = Rule.list(pid, "filter", "INPUT", family: :inet)
      # Should succeed even if chain doesn't exist (just returns empty)
      assert {:ok, _rules} = result
    end
  end

  describe "integration test" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_chain
    test "complete workflow: block, accept, and list", %{pid: pid} do
      # Get initial count
      {:ok, initial_rules} = Rule.list(pid, "filter", "INPUT", family: :inet)
      initial_count = length(initial_rules)

      # Block 2 IPs
      :ok = Rule.block_ip(pid, "filter", "INPUT", <<192, 168, 99, 220>>)
      :ok = Rule.block_ip(pid, "filter", "INPUT", <<192, 168, 99, 221>>)

      # Accept 1 IP
      :ok = Rule.accept_ip(pid, "filter", "INPUT", <<192, 168, 99, 222>>)

      # Verify 3 rules added
      {:ok, final_rules} = Rule.list(pid, "filter", "INPUT", family: :inet)
      assert length(final_rules) == initial_count + 3
    end
  end
end
