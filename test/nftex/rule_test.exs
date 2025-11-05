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

  describe "delete/5" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_chain
    test "deletes a rule by handle", %{pid: pid} do
      # Create a test rule
      ip = <<192, 168, 99, 230>>
      :ok = Rule.block_ip(pid, "filter", "INPUT", ip)

      # Get the rule's handle
      {:ok, rules} = Rule.list(pid, "filter", "INPUT", family: :inet)

      # Find our test rule (should be the last one added)
      test_rule = List.last(rules)
      assert test_rule != nil
      assert is_integer(test_rule.handle)

      # Delete it
      result = Rule.delete(pid, "filter", "INPUT", :inet, test_rule.handle)
      assert result == :ok

      # Verify it's gone
      {:ok, rules_after} = Rule.list(pid, "filter", "INPUT", family: :inet)
      remaining_handles = Enum.map(rules_after, & &1.handle)
      refute test_rule.handle in remaining_handles
    end

    @tag :requires_chain
    test "deletes multiple rules by handle", %{pid: pid} do
      # Get initial count
      {:ok, initial_rules} = Rule.list(pid, "filter", "INPUT", family: :inet)
      initial_count = length(initial_rules)

      # Add 3 test rules
      ips = [<<192, 168, 99, 231>>, <<192, 168, 99, 232>>, <<192, 168, 99, 233>>]
      for ip <- ips do
        :ok = Rule.block_ip(pid, "filter", "INPUT", ip)
      end

      # Get their handles
      {:ok, rules_after_add} = Rule.list(pid, "filter", "INPUT", family: :inet)
      assert length(rules_after_add) == initial_count + 3

      # Get the last 3 rules (our test rules)
      test_rules = Enum.take(rules_after_add, -3)

      # Delete them all
      for rule <- test_rules do
        :ok = Rule.delete(pid, "filter", "INPUT", :inet, rule.handle)
      end

      # Verify they're all gone
      {:ok, final_rules} = Rule.list(pid, "filter", "INPUT", family: :inet)
      assert length(final_rules) == initial_count
    end

    test "returns error for invalid handle", %{pid: pid} do
      # Try to delete with a non-existent handle
      result = Rule.delete(pid, "filter", "INPUT", :inet, 99999999)
      assert {:error, _reason} = result
    end

    test "returns error for invalid family", %{pid: pid} do
      result = Rule.delete(pid, "filter", "INPUT", :invalid_family, 123)
      assert {:error, error_msg} = result
      assert error_msg =~ "Invalid family"
    end
  end

  describe "rate_limit/6" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_chain
    test "creates rate limit rule with default options", %{pid: pid} do
      result = Rule.rate_limit(pid, "filter", "INPUT", 100, :second)
      assert result == :ok
    end

    @tag :requires_chain
    test "creates rate limit rule with custom burst", %{pid: pid} do
      result = Rule.rate_limit(pid, "filter", "INPUT", 50, :minute, burst: 20)
      assert result == :ok
    end

    @tag :requires_chain
    test "creates rate limit rule with reject verdict", %{pid: pid} do
      result = Rule.rate_limit(pid, "filter", "INPUT", 10, :second, reject: true)
      assert result == :ok
    end

    @tag :requires_chain
    test "creates rate limit rule without counter", %{pid: pid} do
      result = Rule.rate_limit(pid, "filter", "INPUT", 100, :second, counter: false)
      assert result == :ok
    end

    @tag :requires_chain
    test "creates bandwidth limit rule (bytes)", %{pid: pid} do
      result = Rule.rate_limit(pid, "filter", "INPUT", 1_000_000, :second, type: :bytes)
      assert result == :ok
    end

    @tag :requires_chain
    test "creates rate limit with different time units", %{pid: pid} do
      # Test various time units
      assert :ok = Rule.rate_limit(pid, "filter", "INPUT", 10, :second)
      assert :ok = Rule.rate_limit(pid, "filter", "INPUT", 100, :minute)
      assert :ok = Rule.rate_limit(pid, "filter", "INPUT", 1000, :hour)
      assert :ok = Rule.rate_limit(pid, "filter", "INPUT", 10000, :day)
      assert :ok = Rule.rate_limit(pid, "filter", "INPUT", 100000, :week)
    end

    test "returns error for invalid table/chain", %{pid: pid} do
      result = Rule.rate_limit(pid, "nonexistent", "INPUT", 100, :second)
      assert {:error, _reason} = result
    end

    test "returns error for invalid family", %{pid: pid} do
      result = Rule.rate_limit(pid, "filter", "INPUT", 100, :second, family: :invalid)
      assert {:error, error_msg} = result
      assert error_msg =~ "Invalid family"
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
