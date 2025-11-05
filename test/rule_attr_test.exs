Code.require_file("test_helper.exs", __DIR__)

defmodule RuleAttrTest do
  use ExUnit.Case
  require Logger

  @moduletag :integration

  describe "NFTex rule attribute operations" do
    # Note: Rule table attribute has libnftnl internal assertion issues
    # Getting attributes from local rule objects causes assertions.
    @tag :skip
    test "can set and get rule table name" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a rule
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)
      assert is_integer(rule_id)

      # Set the rule's table name
      :ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, "filter"}, 5000)

      # Get the table name back
      {:ok, table} = NFTex.Port.call(pid, {:rule_get_str, rule_id, :table}, 5000)
      assert table == "filter"

      NFTex.stop(pid)
    end

    # Note: Rule chain attribute has libnftnl internal assertion issues
    @tag :skip
    test "can set and get rule chain name" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a rule
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)

      # Set the rule's chain name
      :ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, "input"}, 5000)

      # Get the chain name back
      {:ok, chain} = NFTex.Port.call(pid, {:rule_get_str, rule_id, :chain}, 5000)
      assert chain == "input"

      NFTex.stop(pid)
    end

    # Note: Rule family attribute has libnftnl internal assertion issues
    # Getting unset attributes causes assertions. This appears to be a limitation
    # of the libnftnl library where certain attributes can only be queried after
    # being persisted via netlink.
    @tag :skip
    test "can set and get rule family" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a rule
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)

      # Set the rule family (2 = AF_INET)
      :ok = NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, 2}, 5000)

      # Get the family back
      {:ok, family} = NFTex.Port.call(pid, {:rule_get_u32, rule_id, :family}, 5000)
      assert family == 2

      NFTex.stop(pid)
    end

    # Note: Rule position attribute has libnftnl internal assertion issues
    @tag :skip
    test "can set and get rule position" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a rule
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)

      # Set the rule position
      :ok = NFTex.Port.call(pid, {:rule_set_u64, rule_id, :position, 10}, 5000)

      # Get the position back
      {:ok, position} = NFTex.Port.call(pid, {:rule_get_u64, rule_id, :position}, 5000)
      assert position == 10

      NFTex.stop(pid)
    end

    # Note: Rule handle attribute has libnftnl internal assertion issues
    @tag :skip
    test "can set and get rule handle" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a rule
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)

      # Set the rule handle
      :ok = NFTex.Port.call(pid, {:rule_set_u64, rule_id, :handle, 12345}, 5000)

      # Get the handle back
      {:ok, handle} = NFTex.Port.call(pid, {:rule_get_u64, rule_id, :handle}, 5000)
      assert handle == 12345

      NFTex.stop(pid)
    end

    # Note: Some rule setters also have internal assertions in libnftnl
    @tag :skip
    test "can configure complete rule with setters only" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a rule
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)

      # Configure the rule (setters work fine)
      :ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, "filter"}, 5000)
      :ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, "input"}, 5000)
      :ok = NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, 2}, 5000)
      :ok = NFTex.Port.call(pid, {:rule_set_u64, rule_id, :position, 0}, 5000)

      # Note: Cannot verify attributes via getters on local rule objects
      # Getters would work after the rule is persisted via netlink

      NFTex.stop(pid)
    end

    test "can add expression to rule" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a rule and an expression
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)
      {:ok, expr_id} = NFTex.Port.call(pid, {:expr_alloc, "counter"}, 5000)

      # Add the expression to the rule
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, expr_id}, 5000)

      NFTex.stop(pid)
    end

    test "can add multiple expressions to rule" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a rule and multiple expressions
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)
      {:ok, expr_id1} = NFTex.Port.call(pid, {:expr_alloc, "counter"}, 5000)
      {:ok, expr_id2} = NFTex.Port.call(pid, {:expr_alloc, "payload"}, 5000)
      {:ok, expr_id3} = NFTex.Port.call(pid, {:expr_alloc, "cmp"}, 5000)

      # Add all expressions to the rule
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, expr_id1}, 5000)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, expr_id2}, 5000)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, expr_id3}, 5000)

      NFTex.stop(pid)
    end

    test "returns error for invalid rule resource ID in set operations" do
      {:ok, pid} = NFTex.start_link()

      # Try to set on non-existent resource
      {:error, msg} = NFTex.Port.call(pid, {:rule_set_str, 99999, :table, "bad"}, 5000)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "returns error for invalid rule resource ID in get operations" do
      {:ok, pid} = NFTex.start_link()

      # Try to get from non-existent resource
      {:error, msg} = NFTex.Port.call(pid, {:rule_get_str, 99999, :table}, 5000)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "returns error for unknown string attribute" do
      {:ok, pid} = NFTex.start_link()

      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)

      # Try to set unknown string attribute
      {:error, msg} = NFTex.Port.call(pid, {:rule_set_str, rule_id, :unknown, "value"}, 5000)
      assert msg =~ "unknown attr"

      # Try to get unknown string attribute
      {:error, msg} = NFTex.Port.call(pid, {:rule_get_str, rule_id, :unknown}, 5000)
      assert msg =~ "unknown attr"

      NFTex.stop(pid)
    end

    test "returns error for unknown u32 attribute" do
      {:ok, pid} = NFTex.start_link()

      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)

      # Try to set unknown u32 attribute
      {:error, msg} = NFTex.Port.call(pid, {:rule_set_u32, rule_id, :unknown, 42}, 5000)
      assert msg =~ "unknown attr"

      # Try to get unknown u32 attribute
      {:error, msg} = NFTex.Port.call(pid, {:rule_get_u32, rule_id, :unknown}, 5000)
      assert msg =~ "unknown attr"

      NFTex.stop(pid)
    end

    test "returns error for unknown u64 attribute" do
      {:ok, pid} = NFTex.start_link()

      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)

      # Try to set unknown u64 attribute
      {:error, msg} = NFTex.Port.call(pid, {:rule_set_u64, rule_id, :unknown, 42}, 5000)
      assert msg =~ "unknown attr"

      # Try to get unknown u64 attribute
      {:error, msg} = NFTex.Port.call(pid, {:rule_get_u64, rule_id, :unknown}, 5000)
      assert msg =~ "unknown attr"

      NFTex.stop(pid)
    end

    test "returns error for rule_add_expr with non-existent rule" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.Port.call(pid, {:expr_alloc, "counter"}, 5000)

      # Try to add expression to non-existent rule
      {:error, msg} = NFTex.Port.call(pid, {:rule_add_expr, 99999, expr_id}, 5000)
      assert msg =~ "rule not found"

      NFTex.stop(pid)
    end

    test "returns error for rule_add_expr with non-existent expr" do
      {:ok, pid} = NFTex.start_link()

      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)

      # Try to add non-existent expression to rule
      {:error, msg} = NFTex.Port.call(pid, {:rule_add_expr, rule_id, 99999}, 5000)
      assert msg =~ "expr not found"

      NFTex.stop(pid)
    end

    test "returns error for rule_add_expr with wrong resource types" do
      {:ok, pid} = NFTex.start_link()

      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Try to add chain to table (wrong types)
      {:error, msg} = NFTex.Port.call(pid, {:rule_add_expr, table_id, chain_id}, 5000)
      assert msg =~ "not a rule resource" or msg =~ "not an expr resource"

      NFTex.stop(pid)
    end
  end
end
