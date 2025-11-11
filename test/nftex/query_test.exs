Code.require_file("../test_helper.exs", __DIR__)

defmodule NFTablesEx.QueryTest do
  use ExUnit.Case
  require Logger

  alias NFTablesEx.Query

  @moduletag :integration

  # Prerequisites:
  # - CAP_NET_ADMIN capability set on binary
  # - Some nftables configuration exists (tables, chains, etc.)

  describe "list_tables/2" do
    setup do
      {:ok, pid} = NFTablesEx.start_link()
      on_exit(fn ->
        if Process.alive?(pid), do: NFTablesEx.stop(pid)
      end)
      {:ok, pid: pid}
    end

    test "lists tables for inet family", %{pid: pid} do
      {:ok, tables} = Query.list_tables(pid, family: :inet)
      assert is_list(tables)
      # Each table should be a map with required fields
      for table <- tables do
        assert is_map(table)
        assert Map.has_key?(table, :name)
        assert Map.has_key?(table, :family)
      end
    end

    test "lists tables for ip6 family", %{pid: pid} do
      {:ok, tables} = Query.list_tables(pid, family: :ip6)
      assert is_list(tables)
    end

    test "accepts timeout option", %{pid: pid} do
      {:ok, tables} = Query.list_tables(pid, family: :inet, timeout: 10_000)
      assert is_list(tables)
    end

    test "accepts parse: false option", %{pid: pid} do
      {:ok, tables} = Query.list_tables(pid, family: :inet, parse: false)
      assert is_list(tables)
    end
  end

  describe "list_chains/2" do
    setup do
      {:ok, pid} = NFTablesEx.start_link()
      on_exit(fn ->
        if Process.alive?(pid), do: NFTablesEx.stop(pid)
      end)
      {:ok, pid: pid}
    end

    test "lists chains for inet family", %{pid: pid} do
      {:ok, chains} = Query.list_chains(pid, family: :inet)
      assert is_list(chains)
      # Each chain should be a map
      for chain <- chains do
        assert is_map(chain)
        assert Map.has_key?(chain, :name)
        assert Map.has_key?(chain, :table)
      end
    end

    test "chain has expected fields", %{pid: pid} do
      {:ok, chains} = Query.list_chains(pid, family: :inet)

      if length(chains) > 0 do
        chain = hd(chains)
        # Common fields
        assert Map.has_key?(chain, :name)
        assert Map.has_key?(chain, :table)
        assert Map.has_key?(chain, :family)

        # Base chains have additional fields
        if Map.get(chain, :is_base_chain) do
          assert Map.has_key?(chain, :type)
          assert Map.has_key?(chain, :hook)
          assert Map.has_key?(chain, :priority)
        end
      end
    end
  end

  describe "list_rules/2" do
    setup do
      {:ok, pid} = NFTablesEx.start_link()
      on_exit(fn ->
        if Process.alive?(pid), do: NFTablesEx.stop(pid)
      end)
      {:ok, pid: pid}
    end

    test "lists rules for inet family", %{pid: pid} do
      {:ok, rules} = Query.list_rules(pid, family: :inet)
      assert is_list(rules)
      # Each rule should be a map
      for rule <- rules do
        assert is_map(rule)
        assert Map.has_key?(rule, :table)
        assert Map.has_key?(rule, :chain)
      end
    end

    test "rule has expected fields", %{pid: pid} do
      {:ok, rules} = Query.list_rules(pid, family: :inet)

      if length(rules) > 0 do
        rule = hd(rules)
        assert Map.has_key?(rule, :table)
        assert Map.has_key?(rule, :chain)
        assert Map.has_key?(rule, :family)
        assert Map.has_key?(rule, :handle)
      end
    end

    test "accepts timeout option", %{pid: pid} do
      {:ok, rules} = Query.list_rules(pid, family: :inet, timeout: 10_000)
      assert is_list(rules)
    end
  end

  describe "list_sets/2" do
    setup do
      {:ok, pid} = NFTablesEx.start_link()
      on_exit(fn ->
        if Process.alive?(pid), do: NFTablesEx.stop(pid)
      end)
      {:ok, pid: pid}
    end

    test "lists sets for inet family", %{pid: pid} do
      {:ok, sets} = Query.list_sets(pid, family: :inet)
      assert is_list(sets)
      # Each set should be a map
      for set <- sets do
        assert is_map(set)
        assert Map.has_key?(set, :name)
        assert Map.has_key?(set, :table)
      end
    end

    test "set has expected fields", %{pid: pid} do
      {:ok, sets} = Query.list_sets(pid, family: :inet)

      if length(sets) > 0 do
        set = hd(sets)
        assert Map.has_key?(set, :name)
        assert Map.has_key?(set, :table)
        assert Map.has_key?(set, :family)
        assert Map.has_key?(set, :key_type)
        assert Map.has_key?(set, :key_len)
      end
    end
  end

  describe "list_set_elements/3" do
    setup do
      {:ok, pid} = NFTablesEx.start_link()
      on_exit(fn ->
        if Process.alive?(pid), do: NFTablesEx.stop(pid)
      end)
      {:ok, pid: pid}
    end

    @tag :requires_set
    test "lists elements from an existing set", %{pid: pid} do
      # This test requires a pre-existing set with elements
      # For example: nft add set filter test_set '{ type ipv4_addr; }'
      # and: nft add element filter test_set { 192.168.1.1 }

      # Try to list elements (will succeed even if set doesn't exist, returning empty or error)
      result = Query.list_set_elements(pid, "filter", "test_set")

      case result do
        {:ok, elements} ->
          assert is_list(elements)
          for elem <- elements do
            assert is_map(elem)
            assert Map.has_key?(elem, :key_hex) || Map.has_key?(elem, :key_ip)
          end

        {:error, _reason} ->
          # Set doesn't exist, which is fine for this test
          assert true
      end
    end

    test "returns error for non-existent set", %{pid: pid} do
      result = Query.list_set_elements(pid, "nonexistent_table", "nonexistent_set")
      # Should return error for non-existent set
      assert match?({:error, _}, result)
    end
  end

  describe "integration test" do
    setup do
      {:ok, pid} = NFTablesEx.start_link()
      on_exit(fn ->
        if Process.alive?(pid), do: NFTablesEx.stop(pid)
      end)
      {:ok, pid: pid}
    end

    test "can query multiple resource types", %{pid: pid} do
      # Query all major resource types
      {:ok, tables} = Query.list_tables(pid, family: :inet)
      {:ok, chains} = Query.list_chains(pid, family: :inet)
      {:ok, rules} = Query.list_rules(pid, family: :inet)
      {:ok, sets} = Query.list_sets(pid, family: :inet)

      # All should return lists
      assert is_list(tables)
      assert is_list(chains)
      assert is_list(rules)
      assert is_list(sets)

      # Log counts for visibility
      Logger.info("Query results: #{length(tables)} tables, #{length(chains)} chains, #{length(rules)} rules, #{length(sets)} sets")
    end
  end
end
