defmodule NFTex.PortTest do
  use ExUnit.Case, async: false

  @moduletag :unified_port

  setup do
    # Start Unified port
    {:ok, pid} = NFTex.Port.start_link(check_capabilities: false)

    # Clean up any existing test tables (best effort)
    cleanup_tables(pid)

    on_exit(fn ->
      if Process.alive?(pid) do
        cleanup_tables(pid)
        NFTex.Port.stop(pid)
      end
    end)

    {:ok, port: pid}
  end

  describe "JSON mode" do
    test "list tables with JSON string", %{port: pid} do
      cmd = ~s({"nftables": [{"list": {"tables": {"family": "inet"}}}]})

      assert {:ok, response} = NFTex.Port.call(pid, cmd)
      assert is_binary(response)
      assert {:ok, %{"nftables" => items}} = Jason.decode(response)
      assert is_list(items)
    end

    test "add table with JSON string", %{port: pid} do
      cmd = ~s({"nftables": [{"add": {"table": {"family": "inet", "name": "unified_test_json"}}}]})

      assert {:ok, response} = NFTex.Port.call(pid, cmd)
      assert response == "" or is_binary(response)

      # Verify table was created
      tables = list_tables_json(pid, "inet")
      assert "unified_test_json" in tables
    end

    test "delete table with JSON string", %{port: pid} do
      # First create a table
      create_table_json(pid, "inet", "unified_test_delete_json")

      # Verify it exists
      tables = list_tables_json(pid, "inet")
      assert "unified_test_delete_json" in tables

      # Delete it
      cmd = ~s({"nftables": [{"delete": {"table": {"family": "inet", "name": "unified_test_delete_json"}}}]})
      assert {:ok, _} = NFTex.Port.call(pid, cmd)

      # Verify it's gone
      tables = list_tables_json(pid, "inet")
      refute "unified_test_delete_json" in tables
    end
  end

  describe "chain operations" do
    setup %{port: pid} do
      create_table_json(pid, "inet", "unified_test_chains")

      on_exit(fn ->
        if Process.alive?(pid) do
          try do
            delete_table_json(pid, "inet", "unified_test_chains")
          rescue
            _ -> :ok
          catch
            :exit, _ -> :ok
          end
        end
      end)

      :ok
    end

    test "add chain with JSON", %{port: pid} do
      cmd = ~s({"nftables": [{"add": {"chain": {"family": "inet", "table": "unified_test_chains", "name": "input"}}}]})

      assert {:ok, response} = NFTex.Port.call(pid, cmd)
      assert response == "" or is_binary(response)
    end
  end

  describe "data type handling" do
    test "JSON handles integers", %{port: pid} do
      create_table_json(pid, "inet", "unified_test_int_json")

      cmd = ~s({"nftables": [{"add": {"chain": {"family": "inet", "table": "unified_test_int_json", "name": "test", "type": "filter", "hook": "input", "prio": 100, "policy": "accept"}}}]})

      assert {:ok, response} = NFTex.Port.call(pid, cmd)
      assert response == "" or is_binary(response)

      delete_table_json(pid, "inet", "unified_test_int_json")
    end

    test "JSON handles nested structures", %{port: pid} do
      create_table_json(pid, "inet", "unified_test_nested")

      cmd = ~s({"nftables": [{"add": {"set": {"family": "inet", "table": "unified_test_nested", "name": "test_set", "type": "ipv4_addr", "elem": ["192.168.1.1", "10.0.0.1"]}}}]})

      assert {:ok, response} = NFTex.Port.call(pid, cmd)
      assert response == "" or is_binary(response)

      delete_table_json(pid, "inet", "unified_test_nested")
    end
  end

  describe "error handling" do
    test "JSON handles invalid table name", %{port: pid} do
      cmd = ~s({"nftables": [{"list": {"chains": {"family": "inet", "table": "nonexistent"}}}]})

      # Should complete without crashing
      assert {:ok, response} = NFTex.Port.call(pid, cmd)
      assert is_binary(response)
    end
  end

  # Helper functions

  defp cleanup_tables(pid) do
    test_tables = [
      "unified_test_json",
      "unified_test_delete_json",
      "unified_test_chains",
      "unified_test_int_json",
      "unified_test_nested"
    ]

    for table <- test_tables do
      # Ignore errors - table might not exist
      try do
        delete_table_json(pid, "inet", table)
      rescue
        _ -> :ok
      catch
        :exit, _ -> :ok
      end
    end
  end

  # JSON helpers
  defp create_table_json(pid, family, name) do
    cmd = ~s({"nftables": [{"add": {"table": {"family": "#{family}", "name": "#{name}"}}}]})
    NFTex.Port.call(pid, cmd)
  end

  defp delete_table_json(pid, family, name) do
    cmd = ~s({"nftables": [{"delete": {"table": {"family": "#{family}", "name": "#{name}"}}}]})
    NFTex.Port.call(pid, cmd)
  end

  defp list_tables_json(pid, family) do
    cmd = ~s({"nftables": [{"list": {"tables": {"family": "#{family}"}}}]})
    {:ok, response} = NFTex.Port.call(pid, cmd)
    {:ok, %{"nftables" => items}} = Jason.decode(response)

    items
    |> Enum.filter(&Map.has_key?(&1, "table"))
    |> Enum.map(fn %{"table" => t} -> t["name"] end)
  end
end
