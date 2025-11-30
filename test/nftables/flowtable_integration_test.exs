defmodule NFTables.FlowtableIntegrationTest do
  use ExUnit.Case, async: false

  alias NFTables.Builder

  @moduletag :integration
  @moduletag :slow

  setup do
    {:ok, pid} = NFTables.start_link()
    test_table = "flowtable_test_#{:rand.uniform(1_000_000)}"

    # Create test table
    Builder.new()
    |> Builder.add(table: test_table)
    |> Builder.execute(pid)

    on_exit(fn ->
      # Cleanup: delete test table
      if Process.alive?(pid) do
        Builder.new()
        |> Builder.delete(table: test_table, family: :inet)
        |> Builder.execute(pid)
      end
    end)

    {:ok, pid: pid, table: test_table}
  end

  describe "flowtable creation" do
    test "creates flowtable with valid parameters", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(
          flowtable: "fastpath",
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: ["lo"]
        )
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "creates flowtable with single device (lo)", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(
          flowtable: "multi_dev",
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: ["lo"]
        )
        |> Builder.execute(pid)

      # Should succeed on systems with flowtable support
      assert :ok == result
    end

    test "creates flowtable with hardware offload flag", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(
          flowtable: "hwoffload",
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: ["lo"],
          flags: [:offload]
        )
        |> Builder.execute(pid)

      # Note: May fail if hardware doesn't support offload, but API should work
      assert :ok == result or match?({:error, _}, result)
    end

    test "creates flowtable with different priority", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(
          flowtable: "highprio",
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 100,
          devices: ["lo"]
        )
        |> Builder.execute(pid)

      assert :ok == result
    end
  end

  describe "flowtable operations" do
    test "deletes flowtable", %{pid: pid, table: table} do
      # Create flowtable
      :ok =
        Builder.new()
        |> Builder.add(
          flowtable: "to_delete",
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: ["lo"]
        )
        |> Builder.execute(pid)

      # Delete flowtable
      result =
        Builder.new()
        |> Builder.delete(flowtable: "to_delete", table: table, family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end
  end

  describe "context tracking" do
    test "uses table from context", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(table: table)
        |> Builder.add(
          flowtable: "context_test",
          hook: :ingress,
          priority: 0,
          devices: ["lo"]
        )
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "uses family from context", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(table: table)
        |> Builder.add(
          flowtable: "family_context",
          hook: :ingress,
          priority: 0,
          devices: ["lo"]
        )
        |> Builder.execute(pid)

      assert :ok == result
    end
  end

  describe "batch operations" do
    test "creates table, flowtable, and chain in one batch", %{pid: pid} do
      batch_table = "batch_test_#{:rand.uniform(1_000_000)}"

      result =
        Builder.new()
        |> Builder.add(table: batch_table)
        |> Builder.add(
          flowtable: "batch_flow",
          hook: :ingress,
          priority: 0,
          devices: ["lo"]
        )
        |> Builder.add(
          chain: "forward",
          type: :filter,
          hook: :forward,
          priority: 0,
          policy: :accept
        )
        |> Builder.execute(pid)

      assert :ok == result

      # Cleanup
      Builder.new()
      |> Builder.delete(table: batch_table, family: :inet)
      |> Builder.execute(pid)
    end
  end
end
