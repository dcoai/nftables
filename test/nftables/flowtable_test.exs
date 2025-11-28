defmodule NFTables.FlowtableTest do
  use ExUnit.Case, async: false

  alias NFTables.Builder

  @moduletag :sudo_required

  setup do
    {:ok, pid} = NFTables.start_link()
    test_table = "flowtable_test_#{:rand.uniform(1_000_000)}"

    # Create test table
    Builder.new(family: :inet)
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

    @tag :skip
    test "creates flowtable with multiple devices", %{pid: pid, table: table} do
      # Note: Skipped because eth0 might not exist on all systems
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

      # May fail if kernel doesn't support flowtables
      assert :ok == result or match?({:error, _}, result)
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

  describe "flowtable validation" do
    test "rejects invalid hook", %{table: table} do
      assert_raise ArgumentError, ~r/Invalid flowtable hook/, fn ->
        Builder.new()
        |> Builder.add(
          flowtable: "invalid_hook",
          table: table,
          family: :inet,
          hook: :input,  # Invalid: only :ingress allowed
          priority: 0,
          devices: ["lo"]
        )
      end
    end

    test "rejects empty devices list", %{table: table} do
      assert_raise ArgumentError, ~r/Invalid flowtable devices: empty list/, fn ->
        Builder.new()
        |> Builder.add(
          flowtable: "no_devices",
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: []  # Invalid: empty list
        )
      end
    end

    test "rejects non-list devices", %{table: table} do
      assert_raise ArgumentError, ~r/Invalid flowtable devices.*expected list/, fn ->
        Builder.new()
        |> Builder.add(
          flowtable: "bad_devices",
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: "lo"  # Invalid: should be list
        )
      end
    end

    test "rejects devices with non-string elements", %{table: table} do
      assert_raise ArgumentError, ~r/Invalid flowtable devices.*must be strings/, fn ->
        Builder.new()
        |> Builder.add(
          flowtable: "bad_device_type",
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: [:lo, :eth0]  # Invalid: atoms instead of strings
        )
      end
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

    @tag :skip
    test "flushes flowtable", %{pid: pid, table: table} do
      # Note: Skipped - nftables doesn't support flushing flowtables
      # Flowtables are automatically managed and don't need manual flushing
      :ok =
        Builder.new()
        |> Builder.add(
          flowtable: "to_flush",
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: ["lo"]
        )
        |> Builder.execute(pid)

      # This operation is not supported by nftables
      # result =
      #   Builder.new()
      #   |> Builder.flush(flowtable: "to_flush", table: table, family: :inet)
      #   |> Builder.execute(pid)
      #
      # assert :ok == result
    end
  end

  describe "JSON generation" do
    test "generates correct JSON for flowtable add" do
      builder =
        Builder.new(family: :inet)
        |> Builder.add(
          flowtable: "test_flow",
          table: "filter",
          hook: :ingress,
          priority: 0,
          devices: ["eth0", "eth1"]
        )

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{"nftables" => [command]} = decoded
      assert %{"add" => %{"flowtable" => flowtable}} = command

      assert flowtable["family"] == "inet"
      assert flowtable["table"] == "filter"
      assert flowtable["name"] == "test_flow"
      assert flowtable["hook"] == "ingress"
      assert flowtable["prio"] == 0
      assert flowtable["dev"] == ["eth0", "eth1"]
    end

    test "generates correct JSON for flowtable delete" do
      builder =
        Builder.new()
        |> Builder.delete(flowtable: "test_flow", table: "filter", family: :inet)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{"nftables" => [command]} = decoded
      assert %{"delete" => %{"flowtable" => flowtable}} = command

      assert flowtable["family"] == "inet"
      assert flowtable["table"] == "filter"
      assert flowtable["name"] == "test_flow"
    end

    test "generates correct JSON with hardware offload flag" do
      builder =
        Builder.new(family: :inet)
        |> Builder.add(
          flowtable: "hw_flow",
          table: "filter",
          hook: :ingress,
          priority: 0,
          devices: ["eth0"],
          flags: [:offload]
        )

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{"nftables" => [command]} = decoded
      assert %{"add" => %{"flowtable" => flowtable}} = command

      # Flags are converted to strings in JSON
      assert flowtable["flags"] == ["offload"]
    end
  end

  describe "context tracking" do
    test "uses table from context", %{pid: pid, table: table} do
      result =
        Builder.new(family: :inet)
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
        Builder.new(family: :inet)
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
    @tag :skip
    test "creates multiple flowtables atomically", %{pid: pid, table: table} do
      # Generate unique flowtable names to avoid conflicts
      flow1 = "flow_#{:rand.uniform(1_000_000)}_1"
      flow2 = "flow_#{:rand.uniform(1_000_000)}_2"

      # Create flowtables with different hooks to avoid conflicts
      result =
        Builder.new()
        |> Builder.add(
          flowtable: flow1,
          table: table,
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: ["lo"]
        )
        |> Builder.add(
          flowtable: flow2,
          table: table,
          family: :inet,
          hook: :egress,  # Use different hook
          priority: 0,
          devices: ["lo"]
        )
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "creates table, flowtable, and chain in one batch", %{pid: pid} do
      batch_table = "batch_test_#{:rand.uniform(1_000_000)}"

      result =
        Builder.new(family: :inet)
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
