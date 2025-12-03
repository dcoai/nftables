defmodule NFTables.FlowtableUnitTest do
  use ExUnit.Case, async: true

  alias NFTables.Builder

  describe "flowtable validation" do
    test "rejects invalid hook" do
      assert_raise ArgumentError, ~r/Invalid flowtable hook/, fn ->
        Builder.new()
        |> NFTables.add(
          flowtable: "invalid_hook",
          table: "test",
          family: :inet,
          hook: :input,  # Invalid: only :ingress allowed
          priority: 0,
          devices: ["lo"]
        )
      end
    end

    test "rejects empty devices list" do
      assert_raise ArgumentError, ~r/Invalid flowtable devices: empty list/, fn ->
        Builder.new()
        |> NFTables.add(
          flowtable: "no_devices",
          table: "test",
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: []  # Invalid: empty list
        )
      end
    end

    test "rejects non-list devices" do
      assert_raise ArgumentError, ~r/Invalid flowtable devices.*expected list/, fn ->
        Builder.new()
        |> NFTables.add(
          flowtable: "bad_devices",
          table: "test",
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: "lo"  # Invalid: should be list
        )
      end
    end

    test "rejects devices with non-string elements" do
      assert_raise ArgumentError, ~r/Invalid flowtable devices.*must be strings/, fn ->
        Builder.new()
        |> NFTables.add(
          flowtable: "bad_device_type",
          table: "test",
          family: :inet,
          hook: :ingress,
          priority: 0,
          devices: [:lo, :eth0]  # Invalid: atoms instead of strings
        )
      end
    end
  end

  describe "JSON generation" do
    test "generates correct JSON for flowtable add" do
      builder =
        Builder.new()
        |> NFTables.add(
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
        |> NFTables.delete(flowtable: "test_flow", table: "filter", family: :inet)

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
        Builder.new()
        |> NFTables.add(
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
end
