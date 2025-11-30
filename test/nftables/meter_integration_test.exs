defmodule NFTables.MeterIntegrationTest do
  use ExUnit.Case, async: false

  alias NFTables.Builder
  alias NFTables.Match.Meter
  import NFTables.Match

  @moduletag :integration
  @moduletag :slow

  setup do
    {:ok, pid} = NFTables.start_link()
    test_table = "meter_test_#{:rand.uniform(1_000_000)}"

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

  describe "dynamic set creation" do
    test "creates dynamic set with all parameters", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(
          set: "full_set",
          table: table,
          family: :inet,
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 120,
          size: 5000
        )
        |> Builder.execute(pid)

      assert :ok == result
    end
  end

  describe "meter integration tests" do
    test "creates dynamic set and uses it in rule", %{pid: pid, table: table} do
      # Step 1: Create simple chain (avoid Builder bug with hooks)
      :ok =
        Builder.new()
        |> Builder.add(chain: "input", table: table, family: :inet)
        |> Builder.execute(pid)

      # Step 2: Create dynamic set
      :ok =
        Builder.new()
        |> Builder.add(
          set: "ssh_ratelimit",
          table: table,
          family: :inet,
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 60,
          size: 10000
        )
        |> Builder.execute(pid)

      # Step 3: Create rule using meter
      ssh_rule =
        rule()
        |> tcp()
        |> dport(22)
        |> ct_state([:new])
        |> meter_update(Meter.payload(:ip, :saddr), "ssh_ratelimit", 3, :minute, burst: 5)
        |> accept()

      result =
        Builder.new()
        |> Builder.add(rule: ssh_rule, table: table, chain: "input", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "batch creates table, set, chain, and rule", %{pid: pid} do
      batch_table = "batch_meter_#{:rand.uniform(1_000_000)}"

      meter_rule =
        rule()
        |> tcp()
        |> dport(80)
        |> meter_update(Meter.payload(:ip, :saddr), "http_limits", 100, :second, burst: 200)
        |> accept()

      result =
        Builder.new(family: :inet)
        |> Builder.add(table: batch_table)
        |> Builder.add(chain: "input")  # Simple chain without hooks
        |> Builder.add(
          set: "http_limits",
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 60,
          size: 100000
        )
        |> Builder.add(rule: meter_rule)
        |> Builder.execute(pid)

      assert :ok == result

      # Cleanup
      Builder.new()
      |> Builder.delete(table: batch_table, family: :inet)
      |> Builder.execute(pid)
    end
  end
end
