defmodule NFTables.MeterIntegrationTest do
  use ExUnit.Case, async: false

  alias NFTables.Builder
  alias NFTables.Expr.Meter
  import NFTables.Expr

  @moduletag :integration
  @moduletag :slow

  setup do
    {:ok, pid} = NFTables.Port.start_link()
    test_table = "meter_test_#{:rand.uniform(1_000_000)}"

    # Create test table
    Builder.new(family: :inet)
    |> NFTables.add(table: test_table)
    |> NFTables.submit(pid: pid)

    on_exit(fn ->
      # Cleanup: delete test table
      if Process.alive?(pid) do
                NFTables.delete(table: test_table, family: :inet)
        |> NFTables.submit(pid: pid)
      end
    end)

    {:ok, pid: pid, table: test_table}
  end

  describe "dynamic set creation" do
    test "creates dynamic set with all parameters", %{pid: pid, table: table} do
      result =
                NFTables.add(
          set: "full_set",
          table: table,
          family: :inet,
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 120,
          size: 5000
        )
        |> NFTables.submit(pid: pid)

      assert :ok == result
    end
  end

  describe "meter integration tests" do
    test "creates dynamic set and uses it in rule", %{pid: pid, table: table} do
      # Step 1: Create simple chain (avoid Builder bug with hooks)
      :ok =
                NFTables.add(chain: "input", table: table, family: :inet)
        |> NFTables.submit(pid: pid)

      # Step 2: Create dynamic set
      :ok =
                NFTables.add(
          set: "ssh_ratelimit",
          table: table,
          family: :inet,
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 60,
          size: 10000
        )
        |> NFTables.submit(pid: pid)

      # Step 3: Create rule using meter
      ssh_rule =
        expr()
        |> tcp()
        |> dport(22)
        |> ct_state([:new])
        |> meter_update(Meter.payload(:ip, :saddr), "ssh_ratelimit", 3, :minute, burst: 5)
        |> accept()

      result =
                NFTables.add(rule: ssh_rule, table: table, chain: "input", family: :inet)
        |> NFTables.submit(pid: pid)

      assert :ok == result
    end

    test "batch creates table, set, chain, and rule", %{pid: pid} do
      batch_table = "batch_meter_#{:rand.uniform(1_000_000)}"

      meter_rule =
        expr()
        |> tcp()
        |> dport(80)
        |> meter_update(Meter.payload(:ip, :saddr), "http_limits", 100, :second, burst: 200)
        |> accept()

      result =
        Builder.new(family: :inet)
        |> NFTables.add(table: batch_table)
        |> NFTables.add(chain: "input")  # Simple chain without hooks
        |> NFTables.add(
          set: "http_limits",
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 60,
          size: 100000
        )
        |> NFTables.add(rule: meter_rule)
        |> NFTables.submit(pid: pid)

      assert :ok == result

      # Cleanup
            NFTables.delete(table: batch_table, family: :inet)
      |> NFTables.submit(pid: pid)
    end
  end
end
