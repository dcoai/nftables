defmodule NFTables.MeterUnitTest do
  use ExUnit.Case, async: true

  alias NFTables.Builder
  alias NFTables.Expr.Meter
  import NFTables.Expr

  describe "meter expression building" do
    test "builds meter_update with single key" do
      expr =
        expr()
        |> tcp()
        |> dport(22)
        |> meter_update(Meter.payload(:ip, :saddr), "ssh_limits", 3, :minute)
        |> to_list()

      # Should contain set operation
      assert Enum.any?(expr, fn e -> Map.has_key?(e, :set) end)

      set_expr = Enum.find(expr, fn e -> Map.has_key?(e, :set) end)
      assert set_expr[:set][:op] == "update"
      assert set_expr[:set][:set] == "@ssh_limits"
      assert set_expr[:set][:elem] == %{payload: %{protocol: "ip", field: "saddr"}}
    end

    test "builds meter_update with burst" do
      expr =
        expr()
        |> tcp()
        |> dport(80)
        |> meter_update(Meter.payload(:ip, :saddr), "http_limits", 100, :second, burst: 200)
        |> to_list()

      set_expr = Enum.find(expr, fn e -> Map.has_key?(e, :set) end)
      [limit_stmt] = set_expr[:set][:stmt]
      assert limit_stmt[:limit][:burst] == 200
    end

    test "builds meter_update with composite key" do
      key =
        Meter.composite_key([
          Meter.payload(:ip, :saddr),
          Meter.payload(:ip, :daddr)
        ])

      expr =
        expr()
        |> meter_update(key, "flow_limits", 50, :second)
        |> to_list()

      set_expr = Enum.find(expr, fn e -> Map.has_key?(e, :set) end)
      # Composite keys should be wrapped in concat
      assert is_map(set_expr[:set][:elem])
      assert Map.has_key?(set_expr[:set][:elem], :concat)
      assert is_list(set_expr[:set][:elem][:concat])
      assert length(set_expr[:set][:elem][:concat]) == 2
    end

    test "builds meter_add operation" do
      expr =
        expr()
        |> meter_add(Meter.payload(:ip, :saddr), "new_ips", 1, :hour)
        |> to_list()

      set_expr = Enum.find(expr, fn e -> Map.has_key?(e, :set) end)
      assert set_expr[:set][:op] == "add"
    end

    test "builds meter with different time units" do
      # Test all supported time units
      for unit <- [:second, :minute, :hour, :day, :week] do
        expr =
          expr()
          |> meter_update(Meter.payload(:ip, :saddr), "test_set", 10, unit)
          |> to_list()

        set_expr = Enum.find(expr, fn e -> Map.has_key?(e, :set) end)
        [limit_stmt] = set_expr[:set][:stmt]
        assert limit_stmt[:limit][:per] == to_string(unit)
      end
    end
  end

  describe "JSON generation" do
    test "generates correct JSON for dynamic set" do
      builder =
        Builder.new(family: :inet)
        |> NFTables.add(
          set: "json_test",
          table: "filter",
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 60,
          size: 1000
        )

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{"nftables" => [command]} = decoded
      assert %{"add" => %{"set" => set}} = command

      assert set["family"] == "inet"
      assert set["table"] == "filter"
      assert set["name"] == "json_test"
      assert set["type"] == "ipv4_addr"
      assert set["flags"] == ["dynamic"]
      assert set["timeout"] == 60
      assert set["size"] == 1000
    end

    test "generates correct JSON for meter rule" do
      meter_expr =
        expr()
        |> tcp()
        |> dport(22)
        |> ct_state([:new])
        |> meter_update(Meter.payload(:ip, :saddr), "ssh_limits", 3, :minute, burst: 5)
        |> accept()

      builder =
        Builder.new(family: :inet)
        |> NFTables.add(rule: meter_expr, table: "filter", chain: "INPUT")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Find set expression in rule
      set_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :set) end)
      assert set_expr != nil
      assert set_expr.set.op == "update"
      assert set_expr.set.set == "@ssh_limits"

      # Verify limit statement
      [limit_stmt] = set_expr.set.stmt
      assert limit_stmt.limit.rate == 3
      assert limit_stmt.limit.per == "minute"
      assert limit_stmt.limit.burst == 5
    end
  end

  describe "payload helper" do
    test "creates payload expression for IP source" do
      result = Meter.payload(:ip, :saddr)
      assert result == %{payload: %{protocol: "ip", field: "saddr"}}
    end

    test "creates payload expression for IP destination" do
      result = Meter.payload(:ip, :daddr)
      assert result == %{payload: %{protocol: "ip", field: "daddr"}}
    end

    test "creates payload expression for TCP ports" do
      sport = Meter.payload(:tcp, :sport)
      assert sport == %{payload: %{protocol: "tcp", field: "sport"}}

      dport = Meter.payload(:tcp, :dport)
      assert dport == %{payload: %{protocol: "tcp", field: "dport"}}
    end

    test "creates payload expression for IPv6" do
      result = Meter.payload(:ip6, :saddr)
      assert result == %{payload: %{protocol: "ip6", field: "saddr"}}
    end
  end

  describe "composite key helper" do
    test "creates composite key from list of expressions" do
      key =
        Meter.composite_key([
          Meter.payload(:ip, :saddr),
          Meter.payload(:tcp, :dport)
        ])

      assert is_list(key)
      assert length(key) == 2
      assert Enum.at(key, 0) == %{payload: %{protocol: "ip", field: "saddr"}}
      assert Enum.at(key, 1) == %{payload: %{protocol: "tcp", field: "dport"}}
    end

    test "creates three-element composite key" do
      key =
        Meter.composite_key([
          Meter.payload(:ip, :saddr),
          Meter.payload(:ip, :daddr),
          Meter.payload(:ip, :protocol)
        ])

      assert length(key) == 3
    end
  end

  describe "meter with counter" do
    test "combines meter with counter in rule expression" do
      # This is a unit test - just validates the expression structure
      tracked_rule =
        expr()
        |> tcp()
        |> dport(443)
        |> meter_update(Meter.payload(:ip, :saddr), "tracked_ips", 50, :second)
        |> counter()
        |> accept()
        |> to_list()

      # Should have set expression, counter, and accept
      assert Enum.any?(tracked_rule, fn e -> Map.has_key?(e, :set) end)
      assert Enum.any?(tracked_rule, fn e -> Map.has_key?(e, :counter) end)
      assert Enum.any?(tracked_rule, fn e -> Map.has_key?(e, :accept) end)
    end
  end
end
