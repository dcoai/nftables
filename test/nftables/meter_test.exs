defmodule NFTables.MeterTest do
  use ExUnit.Case, async: false

  alias NFTables.Builder
  alias NFTables.Match.Meter
  import NFTables.Match

  @moduletag :sudo_required

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
    test "creates dynamic set with basic parameters", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(
          set: "test_set",
          table: table,
          family: :inet,
          type: :ipv4_addr,
          flags: [:dynamic]
        )
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "creates dynamic set with timeout", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(
          set: "timeout_set",
          table: table,
          family: :inet,
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 60
        )
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "creates dynamic set with size limit", %{pid: pid, table: table} do
      result =
        Builder.new()
        |> Builder.add(
          set: "sized_set",
          table: table,
          family: :inet,
          type: :ipv4_addr,
          flags: [:dynamic],
          size: 10000
        )
        |> Builder.execute(pid)

      assert :ok == result
    end

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

  describe "meter expression building" do
    test "builds meter_update with single key" do
      expr =
        rule()
        |> tcp()
        |> dport(22)
        |> meter_update(Meter.payload(:ip, :saddr), "ssh_limits", 3, :minute)
        |> to_expr()

      # Should contain set operation
      assert Enum.any?(expr, fn e -> Map.has_key?(e, :set) end)

      set_expr = Enum.find(expr, fn e -> Map.has_key?(e, :set) end)
      assert set_expr[:set][:op] == "update"
      assert set_expr[:set][:set] == "@ssh_limits"
      assert set_expr[:set][:elem] == %{payload: %{protocol: "ip", field: "saddr"}}
    end

    test "builds meter_update with burst" do
      expr =
        rule()
        |> tcp()
        |> dport(80)
        |> meter_update(Meter.payload(:ip, :saddr), "http_limits", 100, :second, burst: 200)
        |> to_expr()

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
        rule()
        |> meter_update(key, "flow_limits", 50, :second)
        |> to_expr()

      set_expr = Enum.find(expr, fn e -> Map.has_key?(e, :set) end)
      assert is_list(set_expr[:set][:elem])
      assert length(set_expr[:set][:elem]) == 2
    end

    test "builds meter_add operation" do
      expr =
        rule()
        |> meter_add(Meter.payload(:ip, :saddr), "new_ips", 1, :hour)
        |> to_expr()

      set_expr = Enum.find(expr, fn e -> Map.has_key?(e, :set) end)
      assert set_expr[:set][:op] == "add"
    end

    test "builds meter with different time units" do
      # Test all supported time units
      for unit <- [:second, :minute, :hour, :day, :week] do
        expr =
          rule()
          |> meter_update(Meter.payload(:ip, :saddr), "test_set", 10, unit)
          |> to_expr()

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
        |> Builder.add(
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
        rule()
        |> tcp()
        |> dport(22)
        |> ct_state([:new])
        |> meter_update(Meter.payload(:ip, :saddr), "ssh_limits", 3, :minute, burst: 5)
        |> accept()
        |> to_expr()

      builder =
        Builder.new(family: :inet)
        |> Builder.add(rule: meter_expr, table: "filter", chain: "INPUT")

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

  describe "integration tests" do
    test "creates dynamic set and uses it in rule", %{pid: pid, table: table} do
      # Step 1: Create chain
      :ok =
        Builder.new()
        |> Builder.add(
          chain: "input",
          table: table,
          family: :inet,
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :accept
        )
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
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: ssh_rule, table: table, chain: "input", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "creates set with composite key type", %{pid: pid, table: table} do
      # Composite key: IP + port
      result =
        Builder.new()
        |> Builder.add(
          set: "flow_tracker",
          table: table,
          family: :inet,
          type: {:concat, [:ipv4_addr, :inet_service]},
          flags: [:dynamic],
          timeout: 30,
          size: 50000
        )
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
        |> to_expr()

      result =
        Builder.new(family: :inet)
        |> Builder.add(table: batch_table)
        |> Builder.add(
          chain: "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :accept
        )
        |> Builder.add(
          set: "http_limits",
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 60,
          size: 100000
        )
        |> Builder.add(rule: meter_rule, chain: "input")
        |> Builder.execute(pid)

      assert :ok == result

      # Cleanup
      Builder.new()
      |> Builder.delete(table: batch_table, family: :inet)
      |> Builder.execute(pid)
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
    test "combines meter with counter", %{pid: pid, table: table} do
      # Create set
      :ok =
        Builder.new()
        |> Builder.add(
          set: "tracked_ips",
          table: table,
          family: :inet,
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 300
        )
        |> Builder.execute(pid)

      # Create chain
      :ok =
        Builder.new()
        |> Builder.add(
          chain: "forward",
          table: table,
          family: :inet,
          type: :filter,
          hook: :forward,
          priority: 0,
          policy: :accept
        )
        |> Builder.execute(pid)

      # Rule with meter and counter
      tracked_rule =
        rule()
        |> tcp()
        |> dport(443)
        |> meter_update(Meter.payload(:ip, :saddr), "tracked_ips", 50, :second)
        |> counter()
        |> accept()
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: tracked_rule, table: table, chain: "forward", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end
  end

  describe "real-world use cases" do
    test "SSH brute-force protection", %{pid: pid, table: table} do
      # Create infrastructure
      :ok =
        Builder.new(family: :inet)
        |> Builder.add(table: table)
        |> Builder.add(
          chain: "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :accept
        )
        |> Builder.add(
          set: "ssh_bruteforce",
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 600,
          size: 10000
        )
        |> Builder.execute(pid)

      # SSH rate limiting rule
      ssh_rule =
        rule()
        |> tcp()
        |> dport(22)
        |> ct_state([:new])
        |> meter_update(Meter.payload(:ip, :saddr), "ssh_bruteforce", 5, :minute, burst: 10)
        |> accept()
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: ssh_rule, table: table, chain: "input", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "HTTP flood protection per source", %{pid: pid, table: table} do
      # Create infrastructure
      :ok =
        Builder.new(family: :inet)
        |> Builder.add(table: table)
        |> Builder.add(
          chain: "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :accept
        )
        |> Builder.add(
          set: "http_flood",
          type: :ipv4_addr,
          flags: [:dynamic],
          timeout: 10,
          size: 100000
        )
        |> Builder.execute(pid)

      # HTTP rate limiting rule (100 req/sec per IP)
      http_rule =
        rule()
        |> tcp()
        |> dport(80)
        |> meter_update(Meter.payload(:ip, :saddr), "http_flood", 100, :second, burst: 200)
        |> accept()
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: http_rule, table: table, chain: "input", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "Per-flow bandwidth limiting", %{pid: pid, table: table} do
      # Track by src IP + dst IP + dst port
      :ok =
        Builder.new(family: :inet)
        |> Builder.add(table: table)
        |> Builder.add(
          chain: "forward",
          type: :filter,
          hook: :forward,
          priority: 0,
          policy: :accept
        )
        |> Builder.add(
          set: "flow_bw",
          type: {:concat, [:ipv4_addr, :ipv4_addr, :inet_service]},
          flags: [:dynamic],
          timeout: 60,
          size: 50000
        )
        |> Builder.execute(pid)

      # Per-flow limit
      flow_rule =
        rule()
        |> tcp()
        |> meter_update(
          Meter.composite_key([
            Meter.payload(:ip, :saddr),
            Meter.payload(:ip, :daddr),
            Meter.payload(:tcp, :dport)
          ]),
          "flow_bw",
          1000,
          :second,
          burst: 2000
        )
        |> accept()
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: flow_rule, table: table, chain: "forward", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end
  end
end
