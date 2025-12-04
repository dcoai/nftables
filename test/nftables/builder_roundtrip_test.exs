defmodule NFTables.BuilderRoundtripTest do
  use ExUnit.Case, async: true

  alias NFTables.Builder

  describe "import_table/2" do
    test "imports table from query result" do
      table_map = %{
        name: "filter",
        family: :inet,
        handle: 123
      }

      builder = Builder.new()
      |> Builder.import_table(table_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{
               "nftables" => [
                 %{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}}
               ]
             } = decoded
    end

    test "imports table with different family" do
      table_map = %{
        name: "nat",
        family: :ip6,
        handle: 456
      }

      builder = Builder.new()
      |> Builder.import_table(table_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      table_cmd = Enum.at(decoded["nftables"], 0)
      assert table_cmd["add"]["table"]["family"] == "ip6"
      assert table_cmd["add"]["table"]["name"] == "nat"
    end

    test "imports multiple tables" do
      tables = [
        %{name: "filter", family: :inet, handle: 1},
        %{name: "nat", family: :inet, handle: 2},
        %{name: "mangle", family: :inet, handle: 3}
      ]

      builder = Enum.reduce(tables, Builder.new(), fn table, b ->
        Builder.import_table(b, table)
      end)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert length(decoded["nftables"]) == 3
      table_names = Enum.map(decoded["nftables"], fn cmd ->
        cmd["add"]["table"]["name"]
      end)
      assert table_names == ["filter", "nat", "mangle"]
    end
  end

  describe "import_chain/2" do
    test "imports regular chain" do
      chain_map = %{
        name: "forward",
        table: "filter",
        family: :inet,
        handle: 789
      }

      builder =       NFTables.add(table: "filter")
      |> Builder.import_chain(chain_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      chain_cmd = Enum.at(decoded["nftables"], 1)
      assert chain_cmd["add"]["chain"]["name"] == "forward"
      assert chain_cmd["add"]["chain"]["table"] == "filter"
    end

    test "imports base chain with hook" do
      chain_map = %{
        name: "INPUT",
        table: "filter",
        family: :inet,
        handle: 101,
        type: :filter,
        hook: :input,
        prio: 0,
        policy: :drop
      }

      builder =       NFTables.add(table: "filter")
      |> Builder.import_chain(chain_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      chain_cmd = Enum.at(decoded["nftables"], 1)
      chain = chain_cmd["add"]["chain"]

      assert chain["name"] == "INPUT"
      assert chain["type"] == "filter"
      assert chain["hook"] == "input"
      assert chain["prio"] == 0
      assert chain["policy"] == "drop"
    end

    test "imports chain without optional fields" do
      chain_map = %{
        name: "custom",
        table: "filter",
        family: :inet,
        handle: 202
      }

      builder =       NFTables.add(table: "filter")
      |> Builder.import_chain(chain_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      chain_cmd = Enum.at(decoded["nftables"], 1)
      chain = chain_cmd["add"]["chain"]

      assert chain["name"] == "custom"
      refute Map.has_key?(chain, "type")
      refute Map.has_key?(chain, "hook")
    end
  end

  describe "import_rule/2" do
    test "imports rule with expression list" do
      rule_map = %{
        family: :inet,
        table: "filter",
        chain: "INPUT",
        handle: 321,
        expr: [
          %{match: %{left: %{payload: %{protocol: "ip", field: "saddr"}}, right: "10.0.0.1", op: "=="}},
          %{accept: nil}
        ]
      }

      builder =       NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")
      |> Builder.import_rule(rule_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      rule_cmd = Enum.at(decoded["nftables"], 2)
      assert rule_cmd["add"]["rule"]["chain"] == "INPUT"
      assert rule_cmd["add"]["rule"]["table"] == "filter"
      assert length(rule_cmd["add"]["rule"]["expr"]) == 2
    end

    test "imports complex rule" do
      rule_map = %{
        family: :inet,
        table: "filter",
        chain: "INPUT",
        handle: 444,
        expr: [
          %{match: %{left: %{meta: %{key: "l4proto"}}, right: "tcp", op: "=="}},
          %{match: %{left: %{payload: %{protocol: "tcp", field: "dport"}}, right: 22, op: "=="}},
          %{limit: %{rate: 10, per: "minute", burst: 5}},
          %{counter: %{packets: 0, bytes: 0}},
          %{accept: nil}
        ]
      }

      builder =       NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")
      |> Builder.import_rule(rule_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      rule_cmd = Enum.at(decoded["nftables"], 2)
      assert length(rule_cmd["add"]["rule"]["expr"]) == 5
    end

    test "imports multiple rules" do
      rules = [
        %{family: :inet, table: "filter", chain: "INPUT", handle: 1, expr: [%{accept: nil}]},
        %{family: :inet, table: "filter", chain: "INPUT", handle: 2, expr: [%{drop: nil}]},
        %{family: :inet, table: "filter", chain: "INPUT", handle: 3, expr: [%{reject: nil}]}
      ]

      builder =       NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")

      builder = Enum.reduce(rules, builder, fn rule, b ->
        Builder.import_rule(b, rule)
      end)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      # 1 table + 1 chain + 3 rules = 5 commands
      assert length(decoded["nftables"]) == 5
    end
  end

  describe "import_set/2" do
    test "imports set with basic type" do
      set_map = %{
        name: "blocklist",
        table: "filter",
        family: :inet,
        type: :ipv4_addr,
        handle: 555
      }

      builder =       NFTables.add(table: "filter")
      |> Builder.import_set(set_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      set_cmd = Enum.at(decoded["nftables"], 1)
      assert set_cmd["add"]["set"]["name"] == "blocklist"
      assert set_cmd["add"]["set"]["type"] == "ipv4_addr"
    end

    test "imports set with flags" do
      set_map = %{
        name: "port_ranges",
        table: "filter",
        family: :inet,
        type: :inet_service,
        flags: [:interval],
        handle: 666
      }

      builder =       NFTables.add(table: "filter")
      |> Builder.import_set(set_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      set_cmd = Enum.at(decoded["nftables"], 1)
      set = set_cmd["add"]["set"]

      assert set["name"] == "port_ranges"
      assert set["type"] == "inet_service"
      assert set["flags"] == ["interval"]
    end

    test "imports set with size and timeout" do
      set_map = %{
        name: "temp_blocklist",
        table: "filter",
        family: :inet,
        type: :ipv4_addr,
        size: 1000,
        timeout: 3600,
        handle: 777
      }

      builder =       NFTables.add(table: "filter")
      |> Builder.import_set(set_map)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      set_cmd = Enum.at(decoded["nftables"], 1)
      set = set_cmd["add"]["set"]

      assert set["size"] == 1000
      assert set["timeout"] == 3600
    end
  end

  describe "integration - import and modify" do
    test "imports table, adds chain, adds rule" do
      # Simulate querying an existing table
      table_map = %{name: "filter", family: :inet, handle: 1}

      # Import table and add new content
      builder = Builder.new()
      |> Builder.import_table(table_map)
      |> NFTables.add(chain: "custom_chain")
      |> NFTables.add(rule: [%{accept: nil}])

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      # Should have: table + chain + rule
      assert length(decoded["nftables"]) == 3
      assert Enum.at(decoded["nftables"], 0)["add"]["table"]["name"] == "filter"
      assert Enum.at(decoded["nftables"], 1)["add"]["chain"]["name"] == "custom_chain"
      assert Enum.at(decoded["nftables"], 2)["add"]["rule"] != nil
    end

    test "imports chain and adds rules" do
      chain_map = %{
        name: "INPUT",
        table: "filter",
        family: :inet,
        handle: 2,
        type: :filter,
        hook: :input,
        prio: 0,
        policy: :accept
      }

      builder =       NFTables.add(table: "filter")
      |> Builder.import_chain(chain_map)
      |> NFTables.add(rule: [%{drop: nil}])

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert length(decoded["nftables"]) == 3
      chain_cmd = Enum.at(decoded["nftables"], 1)
      assert chain_cmd["add"]["chain"]["policy"] == "accept"
    end
  end

  describe "from_ruleset/2" do
    # These tests would require actual nftables running
    # For unit tests, we'll test the function exists and has correct signature

    test "from_ruleset function exists" do
      assert function_exported?(Builder, :from_ruleset, 1)
      assert function_exported?(Builder, :from_ruleset, 2)
    end

    test "from_ruleset validates pid parameter" do
      # This should fail type checking if not a pid
      assert_raise FunctionClauseError, fn ->
        Builder.from_ruleset("not_a_pid")
      end
    end
  end

  describe "helper functions" do
    test "maybe_add_opt skips nil values" do
      opts = []
      result = Builder.maybe_add_opt(opts, :type, nil)
      assert result == []
    end

    test "maybe_add_opt adds non-nil values" do
      opts = []
      result = Builder.maybe_add_opt(opts, :type, :filter)
      assert result == [type: :filter]
    end

    test "maybe_add_opt chains multiple values" do
      opts = []
      result = opts
      |> Builder.maybe_add_opt(:type, :filter)
      |> Builder.maybe_add_opt(:hook, :input)
      |> Builder.maybe_add_opt(:priority, nil)
      |> Builder.maybe_add_opt(:policy, :drop)

      # Keyword list order may vary, check contents
      assert Keyword.has_key?(result, :type)
      assert Keyword.has_key?(result, :hook)
      assert Keyword.has_key?(result, :policy)
      refute Keyword.has_key?(result, :priority)
      assert Keyword.get(result, :type) == :filter
      assert Keyword.get(result, :hook) == :input
      assert Keyword.get(result, :policy) == :drop
    end
  end

  describe "round-trip consistency" do
    test "importing and re-exporting table produces same structure" do
      original_table = %{name: "test", family: :inet, handle: 99}

      builder = Builder.new()
      |> Builder.import_table(original_table)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      result_table = Enum.at(decoded["nftables"], 0)["add"]["table"]
      assert result_table["name"] == original_table.name
      assert result_table["family"] == to_string(original_table.family)
    end

    test "importing chain preserves all attributes" do
      original_chain = %{
        name: "INPUT",
        table: "filter",
        family: :inet,
        handle: 10,
        type: :filter,
        hook: :input,
        prio: -150,
        policy: :drop
      }

      builder =       NFTables.add(table: "filter")
      |> Builder.import_chain(original_chain)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      result_chain = Enum.at(decoded["nftables"], 1)["add"]["chain"]
      assert result_chain["name"] == original_chain.name
      assert result_chain["type"] == to_string(original_chain.type)
      assert result_chain["hook"] == to_string(original_chain.hook)
      assert result_chain["prio"] == original_chain.prio
      assert result_chain["policy"] == to_string(original_chain.policy)
    end
  end
end
