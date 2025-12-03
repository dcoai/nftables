defmodule NFTables.BuilderTest do
  use ExUnit.Case, async: true

  alias NFTables.Builder

  describe "new/1" do
    test "creates a new builder with default family" do
      builder = Builder.new()
      assert builder.family == :inet
      assert builder.commands == []
      assert builder.table == nil
      assert builder.chain == nil
    end

    test "creates builder with custom family" do
      builder = Builder.new(family: :ip6)
      assert builder.family == :ip6
    end

    test "creates builder with inet family" do
      builder = Builder.new(family: :inet)
      assert builder.family == :inet
    end
  end

  describe "set_family/2" do
    test "updates the family" do
      builder = Builder.new(family: :inet)
      |> Builder.set_family(:ip6)

      assert builder.family == :ip6
    end
  end

  describe "set/2" do
    test "sets single field: family" do
      builder = Builder.new(family: :inet)
      |> Builder.set(family: :ip6)

      assert builder.family == :ip6
    end

    test "sets single field: requestor" do
      builder = Builder.new()
      |> Builder.set(requestor: MyCustomRequestor)

      assert builder.requestor == MyCustomRequestor
    end

    test "sets single field: table" do
      builder = Builder.new()
      |> Builder.set(table: "filter")

      assert builder.table == "filter"
    end

    test "sets single field: chain" do
      builder = Builder.new()
      |> Builder.set(chain: "INPUT")

      assert builder.chain == "INPUT"
    end

    test "sets single field: collection" do
      builder = Builder.new()
      |> Builder.set(collection: "blocklist")

      assert builder.collection == "blocklist"
    end

    test "sets single field: type" do
      builder = Builder.new()
      |> Builder.set(type: :ipv4_addr)

      assert builder.type == :ipv4_addr
    end

    test "sets type as tuple (for maps)" do
      builder = Builder.new()
      |> Builder.set(type: {:ipv4_addr, :verdict})

      assert builder.type == {:ipv4_addr, :verdict}
    end

    test "sets multiple fields at once" do
      builder = Builder.new()
      |> Builder.set(family: :ip6, table: "filter", chain: "INPUT")

      assert builder.family == :ip6
      assert builder.table == "filter"
      assert builder.chain == "INPUT"
    end

    test "sets all context fields at once" do
      builder = Builder.new()
      |> Builder.set(
        family: :inet,
        requestor: MyCustomRequestor,
        table: "nat",
        chain: "PREROUTING",
        collection: "my_set",
        type: :ipv4_addr
      )

      assert builder.family == :inet
      assert builder.requestor == MyCustomRequestor
      assert builder.table == "nat"
      assert builder.chain == "PREROUTING"
      assert builder.collection == "my_set"
      assert builder.type == :ipv4_addr
    end

    test "clears field by setting to nil: table" do
      builder = Builder.new()
      |> Builder.set(table: "filter")
      |> Builder.set(table: nil)

      assert builder.table == nil
    end

    test "clears field by setting to nil: chain" do
      builder = Builder.new()
      |> Builder.set(chain: "INPUT")
      |> Builder.set(chain: nil)

      assert builder.chain == nil
    end

    test "clears multiple fields at once" do
      builder = Builder.new()
      |> Builder.set(table: "filter", chain: "INPUT", collection: "blocklist")
      |> Builder.set(chain: nil, collection: nil)

      assert builder.table == "filter"
      assert builder.chain == nil
      assert builder.collection == nil
    end

    test "chains with other builder operations" do
      builder = Builder.new()
      |> Builder.set(table: "filter", chain: "INPUT")
      |> NFTables.add(rule: [%{accept: nil}])

      assert builder.table == "filter"
      assert builder.chain == "INPUT"
      assert length(builder.commands) == 1
    end

    test "switches context mid-pipeline" do
      builder = Builder.new()
      |> Builder.set(family: :inet, table: "filter")
      |> NFTables.add(chain: "INPUT")
      |> Builder.set(chain: "FORWARD")
      |> NFTables.add(rule: [%{accept: nil}])

      assert builder.chain == "FORWARD"
      assert length(builder.commands) == 2
      [chain_cmd, rule_cmd] = builder.commands
      assert chain_cmd.add.chain.name == "INPUT"
      assert rule_cmd.add.rule.chain == "FORWARD"
    end

    test "raises on invalid family" do
      assert_raise ArgumentError, ~r/Invalid family.*Must be one of/, fn ->
        Builder.new() |> Builder.set(family: :invalid)
      end
    end

    test "raises on invalid field name" do
      assert_raise ArgumentError, ~r/Invalid field.*Valid fields/, fn ->
        Builder.new() |> Builder.set(invalid_field: "value")
      end
    end

    test "raises on trying to set spec" do
      assert_raise ArgumentError, ~r/:spec is an internal field/, fn ->
        Builder.new() |> Builder.set(spec: %{})
      end
    end

    test "raises on trying to set commands" do
      assert_raise ArgumentError, ~r/:commands cannot be set directly/, fn ->
        Builder.new() |> Builder.set(commands: [])
      end
    end

    test "raises on wrong type for table (not string)" do
      assert_raise ArgumentError, ~r/Invalid field/, fn ->
        Builder.new() |> Builder.set(table: :atom_not_string)
      end
    end

    test "raises on wrong type for chain (not string)" do
      assert_raise ArgumentError, ~r/Invalid field/, fn ->
        Builder.new() |> Builder.set(chain: 123)
      end
    end

    test "raises on wrong type for requestor (not atom)" do
      assert_raise ArgumentError, ~r/Invalid field/, fn ->
        Builder.new() |> Builder.set(requestor: "NotAnAtom")
      end
    end

    test "accepts nil for requestor" do
      builder = Builder.new(requestor: MyCustomRequestor)
      |> Builder.set(requestor: nil)

      assert builder.requestor == nil
    end

    test "accepts nil for type" do
      builder = Builder.new()
      |> Builder.set(type: :ipv4_addr)
      |> Builder.set(type: nil)

      assert builder.type == nil
    end
  end

  describe "context tracking" do
    test "sets table context when adding table" do
      builder = Builder.new()
      |> NFTables.add(table: "filter")

      assert builder.table == "filter"
    end

    test "sets chain context when adding chain" do
      builder = Builder.new()
      |> NFTables.add(table: "filter", chain: "INPUT")

      assert builder.chain == "INPUT"
    end
  end

  describe "add(table:)" do
    test "adds table command with default family" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")

      assert length(builder.commands) == 1
      [cmd] = builder.commands

      assert cmd == %{
        add: %{
          table: %{
            family: :inet,
            name: "filter"
          }
        }
      }
    end

    test "adds table with custom family" do
      builder = Builder.new(family: :ip6)
      |> NFTables.add(table: "filter")

      [cmd] = builder.commands
      assert cmd.add.table.family == :ip6
      assert cmd.add.table.name == "filter"
    end
  end

  describe "add(chain:)" do
    test "adds regular chain without hook" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "custom")

      assert length(builder.commands) == 2
      [_table_cmd, chain_cmd] = builder.commands

      assert chain_cmd == %{
        add: %{
          chain: %{
            family: :inet,
            table: "filter",
            name: "custom"
          }
        }
      }
    end

    test "adds base chain with hook" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT",
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      )

      [_table_cmd, chain_cmd] = builder.commands

      assert chain_cmd.add.chain.type == :filter
      assert chain_cmd.add.chain.hook == :input
      assert chain_cmd.add.chain.prio == 0
      assert chain_cmd.add.chain.policy == :drop
    end

    test "uses table context if set" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")

      [_table_cmd, chain_cmd] = builder.commands
      assert chain_cmd.add.chain.table == "filter"
    end
  end

  describe "add(rule:)" do
    test "adds rule with expression list" do
      expr_list = [
        %{match: %{left: %{payload: %{protocol: "ip", field: "saddr"}}, right: "192.168.1.1", op: "=="}},
        %{drop: nil}
      ]

      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter", chain: "INPUT")
      |> NFTables.add(rule: expr_list)

      assert length(builder.commands) == 2
      [_context_cmd, rule_cmd] = builder.commands

      assert rule_cmd.add.rule.family == :inet
      assert rule_cmd.add.rule.table == "filter"
      assert rule_cmd.add.rule.chain == "INPUT"
      assert rule_cmd.add.rule.expr == expr_list
    end

    test "requires table to be set" do
      assert_raise ArgumentError, ~r/table must be specified/, fn ->
        Builder.new()
        |> NFTables.add(chain: "INPUT")
      end
    end

    test "requires chain to be set" do
      expr_list = [%{accept: nil}]

      builder = Builder.new()
      |> NFTables.add(table: "filter")

      assert_raise ArgumentError, ~r/chain must be specified/, fn ->
        NFTables.add(builder, rule: expr_list)
      end
    end
  end

  describe "add with :rules option" do
    test "adds multiple rules in a batch" do
      rule1 = [%{match: %{left: %{payload: %{protocol: "tcp", field: "dport"}}, right: 22, op: "=="}}, %{accept: nil}]
      rule2 = [%{match: %{left: %{payload: %{protocol: "tcp", field: "dport"}}, right: 80, op: "=="}}, %{accept: nil}]

      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter", chain: "INPUT")
      |> NFTables.add(rules: [rule1, rule2])

      # Should create 2 commands: 1 for chain, 1 for batch rules
      assert length(builder.commands) == 2
    end
  end

  describe "delete(table:)" do
    test "adds delete table command" do
      builder = Builder.new(family: :inet)
      |> NFTables.delete(table: "filter")

      [cmd] = builder.commands

      assert cmd == %{
        delete: %{
          table: %{
            family: :inet,
            name: "filter"
          }
        }
      }
    end
  end

  describe "delete(chain:)" do
    test "deletes chain with table context" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.delete(chain: "INPUT")

      [_table_cmd, cmd] = builder.commands

      assert cmd.delete.chain.family == :inet
      assert cmd.delete.chain.table == "filter"
      assert cmd.delete.chain.name == "INPUT"
    end
  end

  describe "delete(rule:)" do
    test "deletes rule by handle" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter", chain: "INPUT")
      |> NFTables.delete(rule: [handle: 42])

      [_context_cmd, cmd] = builder.commands

      assert cmd.delete.rule.family == :inet
      assert cmd.delete.rule.table == "filter"
      assert cmd.delete.rule.chain == "INPUT"
      assert cmd.delete.rule.handle == 42
    end
  end

  describe "flush(table:)" do
    test "flushes table" do
      builder = Builder.new(family: :inet)
      |> NFTables.flush(table: "filter")

      [cmd] = builder.commands

      assert cmd.flush.table.family == :inet
      assert cmd.flush.table.name == "filter"
    end
  end

  describe "flush(chain:)" do
    test "flushes chain" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.flush(chain: "INPUT")

      [_table_cmd, cmd] = builder.commands

      assert cmd.flush.chain.family == :inet
      assert cmd.flush.chain.table == "filter"
      assert cmd.flush.chain.name == "INPUT"
    end
  end

  describe "to_json/1" do
    test "converts builder to JSON string" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")

      json = Builder.to_json(builder)

      assert is_binary(json)
      assert json =~ "nftables"
      assert json =~ "filter"
    end

    test "generates valid JSON for empty builder" do
      builder = Builder.new()
      json = Builder.to_json(builder)

      assert json == ~s({"nftables":[]})
    end

    test "generates valid JSON for multiple commands" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")

      json = Builder.to_json(builder)

      assert is_binary(json)
      {:ok, decoded} = JSON.decode(json)
      assert is_map(decoded)
      assert Map.has_key?(decoded, "nftables")
      assert length(decoded["nftables"]) == 2
    end
  end

  describe "command batching" do
    test "accumulates multiple commands" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")
      |> NFTables.add(chain: "FORWARD")
      |> NFTables.add(chain: "OUTPUT")

      assert length(builder.commands) == 4
    end

    test "maintains command order" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")
      |> NFTables.add(rule: [%{accept: nil}])

      [cmd1, cmd2, cmd3] = builder.commands

      assert Map.has_key?(cmd1, :add)
      assert Map.has_key?(cmd1.add, :table)
      assert Map.has_key?(cmd2, :add)
      assert Map.has_key?(cmd2.add, :chain)
      assert Map.has_key?(cmd3, :add)
      assert Map.has_key?(cmd3.add, :rule)
    end
  end

  describe "context management" do
    test "maintains separate table and chain contexts" do
      builder = Builder.new()
      |> NFTables.add(table: "filter", chain: "INPUT")

      assert builder.table == "filter"
      assert builder.chain == "INPUT"
    end

    test "context persists across multiple operations" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter", chain: "INPUT")
      |> NFTables.add(rule: [%{accept: nil}])
      |> NFTables.add(rule: [%{drop: nil}])

      [_context_cmd, rule1, rule2] = builder.commands

      assert rule1.add.rule.table == "filter"
      assert rule1.add.rule.chain == "INPUT"
      assert rule2.add.rule.table == "filter"
      assert rule2.add.rule.chain == "INPUT"
    end
  end

  describe "set operations" do
    test "add(set:) creates set command" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.add(set: "blocklist", type: :ipv4_addr)

      [_table_cmd, cmd] = builder.commands

      assert cmd.add.set.family == :inet
      assert cmd.add.set.table == "filter"
      assert cmd.add.set.name == "blocklist"
      assert cmd.add.set.type == :ipv4_addr
    end

    test "add(element:) adds elements to set" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter", set: "blocklist", type: :ipv4_addr)
      |> NFTables.add(element: ["192.168.1.1", "192.168.1.2"])

      [_set_cmd, cmd] = builder.commands

      assert cmd.add.element.family == :inet
      assert cmd.add.element.table == "filter"
      assert cmd.add.element.name == "blocklist"
      assert cmd.add.element.elem == ["192.168.1.1", "192.168.1.2"]
    end

    test "delete(element:) deletes elements from set" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter", set: "blocklist", type: :ipv4_addr)
      |> NFTables.delete(element: ["192.168.1.1"])

      [_set_cmd, cmd] = builder.commands

      assert cmd.delete.element.family == :inet
      assert cmd.delete.element.table == "filter"
      assert cmd.delete.element.name == "blocklist"
      assert cmd.delete.element.elem == ["192.168.1.1"]
    end
  end

  describe "complex scenarios" do
    test "builds complete firewall configuration" do
      builder = Builder.new(family: :inet)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
      |> NFTables.add(chain: "FORWARD", type: :filter, hook: :forward, priority: 0, policy: :drop)
      |> NFTables.add(chain: "OUTPUT", type: :filter, hook: :output, priority: 0, policy: :accept)
      |> NFTables.add(rule: [%{match: %{left: %{meta: %{key: "iifname"}}, right: "lo", op: "=="}}, %{accept: nil}])
      |> NFTables.add(rule: [%{match: %{left: %{ct: %{key: "state"}}, right: ["established", "related"], op: "in"}}, %{accept: nil}])

      assert length(builder.commands) == 6
      json = Builder.to_json(builder)
      assert is_binary(json)
      {:ok, decoded} = JSON.decode(json)
      assert length(decoded["nftables"]) == 6
    end
  end
end
