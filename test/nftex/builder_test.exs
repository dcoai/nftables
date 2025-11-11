defmodule NFTablesEx.BuilderTest do
  use ExUnit.Case, async: true

  alias NFTablesEx.Builder

  describe "new/1" do
    test "creates a new builder with default family" do
      builder = Builder.new()
      assert builder.family == :inet
      assert builder.commands == []
      assert builder.current_table == nil
      assert builder.current_chain == nil
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

  describe "set_table/2" do
    test "sets current table context" do
      builder = Builder.new()
      |> Builder.set_table("filter")

      assert builder.current_table == "filter"
    end
  end

  describe "set_chain/2" do
    test "sets current chain context" do
      builder = Builder.new()
      |> Builder.set_chain("INPUT")

      assert builder.current_chain == "INPUT"
    end
  end

  describe "add_table/2" do
    test "adds table command with default family" do
      builder = Builder.new(family: :inet)
      |> Builder.add_table("filter")

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
      |> Builder.add_table("filter")

      [cmd] = builder.commands
      assert cmd.add.table.family == :ip6
      assert cmd.add.table.name == "filter"
    end
  end

  describe "add_chain/3" do
    test "adds regular chain without hook" do
      builder = Builder.new(family: :inet)
      |> Builder.add_table("filter")
      |> Builder.add_chain("custom")

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
      |> Builder.set_table("filter")
      |> Builder.add_chain("INPUT",
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      )

      [chain_cmd] = builder.commands

      assert chain_cmd.add.chain.type == :filter
      assert chain_cmd.add.chain.hook == :input
      assert chain_cmd.add.chain.prio == 0
      assert chain_cmd.add.chain.policy == :drop
    end

    test "uses current_table context if set" do
      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.add_chain("INPUT")

      [chain_cmd] = builder.commands
      assert chain_cmd.add.chain.table == "filter"
    end
  end

  describe "add_rule/2" do
    test "adds rule with expression list" do
      expr_list = [
        %{match: %{left: %{payload: %{protocol: "ip", field: "saddr"}}, right: "192.168.1.1", op: "=="}},
        %{drop: nil}
      ]

      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.set_chain("INPUT")
      |> Builder.add_rule(expr_list)

      assert length(builder.commands) == 1
      [rule_cmd] = builder.commands

      assert rule_cmd.add.rule.family == :inet
      assert rule_cmd.add.rule.table == "filter"
      assert rule_cmd.add.rule.chain == "INPUT"
      assert rule_cmd.add.rule.expr == expr_list
    end

    test "requires current_table to be set" do
      expr_list = [%{accept: nil}]

      builder = Builder.new()
      |> Builder.set_chain("INPUT")

      assert_raise ArgumentError, ~r/table and chain must be specified/, fn ->
        Builder.add_rule(builder, expr_list)
      end
    end

    test "requires current_chain to be set" do
      expr_list = [%{accept: nil}]

      builder = Builder.new()
      |> Builder.set_table("filter")

      assert_raise ArgumentError, ~r/table and chain must be specified/, fn ->
        Builder.add_rule(builder, expr_list)
      end
    end
  end

  describe "add_rules/2" do
    test "adds multiple rules" do
      rule1 = [%{match: %{left: %{payload: %{protocol: "tcp", field: "dport"}}, right: 22, op: "=="}}, %{accept: nil}]
      rule2 = [%{match: %{left: %{payload: %{protocol: "tcp", field: "dport"}}, right: 80, op: "=="}}, %{accept: nil}]

      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.set_chain("INPUT")
      |> Builder.add_rules([rule1, rule2])

      assert length(builder.commands) == 2
    end
  end

  describe "delete_table/2" do
    test "adds delete table command" do
      builder = Builder.new(family: :inet)
      |> Builder.delete_table("filter")

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

  describe "delete_chain/2" do
    test "deletes chain with current_table context" do
      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.delete_chain("INPUT")

      [cmd] = builder.commands

      assert cmd.delete.chain.family == :inet
      assert cmd.delete.chain.table == "filter"
      assert cmd.delete.chain.name == "INPUT"
    end
  end

  describe "delete_rule/2" do
    test "deletes rule by handle" do
      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.set_chain("INPUT")
      |> Builder.delete_rule(handle: 42)

      [cmd] = builder.commands

      assert cmd.delete.rule.family == :inet
      assert cmd.delete.rule.table == "filter"
      assert cmd.delete.rule.chain == "INPUT"
      assert cmd.delete.rule.handle == 42
    end
  end

  describe "flush_table/2" do
    test "flushes table" do
      builder = Builder.new(family: :inet)
      |> Builder.flush_table("filter")

      [cmd] = builder.commands

      assert cmd.flush.table.family == :inet
      assert cmd.flush.table.name == "filter"
    end
  end

  describe "flush_chain/2" do
    test "flushes chain" do
      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.flush_chain("INPUT")

      [cmd] = builder.commands

      assert cmd.flush.chain.family == :inet
      assert cmd.flush.chain.table == "filter"
      assert cmd.flush.chain.name == "INPUT"
    end
  end

  describe "to_json/1" do
    test "converts builder to JSON string" do
      builder = Builder.new(family: :inet)
      |> Builder.add_table("filter")

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
      |> Builder.add_table("filter")
      |> Builder.add_chain("INPUT")

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
      |> Builder.add_table("filter")
      |> Builder.add_chain("INPUT")
      |> Builder.add_chain("FORWARD")
      |> Builder.add_chain("OUTPUT")

      assert length(builder.commands) == 4
    end

    test "maintains command order" do
      builder = Builder.new(family: :inet)
      |> Builder.add_table("filter")
      |> Builder.set_table("filter")
      |> Builder.add_chain("INPUT")
      |> Builder.set_chain("INPUT")
      |> Builder.add_rule([%{accept: nil}])

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
      |> Builder.set_table("filter")
      |> Builder.set_chain("INPUT")

      assert builder.current_table == "filter"
      assert builder.current_chain == "INPUT"
    end

    test "context persists across multiple operations" do
      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.set_chain("INPUT")
      |> Builder.add_rule([%{accept: nil}])
      |> Builder.add_rule([%{drop: nil}])

      [rule1, rule2] = builder.commands

      assert rule1.add.rule.table == "filter"
      assert rule1.add.rule.chain == "INPUT"
      assert rule2.add.rule.table == "filter"
      assert rule2.add.rule.chain == "INPUT"
    end
  end

  describe "set operations" do
    test "add_set/3 creates set command" do
      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.add_set("blocklist", type: :ipv4_addr)

      [cmd] = builder.commands

      assert cmd.add.set.family == :inet
      assert cmd.add.set.table == "filter"
      assert cmd.add.set.name == "blocklist"
      assert cmd.add.set.type == :ipv4_addr
    end

    test "add_elements/3 adds elements to set" do
      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.add_elements("blocklist", ["192.168.1.1", "192.168.1.2"])

      [cmd] = builder.commands

      assert cmd.add.element.family == :inet
      assert cmd.add.element.table == "filter"
      assert cmd.add.element.name == "blocklist"
      assert cmd.add.element.elem == ["192.168.1.1", "192.168.1.2"]
    end

    test "delete_elements/3 deletes elements from set" do
      builder = Builder.new(family: :inet)
      |> Builder.set_table("filter")
      |> Builder.delete_elements("blocklist", ["192.168.1.1"])

      [cmd] = builder.commands

      assert cmd.delete.element.family == :inet
      assert cmd.delete.element.table == "filter"
      assert cmd.delete.element.name == "blocklist"
      assert cmd.delete.element.elem == ["192.168.1.1"]
    end
  end

  describe "complex scenarios" do
    test "builds complete firewall configuration" do
      builder = Builder.new(family: :inet)
      |> Builder.add_table("filter")
      |> Builder.set_table("filter")
      |> Builder.add_chain("INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
      |> Builder.add_chain("FORWARD", type: :filter, hook: :forward, priority: 0, policy: :drop)
      |> Builder.add_chain("OUTPUT", type: :filter, hook: :output, priority: 0, policy: :accept)
      |> Builder.set_chain("INPUT")
      |> Builder.add_rule([%{match: %{left: %{meta: %{key: "iifname"}}, right: "lo", op: "=="}}, %{accept: nil}])
      |> Builder.add_rule([%{match: %{left: %{ct: %{key: "state"}}, right: ["established", "related"], op: "in"}}, %{accept: nil}])

      assert length(builder.commands) == 6
      json = Builder.to_json(builder)
      assert is_binary(json)
      {:ok, decoded} = JSON.decode(json)
      assert length(decoded["nftables"]) == 6
    end
  end
end
