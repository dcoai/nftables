#!/usr/bin/env elixir

# Distributed Query Example
# Demonstrates how to build query commands without executing them,
# useful for distributed firewall architectures where queries are
# built on a C&C node and executed on remote firewall nodes.

Mix.install([{:nftables_ex, path: Path.expand("..", __DIR__)}])

alias NFTables.Query

defmodule DistributedQueryExample do
  @moduledoc """
  Example of using Query builder functions for distributed firewall operations.
  """

  def demonstrate_query_builders do
    IO.puts """
    ========================================
    Distributed Query Builder Example
    ========================================

    The Query module now provides build_* functions that generate
    JSON commands without executing them. These can be sent to
    remote nodes for execution.
    """

    # 1. Build query for listing tables
    IO.puts "\n1. List all tables (any family):"
    json = Query.build_list_tables()
    IO.puts "   JSON: #{json}"

    # 2. Build query for specific family
    IO.puts "\n2. List tables for inet family:"
    json = Query.build_list_tables(family: :inet)
    IO.puts "   JSON: #{json}"

    # 3. Build query for chains
    IO.puts "\n3. List all chains:"
    json = Query.build_list_chains(family: :inet)
    IO.puts "   JSON: #{json}"

    # 4. Build query for rules in specific chain
    IO.puts "\n4. List rules in specific chain:"
    json = Query.build_list_rules("filter", "INPUT")
    IO.puts "   JSON: #{json}"

    # 5. Build query for all rules
    IO.puts "\n5. List all rules for family:"
    json = Query.build_list_rules(family: :inet)
    IO.puts "   JSON: #{json}"

    # 6. Build query for sets
    IO.puts "\n6. List all sets:"
    json = Query.build_list_sets(family: :inet)
    IO.puts "   JSON: #{json}"

    # 7. Build query for set elements
    IO.puts "\n7. List elements in specific set:"
    json = Query.build_list_set_elements("filter", "blocklist")
    IO.puts "   JSON: #{json}"

    # 8. Build query for entire ruleset
    IO.puts "\n8. List entire ruleset:"
    json = Query.build_list_ruleset(family: :inet)
    IO.puts "   JSON: #{json}"

    # 9. Build flush command
    IO.puts "\n9. Flush ruleset (inet family):"
    json = Query.build_flush_ruleset(family: :inet)
    IO.puts "   JSON: #{json}"

    IO.puts """

    ========================================
    Distributed Firewall Usage Pattern
    ========================================
    """

    demonstrate_distributed_pattern()
  end

  def demonstrate_distributed_pattern do
    IO.puts """
    # On Command & Control Node:
    # Build query commands centrally

    defmodule MyApp.FirewallMonitor do
      alias NFTables.Query

      # Collect firewall state from multiple nodes
      def collect_firewall_state(nodes) do
        # Build queries
        queries = [
          {"tables", Query.build_list_tables(family: :inet)},
          {"chains", Query.build_list_chains(family: :inet)},
          {"rules", Query.build_list_rules(family: :inet)},
          {"sets", Query.build_list_sets(family: :inet)}
        ]

        # Send to all nodes in parallel
        nodes
        |> Enum.map(fn node ->
          Task.async(fn ->
            execute_queries_on_node(node, queries)
          end)
        end)
        |> Task.await_many(timeout: 10_000)
      end

      defp execute_queries_on_node(node, queries) do
        Enum.map(queries, fn {name, json_cmd} ->
          # Send via your transport (Phoenix PubSub, gRPC, etc.)
          response = MyTransport.execute_on_node(node, json_cmd)
          {name, response}
        end)
      end
    end

    # On Firewall Node:
    # Minimal execution layer

    defmodule MyApp.FirewallNode do
      def execute_command(json_cmd) do
        {:ok, pid} = NFTables.Port.start_link()

        # Execute the pre-built command
        case NFTables.Port.commit(pid, json_cmd, 5000) do
          {:ok, response} -> {:ok, response}
          {:error, reason} -> {:error, reason}
        end
      end
    end

    # Usage:
    # On C&C node
    state = MyApp.FirewallMonitor.collect_firewall_state([
      "firewall-1.local",
      "firewall-2.local",
      "firewall-3.local"
    ])

    # Analyze collected state
    IO.inspect(state, label: "Collected Firewall State")
    """
  end
end

# Run the demonstration
DistributedQueryExample.demonstrate_query_builders()
