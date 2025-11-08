defmodule NFTex.JSONBuilder do
  @moduledoc """
  Helper functions to build nftables JSON commands.

  This module provides convenient functions to construct nftables JSON
  command structures that can be sent to the JSON port.

  All functions return Elixir maps that should be encoded to JSON using
  `Jason.encode!/1` before sending to the port.

  ## Example

      # Build command
      cmd = NFTex.JSONBuilder.add_table("inet", "mytest")

      # Encode to JSON
      json = Jason.encode!(cmd)

      # Send to port
      {:ok, response_json} = NFTex.Port.call(pid, json)

  ## Reference

  For complete JSON format documentation, see:
  https://wiki.nftables.org/wiki-nftables/index.php/JSON_API
  """

  @type family :: String.t() | atom()
  @type table_name :: String.t()
  @type chain_name :: String.t()
  @type set_name :: String.t()

  @doc """
  Build an "add table" command.

  ## Example

      NFTex.JSONBuilder.add_table("inet", "filter")
      #=> %{"nftables" => [%{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}}]}
  """
  @spec add_table(family(), table_name()) :: map()
  def add_table(family, name) when is_binary(name) do
    nftables([
      %{
        "add" => %{
          "table" => %{
            "family" => to_string(family),
            "name" => name
          }
        }
      }
    ])
  end

  @doc """
  Build a "delete table" command.
  """
  @spec delete_table(family(), table_name()) :: map()
  def delete_table(family, name) when is_binary(name) do
    nftables([
      %{
        "delete" => %{
          "table" => %{
            "family" => to_string(family),
            "name" => name
          }
        }
      }
    ])
  end

  @doc """
  Build a "list tables" command.

  ## Options

  - `:family` - Filter by family (optional)
  """
  @spec list_tables(keyword()) :: map()
  def list_tables(opts \\ []) do
    table_spec =
      case Keyword.get(opts, :family) do
        nil -> %{}
        family -> %{"family" => to_string(family)}
      end

    nftables([%{"list" => %{"tables" => table_spec}}])
  end

  @doc """
  Build an "add chain" command.

  ## Options

  - `:type` - Chain type ("filter", "nat", "route")
  - `:hook` - Netfilter hook ("prerouting", "input", "forward", "output", "postrouting")
  - `:priority` - Chain priority (integer)
  - `:policy` - Chain policy ("accept" or "drop")
  """
  @spec add_chain(family(), table_name(), chain_name(), keyword()) :: map()
  def add_chain(family, table, name, opts \\ []) when is_binary(table) and is_binary(name) do
    chain_spec =
      %{
        "family" => to_string(family),
        "table" => table,
        "name" => name
      }
      |> maybe_put("type", Keyword.get(opts, :type))
      |> maybe_put("hook", Keyword.get(opts, :hook))
      |> maybe_put("prio", Keyword.get(opts, :priority))
      |> maybe_put("policy", Keyword.get(opts, :policy))

    nftables([%{"add" => %{"chain" => chain_spec}}])
  end

  @doc """
  Build a "delete chain" command.
  """
  @spec delete_chain(family(), table_name(), chain_name()) :: map()
  def delete_chain(family, table, name) when is_binary(table) and is_binary(name) do
    nftables([
      %{
        "delete" => %{
          "chain" => %{
            "family" => to_string(family),
            "table" => table,
            "name" => name
          }
        }
      }
    ])
  end

  @doc """
  Build an "add set" command.

  ## Options

  - `:type` - Set key type (required, e.g., "ipv4_addr", "ipv6_addr", "ether_addr")
  - `:flags` - Set flags list (e.g., ["constant", "interval"])
  - `:timeout` - Default element timeout in seconds
  - `:gc_interval` - Garbage collection interval in seconds
  - `:size` - Maximum set size

  ## Example

      NFTex.JSONBuilder.add_set("inet", "filter", "blocklist", type: "ipv4_addr")
  """
  @spec add_set(family(), table_name(), set_name(), keyword()) :: map()
  def add_set(family, table, name, opts) when is_binary(table) and is_binary(name) do
    unless Keyword.has_key?(opts, :type) do
      raise ArgumentError, "add_set requires :type option"
    end

    set_spec =
      %{
        "family" => to_string(family),
        "table" => table,
        "name" => name,
        "type" => Keyword.fetch!(opts, :type)
      }
      |> maybe_put("flags", Keyword.get(opts, :flags))
      |> maybe_put("timeout", Keyword.get(opts, :timeout))
      |> maybe_put("gc-interval", Keyword.get(opts, :gc_interval))
      |> maybe_put("size", Keyword.get(opts, :size))

    nftables([%{"add" => %{"set" => set_spec}}])
  end

  @doc """
  Build a "delete set" command.
  """
  @spec delete_set(family(), table_name(), set_name()) :: map()
  def delete_set(family, table, name) when is_binary(table) and is_binary(name) do
    nftables([
      %{
        "delete" => %{
          "set" => %{
            "family" => to_string(family),
            "table" => table,
            "name" => name
          }
        }
      }
    ])
  end

  @doc """
  Build an "add element" command for a set.

  ## Parameters

  - `family` - Protocol family
  - `table` - Table name
  - `set` - Set name
  - `elements` - List of element values (strings)

  ## Example

      NFTex.JSONBuilder.add_element("inet", "filter", "blocklist", ["192.168.1.1", "192.168.1.2"])
  """
  @spec add_element(family(), table_name(), set_name(), [String.t()]) :: map()
  def add_element(family, table, set_name, elements)
      when is_binary(table) and is_binary(set_name) and is_list(elements) do
    nftables([
      %{
        "add" => %{
          "element" => %{
            "family" => to_string(family),
            "table" => table,
            "name" => set_name,
            "elem" => elements
          }
        }
      }
    ])
  end

  @doc """
  Build a "delete element" command for a set.
  """
  @spec delete_element(family(), table_name(), set_name(), [String.t()]) :: map()
  def delete_element(family, table, set_name, elements)
      when is_binary(table) and is_binary(set_name) and is_list(elements) do
    nftables([
      %{
        "delete" => %{
          "element" => %{
            "family" => to_string(family),
            "table" => table,
            "name" => set_name,
            "elem" => elements
          }
        }
      }
    ])
  end

  @doc """
  Build an "add rule" command.

  ## Parameters

  - `family` - Protocol family
  - `table` - Table name
  - `chain` - Chain name
  - `rule_expr` - Rule expression (list of expression maps or string)

  ## Example

      # Using nft syntax string
      NFTex.JSONBuilder.add_rule("inet", "filter", "input", "ip saddr 192.168.1.1 drop")

      # Using expression list (more complex)
      NFTex.JSONBuilder.add_rule("inet", "filter", "input", [
        %{"match" => %{"left" => %{"payload" => %{"protocol" => "ip", "field" => "saddr"}},
                        "right" => "192.168.1.1",
                        "op" => "=="}},
        %{"drop" => nil}
      ])
  """
  @spec add_rule(family(), table_name(), chain_name(), String.t() | list()) :: map()
  def add_rule(family, table, chain, rule_expr)
      when is_binary(table) and is_binary(chain) do
    rule_spec =
      %{
        "family" => to_string(family),
        "table" => table,
        "chain" => chain
      }
      |> put_rule_expr(rule_expr)

    nftables([%{"add" => %{"rule" => rule_spec}}])
  end

  @doc """
  Build a "delete rule" command by handle.

  ## Example

      NFTex.JSONBuilder.delete_rule(:inet, "filter", "input", 42)
  """
  @spec delete_rule(family(), table_name(), chain_name(), integer()) :: map()
  def delete_rule(family, table, chain, handle)
      when is_binary(table) and is_binary(chain) and is_integer(handle) do
    rule_spec = %{
      "family" => to_string(family),
      "table" => table,
      "chain" => chain,
      "handle" => handle
    }

    nftables([%{"delete" => %{"rule" => rule_spec}}])
  end

  @doc """
  Build a "list ruleset" command.

  ## Options

  - `:family` - Filter by family (optional)
  """
  @spec list_ruleset(keyword()) :: map()
  def list_ruleset(opts \\ []) do
    ruleset_spec =
      case Keyword.get(opts, :family) do
        nil -> %{}
        family -> %{"family" => to_string(family)}
      end

    nftables([%{"list" => %{"ruleset" => ruleset_spec}}])
  end

  @doc """
  Build a "flush ruleset" command.

  ## Options

  - `:family` - Flush only this family (optional, default: flush all)
  """
  @spec flush_ruleset(keyword()) :: map()
  def flush_ruleset(opts \\ []) do
    ruleset_spec =
      case Keyword.get(opts, :family) do
        nil -> %{}
        family -> %{"family" => to_string(family)}
      end

    nftables([%{"flush" => %{"ruleset" => ruleset_spec}}])
  end

  @doc """
  Build a "list chain" command to get rules in a specific chain.

  ## Example

      NFTex.JSONBuilder.list_chain(:inet, "filter", "input")
  """
  @spec list_chain(family(), table_name(), String.t()) :: map()
  def list_chain(family, table, chain) when is_binary(table) and is_binary(chain) do
    chain_spec = %{
      "family" => to_string(family),
      "table" => table,
      "name" => chain
    }

    nftables([%{"list" => %{"chain" => chain_spec}}])
  end

  @doc """
  Build a "list set" command to get elements in a specific set.

  ## Example

      NFTex.JSONBuilder.list_set(:inet, "filter", "blocked_ips")
  """
  @spec list_set(family(), table_name(), String.t()) :: map()
  def list_set(family, table, set_name) when is_binary(table) and is_binary(set_name) do
    set_spec = %{
      "family" => to_string(family),
      "table" => table,
      "name" => set_name
    }

    nftables([%{"list" => %{"set" => set_spec}}])
  end

  ## Private Helpers

  # Wrap commands in nftables root object
  defp nftables(commands) when is_list(commands) do
    %{"nftables" => commands}
  end

  # Conditionally add a key/value to map if value is not nil
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  # Put rule expression (handle both string syntax and expression list)
  defp put_rule_expr(map, expr) when is_binary(expr) do
    Map.put(map, "expr", expr)
  end

  defp put_rule_expr(map, expr) when is_list(expr) do
    Map.put(map, "expr", expr)
  end
end
