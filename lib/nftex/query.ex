defmodule NFTablesEx.Query do
  @moduledoc """
  High-level API for querying nftables resources.

  Provides convenient functions for listing tables, chains, rules, sets,
  and set elements with automatic parsing of JSON responses.

  ## Quick Start

      {:ok, pid} = NFTablesEx.start_link()

      # List all tables
      {:ok, tables} = NFTablesEx.Query.list_tables(pid, family: :inet)

      # List all sets
      {:ok, sets} = NFTablesEx.Query.list_sets(pid, family: :inet)

      # List elements in a specific set
      {:ok, elements} = NFTablesEx.Query.list_set_elements(pid, "filter", "blocklist")

  """

  alias NFTablesEx.Port

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type result(t) :: {:ok, t} | {:error, term()}

  ## Table Operations

  @doc """
  List all tables for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, tables} = NFTablesEx.Query.list_tables(pid)
      {:ok, tables} = NFTablesEx.Query.list_tables(pid, family: :inet6)
  """
  @spec list_tables(pid(), keyword()) :: result([map()])
  def list_tables(pid, opts \\ []) do
    family = Keyword.get(opts, :family)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Build JSON command
    cmd =
      if family do
        %{"nftables" => [%{"list" => %{"tables" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"list" => %{"tables" => %{}}}]}
      end

    json = cmd |> JSON.encode!()

    # Send to port
    case Port.commit(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case JSON.decode(response_json) do
          {:ok, %{"nftables" => items}} ->
            tables = items
              |> Enum.filter(&Map.has_key?(&1, "table"))
              |> Enum.map(fn %{"table" => t} ->
                %{
                  name: t["name"],
                  family: String.to_atom(t["family"]),
                  handle: t["handle"]
                }
              end)
            {:ok, tables}

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## Chain Operations

  @doc """
  List all chains for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, chains} = NFTablesEx.Query.list_chains(pid)
      {:ok, chains} = NFTablesEx.Query.list_chains(pid, family: :inet6)
  """
  @spec list_chains(pid(), keyword()) :: result([map()])
  def list_chains(pid, opts \\ []) do
    family = Keyword.get(opts, :family)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Use list_ruleset to get chains
    cmd =
      if family do
        %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
      end

    json = cmd |> JSON.encode!()

    case Port.commit(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case JSON.decode(response_json) do
          {:ok, %{"nftables" => items}} ->
            chains = items
              |> Enum.filter(&Map.has_key?(&1, "chain"))
              |> Enum.map(fn %{"chain" => c} ->
                %{
                  name: c["name"],
                  table: c["table"],
                  family: String.to_atom(c["family"]),
                  handle: c["handle"],
                  type: c["type"] && String.to_atom(c["type"]),
                  hook: c["hook"] && String.to_atom(c["hook"]),
                  prio: c["prio"],
                  policy: c["policy"] && String.to_atom(c["policy"])
                }
              end)
            {:ok, chains}

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## Rule Operations

  @doc """
  List all rules in a specific chain.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name
  - `chain` - Chain name
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, rules} = NFTablesEx.Query.list_rules(pid, "filter", "input")
      {:ok, rules} = NFTablesEx.Query.list_rules(pid, "filter", "input", family: :inet6)

  ## List all rules for a family

      {:ok, rules} = NFTablesEx.Query.list_rules(pid, family: :inet)
  """
  @spec list_rules(pid(), keyword()) :: result([map()])
  @spec list_rules(pid(), String.t(), String.t()) :: result([map()])
  @spec list_rules(pid(), String.t(), String.t(), keyword()) :: result([map()])
  def list_rules(pid, opts) when is_list(opts) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Use list ruleset to get all rules
    cmd =
      if family do
        %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
      end

    json = cmd |> JSON.encode!()

    case Port.commit(pid, json, timeout) do
      {:ok, ""} ->
        {:ok, []}

      {:ok, response_json} ->
        case JSON.decode(response_json) do
          {:ok, %{"nftables" => items}} ->
            rules = items
              |> Enum.filter(&Map.has_key?(&1, "rule"))
              |> Enum.map(fn %{"rule" => r} ->
                %{
                  family: String.to_atom(r["family"]),
                  table: r["table"],
                  chain: r["chain"],
                  handle: r["handle"],
                  expr: r["expr"]
                }
              end)
            {:ok, rules}

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, _reason} ->
            # JSON decode failed - likely a plain text response
            # For list operations, treat non-JSON responses as empty results
            # (empty chains return informational messages in some nftables versions)
            {:ok, []}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  def list_rules(pid, table, chain), do: list_rules(pid, table, chain, [])

  def list_rules(pid, table, chain, opts) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Use list_chain to get rules
    cmd = %{
      "nftables" => [
        %{
          "list" => %{
            "chain" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => chain
            }
          }
        }
      ]
    }

    json = cmd |> JSON.encode!()

    case Port.commit(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case JSON.decode(response_json) do
          {:ok, %{"nftables" => items}} ->
            rules = items
              |> Enum.filter(&Map.has_key?(&1, "rule"))
              |> Enum.map(fn %{"rule" => r} ->
                %{
                  family: String.to_atom(r["family"]),
                  table: r["table"],
                  chain: r["chain"],
                  handle: r["handle"],
                  expr: r["expr"]
                }
              end)
            {:ok, rules}

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, _reason} ->
            # JSON decode failed - likely a plain text response
            # For list operations, treat non-JSON responses as empty results
            # (empty chains return informational messages in some nftables versions)
            {:ok, []}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## Set Operations

  @doc """
  List all sets for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, sets} = NFTablesEx.Query.list_sets(pid)
      {:ok, sets} = NFTablesEx.Query.list_sets(pid, family: :inet6)
  """
  @spec list_sets(pid(), keyword()) :: result([map()])
  def list_sets(pid, opts \\ []) do
    family = Keyword.get(opts, :family)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Use list_ruleset to get sets
    cmd =
      if family do
        %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
      end

    json = cmd |> JSON.encode!()

    case Port.commit(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case JSON.decode(response_json) do
          {:ok, %{"nftables" => items}} ->
            sets = items
              |> Enum.filter(&Map.has_key?(&1, "set"))
              |> Enum.map(fn %{"set" => s} ->
                %{
                  name: s["name"],
                  table: s["table"],
                  family: String.to_atom(s["family"]),
                  handle: s["handle"],
                  key_type: s["type"],
                  key_len: s["key_len"],
                  flags: s["flags"]
                }
              end)
            {:ok, sets}

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## Set Element Operations

  @doc """
  List elements in a specific set.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, elements} = NFTablesEx.Query.list_set_elements(pid, "filter", "blocked_ips")
  """
  @spec list_set_elements(pid(), String.t(), String.t(), keyword()) :: result([map()])
  def list_set_elements(pid, table, set_name, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Use list_set to get elements
    cmd = %{
      "nftables" => [
        %{
          "list" => %{
            "set" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => set_name
            }
          }
        }
      ]
    }

    json = cmd |> JSON.encode!()

    case Port.commit(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case JSON.decode(response_json) do
          {:ok, %{"nftables" => items}} ->
            # Find the set object which contains elements
            elements = items
              |> Enum.find_value([], fn
                %{"set" => %{"elem" => elems}} when is_list(elems) -> elems
                _ -> false
              end)
              |> List.wrap()
              |> Enum.map(fn elem ->
                # Elements can be strings or maps
                case elem do
                  val when is_binary(val) -> %{value: val}
                  val when is_map(val) -> val
                  val -> %{value: inspect(val)}
                end
              end)

            {:ok, elements}

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Delete elements from a set.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name
  - `set_name` - Set name
  - `elements` - List of element values (strings)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Example

      :ok = NFTablesEx.Query.delete_set_elements(pid, "filter", "blocked_ips", ["192.168.1.100"])
  """
  @spec delete_set_elements(pid(), String.t(), String.t(), [String.t()], keyword()) :: :ok | {:error, term()}
  def delete_set_elements(pid, table, set_name, elements, opts \\ []) when is_list(elements) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Build JSON command
    cmd = %{
      "nftables" => [
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
      ]
    }

    json = cmd |> JSON.encode!()

    # Send to port
    case Port.commit(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        case JSON.decode(response_json) do
          {:ok, %{"nftables" => _}} ->
            :ok

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## Build Functions (for distributed firewall support)

  @doc """
  Build a JSON command to list tables without executing it.

  Returns a JSON string that can be sent to a remote node or executed later.

  ## Options

  - `:family` - Protocol family (optional)

  ## Examples

      # List all tables
      json = NFTablesEx.Query.build_list_tables()

      # List tables for specific family
      json = NFTablesEx.Query.build_list_tables(family: :inet)

      # Send to remote node
      MyTransport.send_to_node("firewall-1", json)
  """
  @spec build_list_tables(keyword()) :: String.t()
  def build_list_tables(opts \\ []) do
    family = Keyword.get(opts, :family)

    cmd =
      if family do
        %{"nftables" => [%{"list" => %{"tables" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"list" => %{"tables" => %{}}}]}
      end

    cmd |> JSON.encode!()
  end

  @doc """
  Build a JSON command to list chains without executing it.

  Returns a JSON string that can be sent to a remote node or executed later.

  ## Options

  - `:family` - Protocol family (optional)

  ## Examples

      json = NFTablesEx.Query.build_list_chains()
      json = NFTablesEx.Query.build_list_chains(family: :inet)
  """
  @spec build_list_chains(keyword()) :: String.t()
  def build_list_chains(opts \\ []) do
    family = Keyword.get(opts, :family)

    cmd =
      if family do
        %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
      end

    cmd |> JSON.encode!()
  end

  @doc """
  Build a JSON command to list rules without executing it.

  Returns a JSON string that can be sent to a remote node or executed later.

  ## Parameters

  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)

  Or:

  - `table` - Table name (string)
  - `chain` - Chain name (string)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)

  ## Examples

      # List all rules for a family
      json = NFTablesEx.Query.build_list_rules(family: :inet)

      # List rules in specific chain
      json = NFTablesEx.Query.build_list_rules("filter", "input")
      json = NFTablesEx.Query.build_list_rules("filter", "input", family: :inet6)
  """
  @spec build_list_rules(keyword()) :: String.t()
  @spec build_list_rules(String.t(), String.t()) :: String.t()
  @spec build_list_rules(String.t(), String.t(), keyword()) :: String.t()
  def build_list_rules(opts) when is_list(opts) do
    family = Keyword.get(opts, :family, :inet)

    cmd =
      if family do
        %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
      end

    cmd |> JSON.encode!()
  end

  def build_list_rules(table, chain) when is_binary(table) and is_binary(chain) do
    build_list_rules(table, chain, [])
  end

  def build_list_rules(table, chain, opts) when is_binary(table) and is_binary(chain) and is_list(opts) do
    family = Keyword.get(opts, :family, :inet)

    cmd = %{
      "nftables" => [
        %{
          "list" => %{
            "chain" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => chain
            }
          }
        }
      ]
    }

    cmd |> JSON.encode!()
  end

  @doc """
  Build a JSON command to list sets without executing it.

  Returns a JSON string that can be sent to a remote node or executed later.

  ## Options

  - `:family` - Protocol family (optional)

  ## Examples

      json = NFTablesEx.Query.build_list_sets()
      json = NFTablesEx.Query.build_list_sets(family: :inet)
  """
  @spec build_list_sets(keyword()) :: String.t()
  def build_list_sets(opts \\ []) do
    family = Keyword.get(opts, :family)

    cmd =
      if family do
        %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
      end

    cmd |> JSON.encode!()
  end

  @doc """
  Build a JSON command to list set elements without executing it.

  Returns a JSON string that can be sent to a remote node or executed later.

  ## Parameters

  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)

  ## Examples

      json = NFTablesEx.Query.build_list_set_elements("filter", "blocklist")
      json = NFTablesEx.Query.build_list_set_elements("filter", "blocklist", family: :inet6)
  """
  @spec build_list_set_elements(String.t(), String.t(), keyword()) :: String.t()
  def build_list_set_elements(table, set_name, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)

    cmd = %{
      "nftables" => [
        %{
          "list" => %{
            "set" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => set_name
            }
          }
        }
      ]
    }

    cmd |> JSON.encode!()
  end

  @doc """
  Build a JSON command to list the entire ruleset without executing it.

  Returns a JSON string that can be sent to a remote node or executed later.

  ## Options

  - `:family` - Protocol family (optional, default: list all families)

  ## Examples

      # List entire ruleset
      json = NFTablesEx.Query.build_list_ruleset()

      # List ruleset for specific family
      json = NFTablesEx.Query.build_list_ruleset(family: :inet)
  """
  @spec build_list_ruleset(keyword()) :: String.t()
  def build_list_ruleset(opts \\ []) do
    family = Keyword.get(opts, :family)

    cmd =
      if family do
        %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
      end

    cmd |> JSON.encode!()
  end

  @doc """
  Build a JSON command to flush the ruleset without executing it.

  Returns a JSON string that can be sent to a remote node or executed later.

  ## Options

  - `:family` - Protocol family (optional, default: flush all families)

  ## Examples

      # Flush entire ruleset
      json = NFTablesEx.Query.build_flush_ruleset()

      # Flush ruleset for specific family
      json = NFTablesEx.Query.build_flush_ruleset(family: :inet)
  """
  @spec build_flush_ruleset(keyword()) :: String.t()
  def build_flush_ruleset(opts \\ []) do
    family = Keyword.get(opts, :family)

    cmd =
      if family do
        %{"nftables" => [%{"flush" => %{"ruleset" => %{"family" => to_string(family)}}}]}
      else
        %{"nftables" => [%{"flush" => %{"ruleset" => %{}}}]}
      end

    cmd |> JSON.encode!()
  end

  @doc """
  Flush the ruleset (delete all tables, chains, rules, sets).

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (optional, default: flush all families)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      # Flush entire ruleset (all families)
      :ok = NFTablesEx.Query.flush_ruleset(pid)

      # Flush only inet family
      :ok = NFTablesEx.Query.flush_ruleset(pid, family: :inet)
  """
  @spec flush_ruleset(pid(), keyword()) :: :ok | {:error, term()}
  def flush_ruleset(pid, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5000)
    json = build_flush_ruleset(opts)

    case Port.commit(pid, json, timeout) do
      {:ok, ""} ->
        :ok

      {:ok, response_json} ->
        case JSON.decode(response_json) do
          {:ok, %{"nftables" => _}} ->
            :ok

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
