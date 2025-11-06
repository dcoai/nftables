defmodule NFTex.Query do
  @moduledoc """
  High-level API for querying nftables resources.

  Provides convenient functions for listing tables, chains, rules, sets,
  and set elements with automatic parsing of JSON responses.

  ## Quick Start

      {:ok, pid} = NFTex.start_link()

      # List all tables
      {:ok, tables} = NFTex.Query.list_tables(pid, family: :inet)

      # List all sets
      {:ok, sets} = NFTex.Query.list_sets(pid, family: :inet)

      # List elements in a specific set
      {:ok, elements} = NFTex.Query.list_set_elements(pid, "filter", "blocklist")

  """

  alias NFTex.{JSONPort, JSONBuilder}

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

      {:ok, tables} = NFTex.Query.list_tables(pid)
      {:ok, tables} = NFTex.Query.list_tables(pid, family: :inet6)
  """
  @spec list_tables(pid(), keyword()) :: result([map()])
  def list_tables(pid, opts \\ []) do
    family = Keyword.get(opts, :family)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Build JSON command
    cmd = JSONBuilder.list_tables(family: family)
    json = Jason.encode!(cmd)

    # Send to port
    case JSONPort.call(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case Jason.decode(response_json) do
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

      {:ok, chains} = NFTex.Query.list_chains(pid)
      {:ok, chains} = NFTex.Query.list_chains(pid, family: :inet6)
  """
  @spec list_chains(pid(), keyword()) :: result([map()])
  def list_chains(pid, opts \\ []) do
    family = Keyword.get(opts, :family)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Use list_ruleset to get chains
    cmd = JSONBuilder.list_ruleset(family: family)
    json = Jason.encode!(cmd)

    case JSONPort.call(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case Jason.decode(response_json) do
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

      {:ok, rules} = NFTex.Query.list_rules(pid, "filter", "input")
      {:ok, rules} = NFTex.Query.list_rules(pid, "filter", "input", family: :inet6)

  ## List all rules for a family

      {:ok, rules} = NFTex.Query.list_rules(pid, family: :inet)
  """
  @spec list_rules(pid(), keyword()) :: result([map()])
  @spec list_rules(pid(), String.t(), String.t()) :: result([map()])
  @spec list_rules(pid(), String.t(), String.t(), keyword()) :: result([map()])
  def list_rules(pid, opts) when is_list(opts) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Use list ruleset to get all rules
    cmd = JSONBuilder.list_ruleset(family: family)
    json = Jason.encode!(cmd)

    case JSONPort.call(pid, json, timeout) do
      {:ok, ""} ->
        {:ok, []}

      {:ok, response_json} ->
        case Jason.decode(response_json) do
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

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
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
    cmd = JSONBuilder.list_chain(family, table, chain)
    json = Jason.encode!(cmd)

    case JSONPort.call(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case Jason.decode(response_json) do
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

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
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

      {:ok, sets} = NFTex.Query.list_sets(pid)
      {:ok, sets} = NFTex.Query.list_sets(pid, family: :inet6)
  """
  @spec list_sets(pid(), keyword()) :: result([map()])
  def list_sets(pid, opts \\ []) do
    family = Keyword.get(opts, :family)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Use list_ruleset to get sets
    cmd = JSONBuilder.list_ruleset(family: family)
    json = Jason.encode!(cmd)

    case JSONPort.call(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case Jason.decode(response_json) do
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

      {:ok, elements} = NFTex.Query.list_set_elements(pid, "filter", "blocked_ips")
  """
  @spec list_set_elements(pid(), String.t(), String.t(), keyword()) :: result([map()])
  def list_set_elements(pid, table, set_name, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Use list_set to get elements
    cmd = JSONBuilder.list_set(family, table, set_name)
    json = Jason.encode!(cmd)

    case JSONPort.call(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response - return empty list
        {:ok, []}

      {:ok, response_json} ->
        case Jason.decode(response_json) do
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

      :ok = NFTex.Query.delete_set_elements(pid, "filter", "blocked_ips", ["192.168.1.100"])
  """
  @spec delete_set_elements(pid(), String.t(), String.t(), [String.t()], keyword()) :: :ok | {:error, term()}
  def delete_set_elements(pid, table, set_name, elements, opts \\ []) when is_list(elements) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Build JSON command
    cmd = JSONBuilder.delete_element(family, table, set_name, elements)
    json = Jason.encode!(cmd)

    # Send to port
    case JSONPort.call(pid, json, timeout) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        case Jason.decode(response_json) do
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
