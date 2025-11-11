defmodule NFTablesEx.Set do
  @moduledoc """
  High-level set operations for nftables.

  Sets allow efficient matching against multiple values (IP addresses, ports, etc.).

  ## Quick Start

      # Start NFTex
      {:ok, pid} = NFTablesEx.start_link()

      # Create table first
      :ok = NFTablesEx.Table.add(pid, %{name: "filter", family: :inet})

      # Add a set
      :ok = NFTablesEx.Set.add(pid, %{
        name: "blocklist",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr
      })

      # Add IP addresses to blocklist
      ips = ["192.168.1.100", "10.0.0.50"]
      :ok = NFTablesEx.Set.add_elements(pid, "filter", "blocklist", :inet, ips)

      # List blocked IPs
      {:ok, elements} = NFTablesEx.Set.list_elements(pid, "filter", "blocklist")

      # Remove an IP
      :ok = NFTablesEx.Set.delete_elements(pid, "filter", "blocklist", :inet, ["192.168.1.100"])

  """

  alias NFTablesEx.Port

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type key_type :: :ipv4_addr | :ipv6_addr | :ether_addr | :inet_protocol | :inet_service
  @type set_spec :: %{
          name: String.t(),
          table: String.t(),
          family: family(),
          key_type: key_type()
        }

  @doc """
  Add a set.

  ## Parameters

  - `name` - Set name (required)
  - `table` - Table name (required)
  - `family` - Protocol family (required)
  - `key_type` - Key data type (required)

  ## Key Types

  - `:ipv4_addr` - IPv4 address
  - `:ipv6_addr` - IPv6 address
  - `:ether_addr` - Ethernet MAC address
  - `:inet_protocol` - IP protocol number
  - `:inet_service` - Port number

  ## Example

      NFTablesEx.Set.add(pid, %{
        name: "banned_ips",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr
      })

  """
  @spec add(pid(), set_spec()) :: :ok | {:error, term()}
  def add(pid, %{name: name, table: table, family: family, key_type: key_type}) do
    # Build JSON command
    cmd = %{
      "nftables" => [
        %{
          "add" => %{
            "set" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => name,
              "type" => key_type_to_string(key_type)
            }
          }
        }
      ]
    }

    json = cmd |> JSON.encode!()

    # Send to port
    case Port.commit(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
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

  @doc """
  Delete a set.

  ## Example

      NFTablesEx.Set.delete(pid, "filter", "banned_ips", :inet)

  """
  @spec delete(pid(), String.t(), String.t(), family()) :: :ok | {:error, term()}
  def delete(pid, table, name, family) do
    # Build JSON command
    cmd = %{
      "nftables" => [
        %{
          "delete" => %{
            "set" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => name
            }
          }
        }
      ]
    }

    json = cmd |> JSON.encode!()

    # Send to port
    case Port.commit(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
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

  @doc """
  Add elements to an existing set.

  Elements should be strings in the appropriate format for the key type:
  - IPv4: "192.168.1.100"
  - IPv6: "2001:db8::1"
  - MAC: "aa:bb:cc:dd:ee:ff"
  - Protocol: "tcp" or number
  - Port: "80" or number

  ## Example

      NFTablesEx.Set.add_elements(pid, "filter", "banned_ips", :inet, [
        "192.168.1.200",
        "10.0.0.50"
      ])

  """
  @spec add_elements(pid(), String.t(), String.t(), family(), [String.t()]) ::
          :ok | {:error, term()}
  def add_elements(pid, table, name, family, elements) when is_list(elements) do
    # Build JSON command
    cmd = %{
      "nftables" => [
        %{
          "add" => %{
            "element" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => name,
              "elem" => elements
            }
          }
        }
      ]
    }

    json = cmd |> JSON.encode!()

    # Send to port
    case Port.commit(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
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

  @doc """
  Remove elements from a set.

  ## Example

      NFTablesEx.Set.delete_elements(pid, "filter", "banned_ips", :inet, [
        "192.168.1.100"
      ])

  """
  @spec delete_elements(pid(), String.t(), String.t(), family(), [String.t()]) ::
          :ok | {:error, term()}
  def delete_elements(pid, table, name, family, elements) when is_list(elements) do
    # Build JSON command
    cmd = %{
      "nftables" => [
        %{
          "delete" => %{
            "element" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => name,
              "elem" => elements
            }
          }
        }
      ]
    }

    json = cmd |> JSON.encode!()

    # Send to port
    case Port.commit(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
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

  @doc """
  List all sets for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, sets} = NFTablesEx.Set.list(pid)
      {:ok, sets} = NFTablesEx.Set.list(pid, family: :inet6)

      for s <- sets do
        IO.puts("Set: \#{s.name} in table \#{s.table}")
      end

  """
  @spec list(pid(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list(pid, opts \\ []) do
    NFTablesEx.Query.list_sets(pid, opts)
  end

  @doc """
  List elements in a specific set.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, elements} = NFTablesEx.Set.list_elements(pid, "filter", "banned_ips")

      for el <- elements do
        IO.puts("Element: \#{inspect(el)}")
      end

  """
  @spec list_elements(pid(), String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_elements(pid, table, set_name, opts \\ []) do
    NFTablesEx.Query.list_set_elements(pid, table, set_name, opts)
  end

  @doc """
  Check if a set exists.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `family` - Protocol family (default: `:inet`)

  ## Examples

      if NFTablesEx.Set.exists?(pid, "filter", "banned_ips", :inet) do
        IO.puts("Set exists")
      end

  """
  @spec exists?(pid(), String.t(), String.t(), family()) :: boolean()
  def exists?(pid, table, set_name, family \\ :inet) do
    case NFTablesEx.Query.list_sets(pid, family: family) do
      {:ok, sets} ->
        Enum.any?(sets, fn set ->
          set.name == set_name and set.table == table
        end)

      {:error, _} ->
        false
    end
  end

  @doc """
  Build a JSON command to add a set (without executing).

  Returns the JSON string that would be sent to add a set.
  Useful for batching, remote execution, or inspection.

  ## Parameters

  - `spec` - Set specification map (same as `add/2`)

  ## Returns

  JSON string containing the set add command

  ## Examples

      json = NFTablesEx.Set.build_add(%{
        name: "blocklist",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr
      })
      #=> "{\\\"nftables\\\":[{\\\"add\\\":{\\\"set\\\":{...}}}]}"

      # Use in batch
      batch =
        Batch.new()
        |> Batch.add(Set.build_add(%{...}))
        |> Batch.add(Set.build_add_elements("filter", "blocklist", :inet, ["1.2.3.4"]))
  """
  @spec build_add(set_spec()) :: binary()
  def build_add(%{name: name, table: table, family: family, key_type: key_type}) do
    cmd = %{
      "nftables" => [
        %{
          "add" => %{
            "set" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => name,
              "type" => key_type_to_string(key_type)
            }
          }
        }
      ]
    }

    cmd |> JSON.encode!()
  end

  @doc """
  Build a JSON command to delete a set (without executing).

  Returns the JSON string that would be sent to delete a set.

  ## Parameters

  - `table` - Table name
  - `name` - Set name
  - `family` - Protocol family

  ## Returns

  JSON string containing the set delete command

  ## Examples

      json = NFTablesEx.Set.build_delete("filter", "blocklist", :inet)
      NFTablesEx.Executor.execute(json)
  """
  @spec build_delete(String.t(), String.t(), family()) :: binary()
  def build_delete(table, name, family) do
    cmd = %{
      "nftables" => [
        %{
          "delete" => %{
            "set" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => name
            }
          }
        }
      ]
    }

    cmd |> JSON.encode!()
  end

  @doc """
  Build a JSON command to add elements to a set (without executing).

  Returns the JSON string that would be sent to add elements to a set.

  ## Parameters

  - `table` - Table name
  - `name` - Set name
  - `family` - Protocol family
  - `elements` - List of element strings

  ## Returns

  JSON string containing the add elements command

  ## Examples

      json = NFTablesEx.Set.build_add_elements("filter", "blocklist", :inet, [
        "192.168.1.100",
        "10.0.0.50"
      ])

      NFTablesEx.Executor.execute(json)
  """
  @spec build_add_elements(String.t(), String.t(), family(), [String.t()]) :: binary()
  def build_add_elements(table, name, family, elements) when is_list(elements) do
    cmd = %{
      "nftables" => [
        %{
          "add" => %{
            "element" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => name,
              "elem" => elements
            }
          }
        }
      ]
    }

    cmd |> JSON.encode!()
  end

  @doc """
  Build a JSON command to delete elements from a set (without executing).

  Returns the JSON string that would be sent to delete elements from a set.

  ## Parameters

  - `table` - Table name
  - `name` - Set name
  - `family` - Protocol family
  - `elements` - List of element strings

  ## Returns

  JSON string containing the delete elements command

  ## Examples

      json = NFTablesEx.Set.build_delete_elements("filter", "blocklist", :inet, [
        "192.168.1.100"
      ])

      NFTablesEx.Executor.execute(json)
  """
  @spec build_delete_elements(String.t(), String.t(), family(), [String.t()]) :: binary()
  def build_delete_elements(table, name, family, elements) when is_list(elements) do
    cmd = %{
      "nftables" => [
        %{
          "delete" => %{
            "element" => %{
              "family" => to_string(family),
              "table" => table,
              "name" => name,
              "elem" => elements
            }
          }
        }
      ]
    }

    cmd |> JSON.encode!()
  end

  # Private helpers

  defp key_type_to_string(:ipv4_addr), do: "ipv4_addr"
  defp key_type_to_string(:ipv6_addr), do: "ipv6_addr"
  defp key_type_to_string(:ether_addr), do: "ether_addr"
  defp key_type_to_string(:inet_protocol), do: "inet_proto"
  defp key_type_to_string(:inet_service), do: "inet_service"
end
