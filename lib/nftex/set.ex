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
  def add(pid, %{name: _name, table: _table, family: _family, key_type: _key_type} = spec) do
    build_add(spec)
    |> NFTablesEx.Executor.execute(pid: pid)
    |> NFTablesEx.Decoder.decode()
  end

  @doc """
  Delete a set.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `name` - Set name (string)
  - `family` - Protocol family (default: `:inet`)

  ## Example

      :ok = NFTablesEx.Set.delete(pid, "filter", "banned_ips", :inet)

  """
  @spec delete(pid(), String.t(), String.t(), family()) :: :ok | {:error, term()}
  def delete(pid, table, name, family \\ :inet) do
    build_delete(table, name, family)
    |> NFTablesEx.Executor.execute(pid: pid)
    |> NFTablesEx.Decoder.decode()
  end

  @doc """
  Add elements to an existing set.

  Elements should be strings in the appropriate format for the key type:
  - IPv4: "192.168.1.100"
  - IPv6: "2001:db8::1"
  - MAC: "aa:bb:cc:dd:ee:ff"
  - Protocol: "tcp" or number
  - Port: "80" or number

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `name` - Set name (string)
  - `family` - Protocol family (default: `:inet`)
  - `elements` - List of element strings

  ## Example

      :ok = NFTablesEx.Set.add_elements(pid, "filter", "banned_ips", :inet, [
        "192.168.1.200",
        "10.0.0.50"
      ])

  """
  @spec add_elements(pid(), String.t(), String.t(), family(), [String.t()]) ::
          :ok | {:error, term()}
  def add_elements(pid, table, name, family \\ :inet, elements) when is_list(elements) do
    build_add_elements(table, name, family, elements)
    |> NFTablesEx.Executor.execute(pid: pid)
    |> NFTablesEx.Decoder.decode()
  end

  @doc """
  Remove elements from a set.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `name` - Set name (string)
  - `family` - Protocol family (default: `:inet`)
  - `elements` - List of element strings

  ## Example

      :ok = NFTablesEx.Set.delete_elements(pid, "filter", "banned_ips", :inet, [
        "192.168.1.100"
      ])

  """
  @spec delete_elements(pid(), String.t(), String.t(), family(), [String.t()]) ::
          :ok | {:error, term()}
  def delete_elements(pid, table, name, family \\ :inet, elements) when is_list(elements) do
    build_delete_elements(table, name, family, elements)
    |> NFTablesEx.Executor.execute(pid: pid)
    |> NFTablesEx.Decoder.decode()
  end

  @doc """
  Build a command map to add a set (without executing).

  Returns a map that would be sent to add a set.
  Useful for batching, remote execution, or inspection.

  ## Parameters

  - `spec` - Set specification map (same as `add/2`)

  ## Returns

  Map containing the set add command

  ## Examples

      cmd = NFTablesEx.Set.build_add(%{
        name: "blocklist",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr
      })
      #=> %{"nftables" => [%{"add" => %{"set" => ...}}]}

      # Use in batch
      batch =
        Batch.new()
        |> Batch.add(Set.build_add(%{...}))
        |> Batch.add(Set.build_add_elements("filter", "blocklist", :inet, ["1.2.3.4"]))
  """
  @spec build_add(set_spec()) :: map()
  def build_add(%{name: name, table: table, family: family, key_type: key_type}) do
    %{
      "nftables" => [
        %{
          "add" => %{
            "set" => %{
              "family" => family,
              "table" => table,
              "name" => name,
              "type" => key_type_to_string(key_type)
            }
          }
        }
      ]
    }
  end

  @doc """
  Build a command map to delete a set (without executing).

  Returns a map that would be sent to delete a set.

  ## Parameters

  - `table` - Table name
  - `name` - Set name
  - `family` - Protocol family

  ## Returns

  Map containing the set delete command

  ## Examples

      cmd = NFTablesEx.Set.build_delete("filter", "blocklist", :inet)
      NFTablesEx.Executor.execute(cmd)
  """
  @spec build_delete(String.t(), String.t(), family()) :: map()
  def build_delete(table, name, family) do
    %{
      "nftables" => [
        %{
          "delete" => %{
            "set" => %{
              "family" => family,
              "table" => table,
              "name" => name
            }
          }
        }
      ]
    }
  end

  @doc """
  Build a command map to add elements to a set (without executing).

  Returns a map that would be sent to add elements to a set.

  ## Parameters

  - `table` - Table name
  - `name` - Set name
  - `family` - Protocol family
  - `elements` - List of element strings

  ## Returns

  Map containing the add elements command

  ## Examples

      cmd = NFTablesEx.Set.build_add_elements("filter", "blocklist", :inet, [
        "192.168.1.100",
        "10.0.0.50"
      ])

      NFTablesEx.Executor.execute(cmd)
  """
  @spec build_add_elements(String.t(), String.t(), family(), [String.t()]) :: map()
  def build_add_elements(table, name, family, elements) when is_list(elements) do
    %{
      "nftables" => [
        %{
          "add" => %{
            "element" => %{
              "family" => family,
              "table" => table,
              "name" => name,
              "elem" => elements
            }
          }
        }
      ]
    }
  end

  @doc """
  Build a command map to delete elements from a set (without executing).

  Returns a map that would be sent to delete elements from a set.

  ## Parameters

  - `table` - Table name
  - `name` - Set name
  - `family` - Protocol family
  - `elements` - List of element strings

  ## Returns

  Map containing the delete elements command

  ## Examples

      cmd = NFTablesEx.Set.build_delete_elements("filter", "blocklist", :inet, [
        "192.168.1.100"
      ])

      NFTablesEx.Executor.execute(cmd)
  """
  @spec build_delete_elements(String.t(), String.t(), family(), [String.t()]) :: map()
  def build_delete_elements(table, name, family, elements) when is_list(elements) do
    %{
      "nftables" => [
        %{
          "delete" => %{
            "element" => %{
              "family" => family,
              "table" => table,
              "name" => name,
              "elem" => elements
            }
          }
        }
      ]
    }
  end

  # Private helpers

  defp key_type_to_string(:ipv4_addr), do: "ipv4_addr"
  defp key_type_to_string(:ipv6_addr), do: "ipv6_addr"
  defp key_type_to_string(:ether_addr), do: "ether_addr"
  defp key_type_to_string(:inet_protocol), do: "inet_proto"
  defp key_type_to_string(:inet_service), do: "inet_service"
end
