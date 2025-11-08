defmodule NFTex.Set do
  @moduledoc """
  High-level set operations for nftables.

  Sets allow efficient matching against multiple values (IP addresses, ports, etc.).

  ## Quick Start

      # Start NFTex
      {:ok, pid} = NFTex.start_link()

      # Create table first
      :ok = NFTex.Table.create(pid, %{name: "filter", family: :inet})

      # Create a set
      :ok = NFTex.Set.create(pid, %{
        name: "blocklist",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr
      })

      # Add IP addresses to blocklist
      ips = ["192.168.1.100", "10.0.0.50"]
      :ok = NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, ips)

      # List blocked IPs
      {:ok, elements} = NFTex.Set.list_elements(pid, "filter", "blocklist")

      # Remove an IP
      :ok = NFTex.Set.delete_elements(pid, "filter", "blocklist", :inet, ["192.168.1.100"])

  """

  alias NFTex.{Port, JSONBuilder}

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type key_type :: :ipv4_addr | :ipv6_addr | :ether_addr | :inet_protocol | :inet_service
  @type set_spec :: %{
          name: String.t(),
          table: String.t(),
          family: family(),
          key_type: key_type()
        }

  @doc """
  Create a set.

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

      NFTex.Set.create(pid, %{
        name: "banned_ips",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr
      })

  """
  @spec create(pid(), set_spec()) :: :ok | {:error, term()}
  def create(pid, %{name: name, table: table, family: family, key_type: key_type}) do
    # Build JSON command
    cmd = JSONBuilder.add_set(family, table, name, type: key_type_to_string(key_type))
    json = Jason.encode!(cmd)

    # Send to port
    case Port.call(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
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

  @doc """
  Delete a set.

  ## Example

      NFTex.Set.delete(pid, "filter", "banned_ips", :inet)

  """
  @spec delete(pid(), String.t(), String.t(), family()) :: :ok | {:error, term()}
  def delete(pid, table, name, family) do
    # Build JSON command
    cmd = JSONBuilder.delete_set(family, table, name)
    json = Jason.encode!(cmd)

    # Send to port
    case Port.call(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
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

  @doc """
  Add elements to an existing set.

  Elements should be strings in the appropriate format for the key type:
  - IPv4: "192.168.1.100"
  - IPv6: "2001:db8::1"
  - MAC: "aa:bb:cc:dd:ee:ff"
  - Protocol: "tcp" or number
  - Port: "80" or number

  ## Example

      NFTex.Set.add_elements(pid, "filter", "banned_ips", :inet, [
        "192.168.1.200",
        "10.0.0.50"
      ])

  """
  @spec add_elements(pid(), String.t(), String.t(), family(), [String.t()]) ::
          :ok | {:error, term()}
  def add_elements(pid, table, name, family, elements) when is_list(elements) do
    # Build JSON command
    cmd = JSONBuilder.add_element(family, table, name, elements)
    json = Jason.encode!(cmd)

    # Send to port
    case Port.call(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
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

  @doc """
  Remove elements from a set.

  ## Example

      NFTex.Set.delete_elements(pid, "filter", "banned_ips", :inet, [
        "192.168.1.100"
      ])

  """
  @spec delete_elements(pid(), String.t(), String.t(), family(), [String.t()]) ::
          :ok | {:error, term()}
  def delete_elements(pid, table, name, family, elements) when is_list(elements) do
    # Build JSON command
    cmd = JSONBuilder.delete_element(family, table, name, elements)
    json = Jason.encode!(cmd)

    # Send to port
    case Port.call(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
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

  @doc """
  List all sets for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, sets} = NFTex.Set.list(pid)
      {:ok, sets} = NFTex.Set.list(pid, family: :inet6)

      for s <- sets do
        IO.puts("Set: \#{s.name} in table \#{s.table}")
      end

  """
  @spec list(pid(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list(pid, opts \\ []) do
    NFTex.Query.list_sets(pid, opts)
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

      {:ok, elements} = NFTex.Set.list_elements(pid, "filter", "banned_ips")

      for el <- elements do
        IO.puts("Element: \#{inspect(el)}")
      end

  """
  @spec list_elements(pid(), String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_elements(pid, table, set_name, opts \\ []) do
    NFTex.Query.list_set_elements(pid, table, set_name, opts)
  end

  @doc """
  Check if a set exists.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `family` - Protocol family (default: `:inet`)

  ## Examples

      if NFTex.Set.exists?(pid, "filter", "banned_ips", :inet) do
        IO.puts("Set exists")
      end

  """
  @spec exists?(pid(), String.t(), String.t(), family()) :: boolean()
  def exists?(pid, table, set_name, family \\ :inet) do
    case NFTex.Query.list_sets(pid, family: family) do
      {:ok, sets} ->
        Enum.any?(sets, fn set ->
          set.name == set_name and set.table == table
        end)

      {:error, _} ->
        false
    end
  end

  @doc """
  Build a JSON command to create a set (without executing).

  Returns the JSON string that would be sent to create a set.
  Useful for batching, remote execution, or inspection.

  ## Parameters

  - `spec` - Set specification map (same as `create/2`)

  ## Returns

  JSON string containing the set create command

  ## Examples

      json = NFTex.Set.build_create(%{
        name: "blocklist",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr
      })
      #=> "{\\\"nftables\\\":[{\\\"add\\\":{\\\"set\\\":{...}}}]}"

      # Use in batch
      batch =
        Batch.new()
        |> Batch.add(Set.build_create(%{...}))
        |> Batch.add(Set.build_add_elements("filter", "blocklist", :inet, ["1.2.3.4"]))
  """
  @spec build_create(set_spec()) :: binary()
  def build_create(%{name: name, table: table, family: family, key_type: key_type}) do
    cmd = JSONBuilder.add_set(family, table, name, type: key_type_to_string(key_type))
    Jason.encode!(cmd)
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

      json = NFTex.Set.build_delete("filter", "blocklist", :inet)
      NFTex.Executor.execute(json)
  """
  @spec build_delete(String.t(), String.t(), family()) :: binary()
  def build_delete(table, name, family) do
    cmd = JSONBuilder.delete_set(family, table, name)
    Jason.encode!(cmd)
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

      json = NFTex.Set.build_add_elements("filter", "blocklist", :inet, [
        "192.168.1.100",
        "10.0.0.50"
      ])

      NFTex.Executor.execute(json)
  """
  @spec build_add_elements(String.t(), String.t(), family(), [String.t()]) :: binary()
  def build_add_elements(table, name, family, elements) when is_list(elements) do
    cmd = JSONBuilder.add_element(family, table, name, elements)
    Jason.encode!(cmd)
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

      json = NFTex.Set.build_delete_elements("filter", "blocklist", :inet, [
        "192.168.1.100"
      ])

      NFTex.Executor.execute(json)
  """
  @spec build_delete_elements(String.t(), String.t(), family(), [String.t()]) :: binary()
  def build_delete_elements(table, name, family, elements) when is_list(elements) do
    cmd = JSONBuilder.delete_element(family, table, name, elements)
    Jason.encode!(cmd)
  end

  # Private helpers

  defp key_type_to_string(:ipv4_addr), do: "ipv4_addr"
  defp key_type_to_string(:ipv6_addr), do: "ipv6_addr"
  defp key_type_to_string(:ether_addr), do: "ether_addr"
  defp key_type_to_string(:inet_protocol), do: "inet_proto"
  defp key_type_to_string(:inet_service), do: "inet_service"
end
