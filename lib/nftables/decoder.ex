defmodule NFTables.Decoder do
  @moduledoc """
  Universal decoder for all nftables responses.

  Handles read operations, write operations, mixed operations, and errors.

  ## Architecture

  The Decoder sits between NFTables.Local and user code, transforming nftables JSON
  responses into idiomatic Elixir structures:

  ```
  Query.list_tables()             # Build command (pure function)
  |> NFTables.Local.submit(pid: pid)  # Execute & JSON decode
  |> Decoder.decode()             # Transform to Elixir
  ```

  ## Response Types

  ### Write-Only Responses
  Empty responses from write operations (add, delete, flush):

      :ok

  ### Read-Only Responses
  Data responses from list operations, flat structure matching nftables:

      {:ok, %{
        tables: [%{name: "filter", family: :inet, ...}],
        chains: [%{name: "INPUT", table: "filter", ...}],
        rules: [%{handle: 5, table: "filter", chain: "INPUT", ...}],
        sets: [%{name: "blocklist", table: "filter", ...}]
      }}

  Empty lists are filtered out automatically.

  ### Mixed Responses
  Operations with both writes and reads:

      {:ok, %{
        operations: [:success, :success],
        data: %{tables: [...], chains: [...]}
      }}

  ### Error Responses
  Contextual errors indicating operation type:

      {:error, {:write_failed, reason}}
      {:error, {:read_failed, reason}}
      {:error, {:mixed_failed, reason}}

  ## Examples

      # Write operation
      Builder.new()
      |> NFTables.add(table: "filter", family: :inet)
      |> NFTables.submit(pid: pid)
      #=> :ok

      # Read operation
      Query.list_tables(family: :inet)
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
      #=> {:ok, %{tables: [...]}}
  """

  @type decoded_data :: %{
          optional(:tables) => [map()],
          optional(:chains) => [map()],
          optional(:rules) => [map()],
          optional(:sets) => [map()]
        }

  @type decoded_response ::
          :ok
          | {:ok, decoded_data()}
          | {:ok, %{operations: [:success], data: decoded_data()}}
          | {:error, {atom(), term()}}

  @doc """
  Universal decode function that handles any nftables response.

  Automatically detects response type (write/read/mixed/error) and transforms
  to appropriate Elixir structure.

  ## Parameters

  - `response` - The response tuple from NFTables.Local.submit/2

  ## Returns

  - `:ok` - For successful write-only operations
  - `{:ok, %{...}}` - For read-only operations with data
  - `{:ok, %{operations: [...], data: %{...}}}` - For mixed operations
  - `{:error, {context, reason}}` - For errors with context

  ## Examples

      # Write-only (empty response)
      Decoder.decode({:ok, %{}})
      #=> :ok

      # Read-only (has data)
      Decoder.decode({:ok, %{"nftables" => [%{"table" => ...}]}})
      #=> {:ok, %{tables: [...]}}

      # Mixed (batch with writes and reads)
      Decoder.decode({:ok, %{"nftables" => [empty, %{"table" => ...}]}})
      #=> {:ok, %{operations: [:success], data: %{tables: [...]}}}

      # Error
      Decoder.decode({:error, "Table already exists"})
      #=> {:error, {:write_failed, "Table already exists"}}
  """
  @spec decode({:ok, map()} | {:error, term()}) :: decoded_response()
  def decode({:ok, %{nftables: []}}) do
    # Empty nftables array - could be write success OR empty read result
    # Return empty read result format for consistency
    {:ok, %{}}
  end

  def decode({:ok, %{nftables: items}}) when is_list(items) do
    # Filter out metainfo items (nftables metadata, not data or operations)
    items = Enum.reject(items, &is_metainfo_item?/1)

    case detect_response_type(items) do
      :write_only -> :ok
      :read_only -> decode_read_only(items)
      :mixed -> decode_mixed(items)
    end
  end

  def decode({:ok, %{}}), do: :ok

  def decode({:error, reason}) do
    # Try to infer context from error message
    context =
      cond do
        is_binary(reason) and String.contains?(reason, ["add", "delete", "flush", "create"]) ->
          :write_failed

        is_binary(reason) and String.contains?(reason, ["list", "get", "query"]) ->
          :read_failed

        true ->
          :operation_failed
      end

    {:error, {context, reason}}
  end

  # Private Functions

  # Detect response type by analyzing items
  defp detect_response_type(items) do
    has_data = Enum.any?(items, &is_data_item?/1)
    has_empty = Enum.any?(items, &is_empty_item?/1)

    cond do
      has_data and has_empty -> :mixed
      has_data -> :read_only
      true -> :write_only
    end
  end

  # Metainfo items are nftables metadata (version info, etc.)
  defp is_metainfo_item?(%{metainfo: _}), do: true
  defp is_metainfo_item?(_), do: false

  # Data items have recognizable resource keys
  defp is_data_item?(item) when is_map(item) do
    Map.has_key?(item, :table) or
      Map.has_key?(item, :chain) or
      Map.has_key?(item, :rule) or
      Map.has_key?(item, :set) or
      Map.has_key?(item, :element)
  end

  defp is_data_item?(_), do: false

  # Empty items are maps with no recognizable keys or empty maps
  defp is_empty_item?(item) when is_map(item) do
    not is_data_item?(item)
  end

  defp is_empty_item?(_), do: true

  # Decode read-only response (only data items)
  defp decode_read_only(items) do
    # Extract set elements from sets that have "elem" field
    set_items = items |> Enum.filter(&Map.has_key?(&1, :set))

    set_elements =
      set_items
      |> Enum.filter(fn %{set: s} -> Map.has_key?(s, :elem) end)
      |> Enum.flat_map(&extract_set_elements/1)

    decoded = %{
      tables: items |> Enum.filter(&Map.has_key?(&1, :table)) |> Enum.map(&decode_table/1),
      chains: items |> Enum.filter(&Map.has_key?(&1, :chain)) |> Enum.map(&decode_chain/1),
      rules: items |> Enum.filter(&Map.has_key?(&1, :rule)) |> Enum.map(&decode_rule/1),
      sets: set_items |> Enum.map(&decode_set/1),
      set_elements: set_elements
    }

    # Filter out empty lists for cleaner response
    result =
      decoded
      |> Enum.reject(fn {_k, v} -> Enum.empty?(v) end)
      |> Map.new()

    {:ok, result}
  end

  # Decode mixed response (both write confirmations and data)
  defp decode_mixed(items) do
    # Count successful write operations (empty items)
    operation_count = Enum.count(items, &is_empty_item?/1)
    operations = List.duplicate(:success, operation_count)

    # Decode data items
    {:ok, data} = decode_read_only(items)

    {:ok, %{operations: operations, data: data}}
  end

  # Singular Decoders (private, composable)

  # Decode a single table item
  defp decode_table(%{table: t}) do
    %{
      name: t.name,
      family: t.family,
      handle: t[:handle]
    }
  end

  defp decode_table(%{chain: c}) do
    %{
      table: c.table,
      family: c.family
    }
  end

  defp decode_table(%{rule: r}) do
    %{
      table: r.table,
      family: r.family
    }
  end

  defp decode_table(%{set: s}) do
    %{
      table: s.table,
      family: s.family
    }
  end

  # Decode a single chain item (reuses decode_table)
  defp decode_chain(%{chain: c} = item) do
    decode_table(item)
    |> Map.merge(%{
      name: c.name,
      handle: c[:handle],
      type: c[:type],
      hook: c[:hook],
      prio: c[:prio],
      policy: c[:policy]
    })
  end

  defp decode_chain(%{rule: r} = item) do
    decode_table(item)
    |> Map.put(:chain, r.chain)
  end

  # Decode a single rule item (reuses decode_chain which reuses decode_table)
  defp decode_rule(%{rule: r} = item) do
    decode_chain(item)
    |> Map.merge(%{
      handle: r[:handle],
      expr: convert_ranges_to_elixir(r[:expr])
    })
  end

  # Decode a single set item (reuses decode_table)
  defp decode_set(%{set: s} = item) do
    decode_table(item)
    |> Map.merge(%{
      name: s.name,
      handle: s[:handle],
      key_type: s[:type],
      key_len: s[:key_len],
      flags: s[:flags]
    })
  end

  # Extract set elements from a set item that has "elem" field
  defp extract_set_elements(%{set: s}) do
    case s[:elem] do
      elems when is_list(elems) ->
        Enum.map(elems, fn elem ->
          # Elements can be simple values or maps with "val" key
          case elem do
            val when is_binary(val) or is_integer(val) -> %{value: val}
            %{val: val} -> %{value: val}
            other -> %{value: other}
          end
        end)

      _ ->
        []
    end
  end

  # Convert JSON range arrays to Elixir ranges
  # Recursively walks through maps and lists, converting {range: [min, max]} to min..max
  defp convert_ranges_to_elixir(%{range: [min, max]} = map)
       when is_integer(min) and is_integer(max) do
    # Replace the range array with an Elixir range
    Map.put(map, :range, min..max)
  end

  defp convert_ranges_to_elixir(map) when is_map(map) do
    # Recursively process all values in the map
    Map.new(map, fn {k, v} -> {k, convert_ranges_to_elixir(v)} end)
  end

  defp convert_ranges_to_elixir(list) when is_list(list) do
    # Recursively process all items in the list
    Enum.map(list, &convert_ranges_to_elixir/1)
  end

  defp convert_ranges_to_elixir(other), do: other
end
