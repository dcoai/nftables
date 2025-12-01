defmodule NFTables.Local do
  @moduledoc """
  Default local execution requestor for NFTables.

  This module implements the NFTables.Requestor behaviour and provides local
  execution of nftables commands via NFTables.Port. It serves as the default
  requestor for Builder operations.

  NFTables.Local handles:
  - JSON encoding of Elixir command structures
  - Communication with the local NFTables.Port process
  - JSON decoding of responses
  - Error detection and normalization

  ## Usage

  NFTables.Local is the default requestor for Builder.new(), so most users
  won't need to specify it explicitly:

      # Uses NFTables.Local by default
      Builder.new()
      |> Builder.add(table: "filter")
      |> Builder.submit()

  You can also use it explicitly:

      Builder.new(requestor: NFTables.Local)
      |> Builder.add(table: "filter")
      |> Builder.submit(pid: custom_pid, timeout: 10_000)

  Or override at submit time:

      builder = Builder.new(requestor: MyApp.RemoteRequestor)
      |> Builder.add(table: "filter")

      # Override to use local execution
      Builder.submit(builder, requestor: NFTables.Local)

  ## Options

  The following options are supported in the `opts` parameter:

  - `:pid` - NFTables.Port process pid (default: registered process lookup)
  - `:timeout` - Command timeout in milliseconds (default: 5000)

  ## Examples

      # Basic usage with default options (write operation)
      builder = Builder.new()
      |> Builder.add(table: "filter")
      :ok = Builder.submit(builder)

      # With specific port process
      {:ok, pid} = NFTables.start_link()
      builder = Builder.new()
      |> Builder.add(table: "filter")
      Builder.submit(builder, pid: pid)

      # Custom timeout for long operations
      builder = Builder.new()
      |> Builder.add(table: "filter")
      |> Builder.add(chain: "INPUT")
      Builder.submit(builder, timeout: 30_000)

  ## Return Values

  Returns:
  - `:ok` - Successful write operation with no response data
  - `{:ok, response}` - Successful query with decoded response map
  - `{:error, reason}` - On failure

  The module detects errors in nftables JSON responses and normalizes them
  into `{:error, reason}` tuples.
  """

  @behaviour NFTables.Requestor

  alias NFTables.Builder
  alias Jason, as: JSON

  @doc """
  Submit a Builder configuration or raw command map for local execution.

  This is the implementation of the NFTables.Requestor behaviour callback.
  It accepts either a Builder struct or a raw command map, encodes it as JSON,
  sends it to the local NFTables.Port process, and decodes the response.

  ## Parameters

  - `builder_or_command` - NFTables.Builder struct or raw command map
  - `opts` - Options keyword list:
    - `:pid` - NFTables.Port process (default: looks up registered process)
    - `:timeout` - Timeout in milliseconds (default: 5000)

  ## Returns

  - `:ok` - Successful write operation with no response data
  - `{:ok, response}` - Successful query with decoded response map
  - `{:error, reason}` - On failure

  ## Examples

      # With Builder struct (write operation)
      builder = Builder.new()
      |> Builder.add(table: "filter")
      :ok = NFTables.Local.submit(builder, [])

      # With raw command map (query operation)
      command = %{nftables: [%{list: %{tables: %{}}}]}
      {:ok, response} = NFTables.Local.submit(command, pid: pid)

      # With options (write operation)
      :ok = NFTables.Local.submit(builder, pid: custom_pid, timeout: 10_000)
  """
  @impl true
  def submit(builder_or_command, opts) when is_list(opts) do
    # Convert Builder struct to command map if needed
    command = case builder_or_command do
      %{__struct__: Builder} -> Builder.to_map(builder_or_command)
      map when is_map(map) -> map
    end

    execute_command(command, opts)
  end

  # Private function that does the actual execution
  defp execute_command(command, opts) when is_map(command) do

    # Encode Elixir map to JSON (this is the ONLY place JSON encoding happens)
    json_string = JSON.encode!(command)

    # Get port pid and timeout from options
    pid = get_port_pid(opts)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Execute via NFTables.Port
    case NFTables.Port.commit(pid, json_string, timeout) do
      {:ok, ""} ->
        # Empty response is success (write operations)
        :ok

      {:ok, response_json} ->
        # Decode JSON response to Elixir structures (ONLY place JSON decoding happens)
        case JSON.decode(response_json, keys: :atoms) do
          {:ok, %{nftables: items} = decoded} when is_list(items) ->
            # Check if any item contains an error
            case Enum.find(items, fn item -> Map.has_key?(item, :error) end) do
              %{error: error} -> {:error, error}
              nil -> {:ok, decoded}  # Return decoded Elixir map
            end

          {:ok, %{error: error}} ->
            {:error, error}

          {:ok, decoded} ->
            # Valid JSON but unexpected format, return decoded data
            {:ok, decoded}

          {:error, _reason} ->
            # Not valid JSON, could be plain error text
            if String.contains?(response_json, "does not exist") or
               String.contains?(response_json, "No such") or
               String.contains?(response_json, "not found") or
               String.contains?(response_json, "Error:") do
              {:error, response_json}
            else
              # Return raw response wrapped in a map
              {:ok, %{raw_response: response_json}}
            end
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private helpers

  @doc false
  defp get_port_pid(opts) do
    case Keyword.fetch(opts, :pid) do
      {:ok, pid} when is_pid(pid) ->
        pid

      :error ->
        # Try to find registered NFTables.Port process
        case Process.whereis(NFTables.Port) do
          nil ->
            raise ArgumentError, """
            No NFTables.Port process found. Either:
            1. Start NFTables with: NFTables.start_link()
            2. Pass pid explicitly: Builder.submit(builder, pid: pid)
            """

          pid ->
            pid
        end
    end
  end
end
