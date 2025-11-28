defmodule NFTables.Executor do
  @moduledoc """
  Command execution abstraction for NFTables.

  This module provides a clean interface for executing nftables JSON commands,
  decoupling command building from execution. This enables:

  - Local execution via NFTables.Port
  - Remote execution via custom transports
  - Command inspection and logging
  - Testing without actual firewall changes

  ## Examples

      # Local execution (default)
      json = Table.build_add(%{name: "filter", family: :inet})
      {:ok, response} = Executor.execute(json)

      # With specific port process
      {:ok, pid} = NFTables.start_link()
      Executor.execute(json, pid: pid)

      # Custom timeout
      Executor.execute(json, timeout: 10_000)

  ## For Distributed Firewalls

  Applications can implement custom executors for remote nodes:

      defmodule MyApp.RemoteExecutor do
        def execute(command, opts) do
          node = Keyword.fetch!(opts, :node)
          MyTransport.send_to_node(node, command)
        end
      end

      # Use it
      json = Rule.build_block_ip("filter", "INPUT", "1.2.3.4")
      MyApp.RemoteExecutor.execute(json, node: "firewall-1")

  """

  alias NFTables.Builder

  @doc """
  Execute an nftables command from a Builder struct or Elixir data structures.

  This is the only place where JSON encoding/decoding happens. All other
  modules should work with pure Elixir maps, atoms, lists, etc.

  ## Parameters

  - `builder_or_command` - Builder struct or Map containing nftables commands
  - `opts` - Options:
    - `:pid` - NFTables.Port process (default: looks up registered process)
    - `:timeout` - Timeout in milliseconds (default: 5000)

  ## Returns

  - `{:ok, response}` - Decoded response map on success
  - `{:error, reason}` - On failure

  ## Examples

      # Execute with Builder
      Builder.new()
      |> Builder.add(table: "filter")
      |> Executor.execute(pid)

      # Execute with Elixir map
      command = %{nftables: [%{list: %{tables: %{family: "inet"}}}]}
      {:ok, response} = Executor.execute(command)

      # Execute with specific port pid
      {:ok, pid} = NFTables.start_link()
      Executor.execute(command, pid: pid)

      # Custom timeout for long operations
      Executor.execute(command, timeout: 30_000)
  """
  @spec execute(Builder.t() | map(), keyword() | pid()) :: {:ok, term()} | {:error, term()}
  # Default value header
  def execute(command_or_builder, opts_or_pid \\ [])

  # Handle Builder struct - convert to JSON map first
  def execute(%Builder{} = builder, opts_or_pid) do
    command = Builder.to_map(builder)
    execute(command, normalize_opts(opts_or_pid))
  end

  # Handle raw command map
  def execute(command, opts_or_pid) when is_map(command) do
    opts = normalize_opts(opts_or_pid)
    # Encode Elixir map to JSON (this is the ONLY place JSON encoding happens)
    json_string = JSON.encode!(command)
    pid = get_port_pid(opts)
    timeout = Keyword.get(opts, :timeout, 5000)

    case NFTables.Port.commit(pid, json_string, timeout) do
      {:ok, ""} ->
        # Empty response is success
        {:ok, %{}}

      {:ok, response_json} ->
        # Decode JSON response to Elixir structures (ONLY place JSON decoding happens)
        case JSON.decode(response_json) do
          {:ok, %{"nftables" => items} = decoded} when is_list(items) ->
            # Check if any item contains an error
            case Enum.find(items, fn item -> Map.has_key?(item, "error") end) do
              %{"error" => error} -> {:error, error}
              nil -> {:ok, decoded}  # Return decoded Elixir map
            end

          {:ok, %{"error" => error}} ->
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

  @doc """
  Execute an nftables command, raising on error.

  Same as `execute/2` but raises `RuntimeError` on failure instead of
  returning `{:error, reason}`.

  ## Examples

      command = %{nftables: [%{add: %{table: %{family: "inet", name: "filter"}}}]}
      response = Executor.execute!(command)
  """
  @spec execute!(map(), keyword()) :: term()
  def execute!(command, opts \\ []) when is_map(command) do
    case execute(command, opts) do
      {:ok, response} -> response
      {:error, reason} -> raise "NFTex execution failed: #{inspect(reason)}"
    end
  end

  # Private helpers

  # Normalize opts_or_pid to keyword list
  defp normalize_opts(opts) when is_list(opts), do: opts
  defp normalize_opts(pid) when is_pid(pid), do: [pid: pid]

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
            1. Start NFTex with: NFTables.start_link()
            2. Pass pid explicitly: Executor.execute(json, pid: pid)
            """

          pid ->
            pid
        end
    end
  end
end
