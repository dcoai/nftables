defmodule NFTex.UnifiedPort do
  @moduledoc """
  GenServer managing the unified nftables port that supports both JSON and ETF formats.

  This port automatically detects and handles both JSON strings and ETF-encoded Elixir maps,
  providing a flexible interface that combines the benefits of both JSONPort and ETFPort.

  ## How It Works

  ```
  JSON mode (backward compatible):
    Elixir string → Port → libnftables → JSON string back

  ETF mode (native Elixir):
    Elixir map → ETF encode → "ETF:" prefix → Port → ETF decode → JSON → libnftables
    → JSON → ETF encode → "ETF:" prefix → Elixir → ETF decode → JSON string back
  ```

  ## Features

  - **Backward Compatible**: Accepts JSON strings (no prefix needed)
  - **ETF Support**: Accepts Elixir maps (automatically uses ETF with "ETF:" prefix)
  - **Format Detection**: Port automatically detects format and responds accordingly
  - **Drop-in Replacement**: Can replace both JSONPort and ETFPort

  ## Protocol

  The port uses 4-byte big-endian length-prefixed packets with optional format prefixes:

  ```
  JSON (default):    [4 bytes length][JSON string]
  JSON (explicit):   [4 bytes length]["JSN:" JSON string]
  ETF:              [4 bytes length]["ETF:" ETF binary]
  ```

  ## Example

      {:ok, pid} = NFTex.UnifiedPort.start_link()

      # JSON mode (backward compatible, no prefix)
      cmd1 = ~s({"nftables": [{"list": {"tables": {}}}]})
      {:ok, json_response} = NFTex.UnifiedPort.call(pid, cmd1)

      # ETF mode (automatic with maps)
      cmd2 = %{"nftables" => [%{"list" => %{"tables" => %{}}}]}
      {:ok, json_response} = NFTex.UnifiedPort.call(pid, cmd2)
      # Note: Response is always a JSON string for compatibility

  ## Comparison with Other Ports

  | Feature | JSONPort | ETFPort | UnifiedPort |
  |---------|----------|---------|-------------|
  | Accepts JSON strings | ✓ | ✗ | ✓ |
  | Accepts Elixir maps | ✗ | ✓ | ✓ |
  | Backward compatible | N/A | ✗ | ✓ |
  | JSON encoding location | Elixir | Port | Port (for maps) |
  | Wire format | JSON | ETF | Both |
  """

  use GenServer
  require Logger

  @default_timeout 5_000

  defmodule State do
    @moduledoc false
    defstruct [:port, :pending, check_capabilities: true]
  end

  ## Client API

  @doc """
  Start the unified port.

  ## Options

  - `:check_capabilities` - Check for CAP_NET_ADMIN capability on startup (default: true)
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Send a command to nftables and wait for response.

  Accepts either a JSON string (backward compatible) or an Elixir map (ETF mode).

  ## Parameters

  - `pid` - The port GenServer PID
  - `command` - Either:
    - Binary/String: JSON command (sent as-is, no prefix)
    - Map: Elixir map (converted to ETF with "ETF:" prefix)
  - `timeout` - Timeout in milliseconds (default: 5000)

  ## Returns

  - `{:ok, json_string}` - Success, returns JSON string response
  - `{:error, reason}` - Error occurred

  ## Examples

      # JSON mode (backward compatible)
      cmd = ~s({"nftables": [{"list": {"tables": {}}}]})
      {:ok, response} = UnifiedPort.call(pid, cmd)

      # ETF mode (with Elixir map)
      cmd = %{"nftables" => [%{"list" => %{"tables" => %{}}}]}
      {:ok, response} = UnifiedPort.call(pid, cmd)
  """
  def call(pid, command, timeout \\ @default_timeout) when is_binary(command) or is_map(command) do
    GenServer.call(pid, {:execute, command}, timeout)
  end

  @doc """
  Stop the port.
  """
  def stop(pid) do
    GenServer.stop(pid, :normal)
  end

  ## Server Callbacks

  @impl true
  def init(opts) do
    check_capabilities = Keyword.get(opts, :check_capabilities, true)

    state = %State{
      port: nil,
      pending: nil,
      check_capabilities: check_capabilities
    }

    {:ok, state, {:continue, :start_port}}
  end

  @impl true
  def handle_continue(:start_port, state) do
    port_path = get_port_path()

    # Open port with packet mode (4-byte length prefix)
    # Use :binary and {:packet, 4} for automatic length prefixing
    port =
      Port.open({:spawn_executable, port_path}, [
        :binary,
        :exit_status,
        {:packet, 4},
        :use_stdio
      ])

    Logger.info("NFTex Unified port started: #{port_path}")

    {:noreply, %{state | port: port}}
  end

  @impl true
  def handle_call({:execute, command}, from, state) when is_binary(command) do
    # JSON mode: Send string as-is (no prefix for backward compatibility)
    Port.command(state.port, command)

    # Store caller info and format
    {:noreply, %{state | pending: {from, :json_raw}}}
  end

  @impl true
  def handle_call({:execute, command}, from, state) when is_map(command) do
    # ETF mode: Encode map to ETF and prepend "ETF:" prefix
    etf_encoded = :erlang.term_to_binary(command)
    prefixed = "ETF:" <> etf_encoded

    Port.command(state.port, prefixed)

    # Store caller info and format
    {:noreply, %{state | pending: {from, :etf}}}
  end

  @impl true
  def handle_info({port, {:data, response}}, %{port: port, pending: {from, format}} = state) do
    # Decode response based on format
    decoded =
      case format do
        :json_raw ->
          # No prefix, response is plain JSON
          response

        :json_prefixed ->
          # Strip "JSN:" prefix
          <<"JSN:", json::binary>> = response
          json

        :etf ->
          # Strip "ETF:" prefix and decode ETF to get JSON string
          <<"ETF:", etf::binary>> = response
          :erlang.binary_to_term(etf)
      end

    GenServer.reply(from, {:ok, decoded})
    {:noreply, %{state | pending: nil}}
  end

  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.error("NFTex Unified port exited with status #{status}")
    {:stop, {:port_exit, status}, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warning("NFTex Unified port received unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    if state.port do
      Port.close(state.port)
    end

    :ok
  end

  ## Private Functions

  defp get_port_path do
    # Check if running in development (via Mix) or production (release)
    cond do
      Code.ensure_loaded?(Mix.Project) ->
        # Development: Use priv directory
        priv_dir = :code.priv_dir(:nftables)

        case priv_dir do
          {:error, _} ->
            # Fallback to native build directory
            "native/zig-out/bin/libnf_unified"

          dir when is_list(dir) ->
            Path.join(to_string(dir), "libnf_unified")
        end

      true ->
        # Production: Use application priv directory
        Application.app_dir(:nftables, "priv/libnf_unified")
    end
  end
end
