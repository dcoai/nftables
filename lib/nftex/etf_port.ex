defmodule NFTex.ETFPort do
  @moduledoc """
  GenServer managing the ETF-based nftables port.

  This is an alternative to `NFTex.JSONPort` that uses ETF (External Term Format) for
  communication, allowing you to send native Elixir terms instead of JSON strings.

  ## How It Works

  ```
  Elixir term → ETF → Zig port → JSON → libnftables → JSON → ETF → Elixir term
  ```

  The port handles all JSON conversion internally, so you work with native Elixir data structures.

  ## Features

  - Send nftables commands as Elixir terms (maps, lists, binaries)
  - Receive responses as Elixir terms
  - No JSON encoding/decoding in Elixir (done in the port)
  - Same JSON API as `NFTex.JSONPort` internally

  ## Protocol

  The port uses 4-byte big-endian length-prefixed packets with ETF encoding:

  ```
  Request:  [4 bytes length][ETF encoded term]
  Response: [4 bytes length][ETF encoded term]
  ```

  The term is typically a JSON string (binary), which the port converts internally.

  ## Example

      {:ok, pid} = NFTex.ETFPort.start_link()

      # Send Elixir map (will be ETF-encoded automatically)
      cmd = %{
        "nftables" => [
          %{"add" => %{"table" => %{"family" => "inet", "name" => "test"}}}
        ]
      }
      {:ok, response} = NFTex.ETFPort.call(pid, cmd)

      # Response is a binary (JSON string)
      response_map = Jason.decode!(response)

  ## Comparison with JSONPort

  | Feature | JSONPort | ETFPort |
  |---------|----------|---------|
  | Elixir sends | JSON string | Elixir map |
  | Wire format | JSON | ETF |
  | Port converts | None | ETF → JSON → libnftables |
  | Elixir receives | JSON string | JSON string (as binary) |
  | Performance | Slightly faster | More native to Erlang |
  | JSON encoding | Done in Elixir | Done in Zig port |

  Both use the same libnftables JSON API internally.
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
  Start the ETF port.

  ## Options

  - `:check_capabilities` - Check for CAP_NET_ADMIN capability on startup (default: true)
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Send a command to nftables via ETF and wait for response.

  ## Parameters

  - `pid` - The port GenServer PID
  - `command` - The nftables command as an Elixir map (will be ETF-encoded and converted to JSON)
  - `timeout` - Timeout in milliseconds (default: 5000)

  ## Returns

  - `{:ok, response}` - Success, returns response (JSON string as binary)
  - `{:error, reason}` - Error occurred

  ## Example

      # Send command as Elixir map (will be ETF-encoded)
      cmd = %{
        "nftables" => [
          %{"list" => %{"tables" => %{}}}
        ]
      }
      {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      tables = Jason.decode!(response)
  """
  def call(pid, command, timeout \\ @default_timeout) when is_map(command) do
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

    Logger.info("NFTex ETF port started: #{port_path}")

    {:noreply, %{state | port: port}}
  end

  @impl true
  def handle_call({:execute, command}, from, state) do
    # ETF-encode the map before sending
    # The {:packet, 4} mode handles the length prefix, but we need to encode the term
    encoded = :erlang.term_to_binary(command)

    # Send encoded term to port
    Port.command(state.port, encoded)

    # Store caller info to reply when response arrives
    {:noreply, %{state | pending: from}}
  end

  @impl true
  def handle_info({port, {:data, response}}, %{port: port, pending: from} = state)
      when not is_nil(from) do
    # Response received from port - decode from ETF
    # The {:packet, 4} mode strips the length prefix, but we need to decode the term
    decoded = :erlang.binary_to_term(response)

    GenServer.reply(from, {:ok, decoded})
    {:noreply, %{state | pending: nil}}
  end

  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.error("NFTex ETF port exited with status #{status}")
    {:stop, {:port_exit, status}, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warning("NFTex ETF port received unexpected message: #{inspect(msg)}")
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
            "native/zig-out/bin/libnf_etf"

          dir when is_list(dir) ->
            Path.join(to_string(dir), "libnf_etf")
        end

      true ->
        # Production: Use application priv directory
        Application.app_dir(:nftables, "priv/libnf_etf")
    end
  end
end
