defmodule NFTex.Port do
  @moduledoc """
  GenServer managing the nftables port with JSON communication.

  This port uses JSON for all communication with libnftables, providing
  a simple and performant interface.

  ## How It Works

  ```
  Elixir JSON string → Port → libnftables → JSON string back
  ```

  ## Protocol

  The port uses 4-byte big-endian length-prefixed packets:

  ```
  [4 bytes length][JSON string]
  ```

  ## Port Binary Location

  The port binary is located using the following resolution order:

  1. **PORT_NFTABLES_PATH** environment variable (if set and file exists)
  2. **/usr/local/sbin/port_nftables** (system-wide installation)
  3. **/usr/sbin/port_nftables** (system-wide installation)
  4. **priv/port_nftables** (development or application-bundled)

  For production deployments, set the `PORT_NFTABLES_PATH` environment variable
  to specify a custom location, or install to `/usr/local/sbin/port_nftables`.

  ## Example

      {:ok, pid} = NFTex.Port.start_link()

      # Send JSON command
      cmd = ~s({"nftables": [{"list": {"tables": {}}}]})
      {:ok, json_response} = NFTex.Port.call(pid, cmd)
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
  Start the nftables port.

  ## Options

  - `:check_capabilities` - Check for CAP_NET_ADMIN capability on startup (default: true)
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Send a command to nftables and wait for response.

  ## Parameters

  - `pid` - The port GenServer PID
  - `command` - JSON string command
  - `timeout` - Timeout in milliseconds (default: 5000)

  ## Returns

  - `{:ok, json_string}` - Success, returns JSON string response
  - `{:error, reason}` - Error occurred

  ## Examples

      cmd = ~s({"nftables": [{"list": {"tables": {}}}]})
      {:ok, response} = NFTex.Port.call(pid, cmd)
  """
  def call(pid, command, timeout \\ @default_timeout) when is_binary(command) do
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

    {:noreply, %{state | port: port}}
  end

  @impl true
  def handle_call({:execute, command}, from, state) when is_binary(command) do
    # Send JSON string to port
    Port.command(state.port, command)

    # Store caller info
    {:noreply, %{state | pending: from}}
  end

  @impl true
  def handle_info({port, {:data, response}}, %{port: port, pending: from} = state) do
    # Response is JSON string
    GenServer.reply(from, {:ok, response})
    {:noreply, %{state | pending: nil}}
  end

  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.error("NFTex port exited with status #{status}")
    {:stop, {:port_exit, status}, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warning("NFTex port received unexpected message: #{inspect(msg)}")
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
    # 1. Check environment variable first (production override)
    case System.get_env("PORT_NFTABLES_PATH") do
      nil ->
        find_port_in_system()

      path when is_binary(path) ->
        if File.exists?(path) do
          path
        else
          find_port_in_system()
        end
    end
  end

  defp find_port_in_system do
    # 2. Search standard system directories in production
    system_paths = [
      "/usr/local/sbin/port_nftables",
      "/usr/sbin/port_nftables"
    ]

    Enum.find(system_paths, &File.exists?/1) || fallback_port_path()
  end

  defp fallback_port_path do
    # 3. Fallback to development/application directories
    cond do
      Code.ensure_loaded?(Mix.Project) ->
        # Development: Use priv directory
        priv_dir = :code.priv_dir(:nftables)

        case priv_dir do
          {:error, _} ->
            # Fallback to native build directory
            "native/zig-out/bin/port_nftables"

          dir when is_list(dir) ->
            Path.join(to_string(dir), "port_nftables")
        end

      true ->
        # Production: Use application priv directory
        Application.app_dir(:nftables, "priv/port_nftables")
    end
  end
end
