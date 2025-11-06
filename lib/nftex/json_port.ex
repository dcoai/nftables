defmodule NFTex.JSONPort do
  @moduledoc """
  GenServer managing the JSON-based nftables port.

  This is a simpler alternative to `NFTex.Port` that uses libnftables with JSON
  instead of low-level libnftnl netlink operations.

  ## Features

  - Sends nftables commands as JSON strings
  - Receives responses as JSON strings
  - No resource management needed (libnftables handles everything)
  - Simpler protocol: just JSON in/out with packet framing

  ## Protocol

  The port uses 4-byte big-endian length-prefixed packets:

  ```
  Request:  [4 bytes length][JSON bytes]
  Response: [4 bytes length][JSON bytes]
  ```

  ## Example

      {:ok, pid} = NFTex.JSONPort.start_link()

      # Send JSON command
      cmd = ~s({"nftables": [{"add": {"table": {"family": "inet", "name": "test"}}}]})
      {:ok, response_json} = NFTex.JSONPort.call(pid, cmd)

      # Response is JSON string
      response = Jason.decode!(response_json)
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
  Start the JSON port.

  ## Options

  - `:check_capabilities` - Check for CAP_NET_ADMIN capability on startup (default: true)
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Send a JSON command to nftables and wait for response.

  ## Parameters

  - `pid` - The port GenServer PID
  - `json_string` - The nftables JSON command as a string
  - `timeout` - Timeout in milliseconds (default: 5000)

  ## Returns

  - `{:ok, response_json}` - Success, returns response as JSON string
  - `{:error, reason}` - Error occurred

  ## Example

      cmd = ~s({"nftables": [{"list": {"tables": {}}}]})
      {:ok, response} = NFTex.JSONPort.call(pid, cmd)
      tables = Jason.decode!(response)
  """
  def call(pid, json_string, timeout \\ @default_timeout) when is_binary(json_string) do
    GenServer.call(pid, {:execute, json_string}, timeout)
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
    case start_port(state.check_capabilities) do
      {:ok, port} ->
        Logger.info("NFTex JSON port started: #{port_path()}")
        {:noreply, %{state | port: port}}

      {:error, reason} ->
        {:stop, {:port_start_failed, reason}, state}
    end
  end

  @impl true
  def handle_call({:execute, json_string}, from, %State{port: port, pending: nil} = state) do
    # Send JSON to port - {:packet, 4} mode automatically adds length prefix
    Port.command(port, json_string)

    # Wait for response
    {:noreply, %{state | pending: from}}
  end

  def handle_call({:execute, _json_string}, _from, %State{pending: pending} = state)
      when pending != nil do
    # Already have a pending request - this shouldn't happen with proper usage
    {:reply, {:error, :request_in_progress}, state}
  end

  @impl true
  def handle_info({port, {:data, json_response}}, %State{port: port, pending: from} = state)
      when from != nil do
    # {:packet, 4} mode automatically strips length prefix - we get raw JSON
    GenServer.reply(from, {:ok, json_response})
    {:noreply, %{state | pending: nil}}
  end

  def handle_info({port, {:data, _data}}, %State{port: port} = state) do
    # Unexpected data (no pending request) - ignore
    Logger.warning("NFTex JSON port received unexpected data")
    {:noreply, state}
  end

  def handle_info({port, {:exit_status, status}}, %State{port: port} = state) do
    Logger.error("NFTex JSON port exited with status: #{status}")
    {:stop, {:port_exit, status}, state}
  end

  def handle_info({:EXIT, port, reason}, %State{port: port} = state) do
    Logger.info("NFTex JSON port terminating: #{inspect(reason)}")
    {:stop, reason, state}
  end

  @impl true
  def terminate(reason, %State{port: port} = _state) do
    Logger.info("NFTex JSON port terminating: #{inspect(reason)}")

    if port && Port.info(port) do
      Port.close(port)
    end

    :ok
  end

  ## Private Helpers

  defp start_port(check_capabilities) do
    path = port_path()

    unless File.exists?(path) do
      {:error, {:port_not_found, path}}
    else
      # Check capabilities if requested
      if check_capabilities do
        case check_port_capabilities(path) do
          :ok -> do_start_port(path)
          {:error, reason} -> {:error, {:capability_check_failed, reason}}
        end
      else
        do_start_port(path)
      end
    end
  end

  defp do_start_port(path) do

    # Start port with packet mode (4-byte length prefix)
    port =
      Port.open({:spawn_executable, path}, [
        {:packet, 4},
        :binary,
        :exit_status
      ])

    {:ok, port}
  end

  defp port_path do
    :code.priv_dir(:nftables)
    |> to_string()
    |> Path.join("libnf_json")
  end

  defp check_port_capabilities(path) do
    case System.cmd("/usr/sbin/getcap", [path], stderr_to_stdout: true) do
      {output, 0} ->
        if String.contains?(output, "cap_net_admin") do
          :ok
        else
          IO.puts("""
          \n⚠ WARNING: CAP_NET_ADMIN capability is not set on #{path}

          Netlink operations will fail without this capability.
          To fix, run:

              sudo setcap cap_net_admin=ep #{path}
          """)

          {:error, :missing_cap_net_admin}
        end

      {_output, _code} ->
        # getcap failed - assume capability check not available
        :ok
    end
  end
end
