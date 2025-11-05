defmodule NFTex.Port do
  @moduledoc """
  GenServer that manages the libnf_ex port process.

  This module handles:
  - Spawning and monitoring the Zig port process
  - Encoding/decoding ETF messages
  - Request/response correlation
  - Timeout handling
  - Resource cleanup on exit
  """

  use GenServer
  require Logger

  @default_timeout 5_000
  @port_name "libnf_ex"

  defmodule State do
    @moduledoc false
    defstruct [
      :port,
      :requests,
      :next_ref,
      :check_capabilities
    ]

    @type t :: %__MODULE__{
            port: port() | nil,
            requests: %{non_neg_integer() => GenServer.from()},
            next_ref: non_neg_integer(),
            check_capabilities: boolean()
          }
  end

  # Client API

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: opts[:name])
  end

  @spec stop(pid()) :: :ok
  def stop(pid) do
    GenServer.stop(pid)
  end

  @spec call(pid(), term(), timeout()) :: term()
  def call(pid, request, timeout \\ @default_timeout) do
    GenServer.call(pid, {:port_call, request}, timeout)
  end

  @doc """
  Check if CAP_NET_ADMIN capability is available.

  Returns `true` if the port has CAP_NET_ADMIN, `false` otherwise.
  """
  @spec has_capabilities?(pid()) :: boolean()
  def has_capabilities?(pid) do
    case call(pid, {:check_capabilities}) do
      {:ok, 1} -> true
      {:ok, 0} -> false
      _ -> false
    end
  end

  # Server callbacks

  @impl true
  def init(opts) do
    state = %State{
      port: nil,
      requests: %{},
      next_ref: 1,
      check_capabilities: Keyword.get(opts, :check_capabilities, true)
    }

    {:ok, state, {:continue, :start_port}}
  end

  @impl true
  def handle_continue(:start_port, state) do
    port_path = find_port_executable()

    port =
      Port.open({:spawn_executable, port_path}, [
        {:packet, 4},
        :binary,
        :exit_status,
        :use_stdio
      ])

    Logger.info("NFTex port started: #{port_path}")

    state = %{state | port: port}

    # Check capabilities if requested
    if state.check_capabilities do
      case check_capabilities_sync(state) do
        true ->
          {:noreply, state}

        false ->
          Port.close(port)
          {:stop, {:error, "capability cap_net_admin not set"}, state}
      end
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_call({:port_call, request}, from, state) do
    req_id = state.next_ref

    # Encode request as ETF
    message = :erlang.term_to_binary({req_id, request})

    # Send to port
    Port.command(state.port, message)

    # Store pending request
    requests = Map.put(state.requests, req_id, from)
    state = %{state | requests: requests, next_ref: req_id + 1}

    {:noreply, state}
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    # Decode ETF response
    {req_id, response} = :erlang.binary_to_term(data)

    case Map.pop(state.requests, req_id) do
      {from, requests} when from != nil ->
        GenServer.reply(from, response)
        {:noreply, %{state | requests: requests}}

      {nil, _} ->
        Logger.warning("Received response for unknown request ID: #{req_id}")
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.error("Port exited with status: #{status}")
    {:stop, {:port_exit, status}, state}
  end

  @impl true
  def handle_info({:EXIT, port, reason}, %{port: port} = state) do
    Logger.error("Port process died: #{inspect(reason)}")
    {:stop, {:port_died, reason}, state}
  end

  @impl true
  def terminate(reason, state) do
    Logger.info("NFTex port terminating: #{inspect(reason)}")

    if state.port do
      Port.close(state.port)
    end

    # Reply to any pending requests with error
    for {_req_id, from} <- state.requests do
      GenServer.reply(from, {:error, :port_closed})
    end

    :ok
  end

  # Private helpers

  defp check_capabilities_sync(state) do
    # Send check_capabilities request
    req_id = 1
    message = :erlang.term_to_binary({req_id, {:check_capabilities}})
    Port.command(state.port, message)

    # Wait for response with timeout
    receive do
      {port, {:data, data}} when port == state.port ->
        case :erlang.binary_to_term(data) do
          {^req_id, {:ok, 1}} -> true
          {^req_id, {:ok, 0}} -> false
          _ -> false
        end
    after
      1_000 -> false
    end
  end

  defp find_port_executable do
    # Check multiple possible locations for the compiled port binary
    possible_paths = [
      # Development build location
      Path.join([__DIR__, "..", "..", "priv", @port_name]),
      # Mix release location
      Path.join([:code.priv_dir(:nftables), @port_name]),
      # Zig build output location
      Path.join([__DIR__, "..", "..", "native", "zig-out", "bin", @port_name])
    ]

    possible_paths
    |> Enum.find(&File.exists?/1)
    |> case do
      nil ->
        raise """
        Could not find #{@port_name} executable in any of:
        #{Enum.map_join(possible_paths, "\n", &"  - #{&1}")}

        Please build the native code first:
          cd native && zig build
        """

      path ->
        Path.expand(path)
    end
  end
end
