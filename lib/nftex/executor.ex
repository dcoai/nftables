defmodule NFTex.Executor do
  @moduledoc """
  Command execution abstraction for NFTex.

  This module provides a clean interface for executing nftables JSON commands,
  decoupling command building from execution. This enables:

  - Local execution via NFTex.Port
  - Remote execution via custom transports
  - Command inspection and logging
  - Testing without actual firewall changes

  ## Examples

      # Local execution (default)
      json = Table.build_add(%{name: "filter", family: :inet})
      {:ok, response} = Executor.execute(json)

      # With specific port process
      {:ok, pid} = NFTex.start_link()
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

  @doc """
  Execute an nftables JSON command.

  ## Parameters

  - `command` - JSON string containing nftables commands
  - `opts` - Options:
    - `:pid` - NFTex.Port process (default: looks up registered process)
    - `:timeout` - Timeout in milliseconds (default: 5000)

  ## Returns

  - `{:ok, response}` - JSON response string on success
  - `{:error, reason}` - On failure

  ## Examples

      # Execute with default port
      json = ~s({"nftables": [{"list": {"tables": {"family": "inet"}}}]})
      {:ok, response} = Executor.execute(json)

      # Execute with specific port pid
      {:ok, pid} = NFTex.start_link()
      Executor.execute(json, pid: pid)

      # Custom timeout for long operations
      Executor.execute(json, timeout: 30_000)
  """
  @spec execute(binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def execute(command, opts \\ []) when is_binary(command) do
    pid = get_port_pid(opts)
    timeout = Keyword.get(opts, :timeout, 5000)

    NFTex.Port.call(pid, command, timeout)
  end

  @doc """
  Execute an nftables JSON command, raising on error.

  Same as `execute/2` but raises `RuntimeError` on failure instead of
  returning `{:error, reason}`.

  ## Examples

      json = Table.build_add(%{name: "filter", family: :inet})
      response = Executor.execute!(json)
  """
  @spec execute!(binary(), keyword()) :: binary()
  def execute!(command, opts \\ []) when is_binary(command) do
    case execute(command, opts) do
      {:ok, response} -> response
      {:error, reason} -> raise "NFTex execution failed: #{inspect(reason)}"
    end
  end

  # Private helpers

  defp get_port_pid(opts) do
    case Keyword.fetch(opts, :pid) do
      {:ok, pid} when is_pid(pid) ->
        pid

      :error ->
        # Try to find registered NFTex.Port process
        case Process.whereis(NFTex.Port) do
          nil ->
            raise ArgumentError, """
            No NFTex.Port process found. Either:
            1. Start NFTex with: NFTex.start_link()
            2. Pass pid explicitly: Executor.execute(json, pid: pid)
            """

          pid ->
            pid
        end
    end
  end
end
