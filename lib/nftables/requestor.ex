defmodule NFTables.Requestor do
  @moduledoc """
  Behaviour for custom Builder submission handlers.

  The Requestor behaviour allows you to define custom handlers for submitting
  Builder configurations. This enables use cases beyond local execution via
  NFTables.Port, such as:

  - **Remote execution**: Submit configurations to remote nodes
  - **Audit logging**: Log all firewall changes before applying
  - **Testing**: Capture and inspect configurations without applying
  - **Batching**: Accumulate multiple configs before submission
  - **Conditional execution**: Apply different strategies based on environment

  ## Behaviour Callback

  Modules implementing this behaviour must provide a `submit/2` callback:

      @callback submit(builder, opts) :: :ok | {:ok, term()} | {:error, term()}
        when builder: NFTables.Builder.t(),
             opts: keyword()

  The callback receives:
  - `builder` - The NFTables.Builder struct with accumulated commands
  - `opts` - Keyword list of options (requestor-specific)

  And should return:
  - `:ok` - On successful submission
  - `{:ok, result}` - On success with a result value
  - `{:error, reason}` - On failure

  ## Usage with Builder

  ### Setting Requestor at Creation

      builder = Builder.new(family: :inet, requestor: MyApp.RemoteRequestor)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")
      |> NFTables.submit(node: :firewall@server)

  ### Setting Requestor Later

      builder = Builder.new()
      |> NFTables.add(table: "filter")
      |> Builder.set_requestor(MyApp.AuditRequestor)
      |> NFTables.submit(audit_id: "12345")

  ### Overriding Requestor at Submit Time

      builder = Builder.new(requestor: MyApp.DefaultRequestor)
      |> NFTables.add(table: "filter")
      |> NFTables.submit(requestor: MyApp.SpecialRequestor, priority: :high)

  ## Example Implementations

  ### Remote Execution

      defmodule MyApp.RemoteRequestor do
        @behaviour NFTables.Requestor

        @impl true
        def submit(builder, opts) do
          node = Keyword.fetch!(opts, :node)
          commands = NFTables.Builder.to_map(builder)

          case :rpc.call(node, NFTables.Local, :submit, [commands, opts]) do
            {:ok, result} -> {:ok, result}
            {:error, reason} -> {:error, {:remote_failure, reason}}
            {:badrpc, reason} -> {:error, {:rpc_error, reason}}
          end
        end
      end

  ### Audit Logging

      defmodule MyApp.AuditRequestor do
        @behaviour NFTables.Requestor

        @impl true
        def submit(builder, opts) do
          audit_id = Keyword.fetch!(opts, :audit_id)
          commands = NFTables.Builder.to_map(builder)

          # Log the change
          MyApp.AuditLog.record(audit_id, commands)

          # Then execute locally
          pid = Keyword.get(opts, :pid) || Process.whereis(NFTables.Port)
          NFTables.Local.submit(commands, pid: pid)
        end
      end

  ### Testing/Capture

      defmodule MyApp.CaptureRequestor do
        @behaviour NFTables.Requestor

        @impl true
        def submit(builder, _opts) do
          # Send to test process for inspection
          send(self(), {:nftables_submit, builder})
          :ok
        end
      end

  ### Conditional Execution

      defmodule MyApp.SmartRequestor do
        @behaviour NFTables.Requestor

        @impl true
        def submit(builder, opts) do
          case Application.get_env(:my_app, :env) do
            :prod ->
              # In production, require approval
              require_approval_and_execute(builder, opts)

            :staging ->
              # In staging, log and execute
              log_and_execute(builder, opts)

            :dev ->
              # In dev, just log
              IO.inspect(builder, label: "Would execute")
              :ok
          end
        end

        defp require_approval_and_execute(builder, opts) do
          # Implementation...
        end

        defp log_and_execute(builder, opts) do
          # Implementation...
        end
      end

  ## Comparison with execute/2

  | Feature | execute/2 | submit/2 |
  |---------|-----------|----------|
  | **Target** | Local NFTables.Port | Custom handler |
  | **Flexibility** | Fixed behavior | Fully customizable |
  | **Use Case** | Direct kernel execution | Remote, testing, audit, etc. |
  | **Configuration** | Requires pid | Uses behaviour module |

  Both approaches work - use `submit/1` with NFTables.Local requestor for direct
  local execution, or use `submit/2` with custom requestors for alternate strategies.

  ## See Also

  - `NFTables.Builder.submit/1` - Submit with builder's requestor
  - `NFTables.Builder.submit/2` - Submit with options/override requestor
  - `NFTables.Builder.set_requestor/2` - Set requestor on builder
  - `NFTables.Local` - Default local execution requestor
  """

  @doc """
  Callback for submitting a Builder configuration.

  Implementations should process the builder's accumulated commands and
  return a result indicating success or failure.

  ## Parameters

  - `builder` - NFTables.Builder struct or command map with accumulated commands
  - `opts` - Keyword list of options (requestor-specific)

  ## Returns

  - `:ok` - Successful submission with no result
  - `{:ok, result}` - Successful submission with result value
  - `{:error, reason}` - Failed submission with error reason

  ## Examples

      @impl true
      def submit(builder, opts) do
        # Convert builder to command map
        commands = if is_struct(builder) do
          NFTables.Builder.to_map(builder)
        else
          builder
        end

        node = Keyword.fetch!(opts, :node)

        case :rpc.call(node, MyApp, :apply_config, [commands]) do
          :ok -> :ok
          {:error, reason} -> {:error, reason}
        end
      end
  """
  @callback submit(builder :: term(), opts :: keyword()) ::
              :ok | {:ok, term()} | {:error, term()}
end
