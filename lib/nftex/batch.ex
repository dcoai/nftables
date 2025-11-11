defmodule NFTablesEx.Batch do
  @moduledoc """
  Batch multiple nftables commands into a single atomic operation.

  The Batch module allows you to combine multiple nftables commands into
  a single JSON request, which is executed atomically. This is useful for:

  - Efficient multi-command operations (one round-trip)
  - Atomic firewall updates (all-or-nothing)
  - Distributed firewalls (send batch over network once)
  - Complex rule setups

  ## Examples

      # Create multiple firewall rules at once
      batch =
        Batch.new()
        |> Batch.add(Table.build_add(%{name: "filter", family: :inet}))
        |> Batch.add(Chain.build_add(%{table: "filter", name: "INPUT", family: :inet}))
        |> Batch.add(Rule.build_block_ip("filter", "INPUT", "1.2.3.4"))
        |> Batch.add(Rule.build_block_ip("filter", "INPUT", "5.6.7.8"))

      # Execute the batch
      {:ok, response} = Batch.execute(batch)

      # Or build JSON for remote execution
      json = Batch.to_json(batch)
      MyTransport.send_to_node("firewall-1", json)

  ## Atomicity

  Batches are executed atomically by nftables. Either all commands succeed
  or all commands are rolled back. This prevents partial firewall updates.

  """

  @type t :: list(binary())

  @doc """
  Create a new empty batch.

  ## Examples

      batch = Batch.new()
  """
  @spec new() :: t()
  def new(), do: []

  @doc """
  Add a JSON command to the batch.

  Commands are added to the batch in the order they are called.
  They will be executed in this order.

  ## Parameters

  - `batch` - The batch to add to
  - `json_command` - A JSON string containing an nftables command

  ## Examples

      batch = Batch.new()
      |> Batch.add(Table.build_add(%{name: "filter"}))
      |> Batch.add(Chain.build_add(%{table: "filter", name: "INPUT"}))
  """
  @spec add(t(), binary()) :: t()
  def add(batch, json_command) when is_binary(json_command) do
    [json_command | batch]
  end

  @doc """
  Add multiple JSON commands to the batch.

  ## Parameters

  - `batch` - The batch to add to
  - `commands` - List of JSON command strings

  ## Examples

      commands = [
        Table.build_add(%{name: "filter"}),
        Table.build_add(%{name: "nat"})
      ]

      batch = Batch.new()
      |> Batch.add_many(commands)
  """
  @spec add_many(t(), list(binary())) :: t()
  def add_many(batch, commands) when is_list(commands) do
    Enum.reduce(commands, batch, fn cmd, acc -> add(acc, cmd) end)
  end

  @doc """
  Convert batch to nftables JSON format.

  Combines all commands in the batch into a single JSON object
  with an "nftables" array containing all operations.

  ## Parameters

  - `batch` - The batch to convert

  ## Returns

  JSON string containing all batch commands

  ## Examples

      batch = Batch.new()
      |> Batch.add(Table.build_add(%{name: "filter"}))
      |> Batch.to_json()

      #=> "{\"nftables\":[{\"add\":{\"table\":{...}}}]}"
  """
  @spec to_json(t()) :: binary()
  def to_json(batch) do
    # Reverse to maintain insertion order
    commands =
      batch
      |> Enum.reverse()
      |> Enum.map(&decode_command/1)
      |> List.flatten()

    %{"nftables" => commands}
    |> JSON.encode!()
    
  end

  @doc """
  Execute a batch of commands.

  Executes all commands in the batch atomically. Either all succeed
  or all are rolled back.

  ## Parameters

  - `batch` - The batch to execute
  - `opts` - Options passed to `NFTablesEx.Executor.execute/2`:
    - `:pid` - NFTablesEx.Port process
    - `:timeout` - Timeout in milliseconds

  ## Returns

  - `{:ok, response}` - JSON response on success
  - `{:error, reason}` - On failure

  ## Examples

      batch = Batch.new()
      |> Batch.add(Table.build_add(%{name: "filter"}))
      |> Batch.add(Chain.build_add(%{table: "filter", name: "INPUT"}))

      {:ok, _response} = Batch.execute(batch)

      # With options
      Batch.execute(batch, pid: my_pid, timeout: 10_000)
  """
  @spec execute(t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def execute(batch, opts \\ []) do
    json = to_json(batch)
    NFTablesEx.Executor.execute(json, opts)
  end

  @doc """
  Execute a batch of commands, raising on error.

  Same as `execute/2` but raises `RuntimeError` on failure.

  ## Examples

      batch = Batch.new()
      |> Batch.add(Table.build_add(%{name: "filter"}))
      |> Batch.execute!()
  """
  @spec execute!(t(), keyword()) :: binary()
  def execute!(batch, opts \\ []) do
    case execute(batch, opts) do
      {:ok, response} -> response
      {:error, reason} -> raise "Batch execution failed: #{inspect(reason)}"
    end
  end

  @doc """
  Get the number of commands in the batch.

  ## Examples

      batch = Batch.new()
      |> Batch.add(Table.build_add(%{name: "filter"}))
      |> Batch.add(Chain.build_add(%{table: "filter", name: "INPUT"}))

      Batch.size(batch)  #=> 2
  """
  @spec size(t()) :: non_neg_integer()
  def size(batch), do: length(batch)

  @doc """
  Check if batch is empty.

  ## Examples

      Batch.new() |> Batch.empty?()  #=> true

      Batch.new()
      |> Batch.add(Table.build_add(%{name: "filter"}))
      |> Batch.empty?()  #=> false
  """
  @spec empty?(t()) :: boolean()
  def empty?(batch), do: batch == []

  # Private helpers

  # Decode a JSON command string to extract the nftables command object
  defp decode_command(json_str) when is_binary(json_str) do
    case JSON.decode(json_str) do
      {:ok, %{"nftables" => commands}} when is_list(commands) ->
        commands

      {:ok, command} when is_map(command) ->
        [command]

      {:error, _} ->
        # If it's not valid JSON, assume it's an nft syntax string
        # and wrap it in a metainfo command
        [%{"metainfo" => %{"json_cli" => false}}]
    end
  end
end
