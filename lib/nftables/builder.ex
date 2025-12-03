defmodule NFTables.Builder do
  @moduledoc """
  Functional builder for constructing nftables configurations.

  This module provides a clean, functional API for building nftables commands.
  The builder accumulates commands and can be executed when ready, separating
  configuration building from execution.

  ## Design Philosophy

  - **Pure Building**: Builder is immutable, no side effects during construction
  - **Explicit Submission**: Commands submit only when `submit/1` or `submit/2` is called
  - **Atom Keys**: All JSON uses atom keys (converted to strings during encoding)
  - **Context Tracking**: Automatically tracks table/chain/collection context for chaining
  - **Unified API**: Single set of functions (add/delete/flush/etc) for all object types

  ## Basic Usage

      # Create builder (automatically uses NFTables.Local as default requestor)
      builder = Builder.new(family: :inet)

      # Add table and chain - context is automatically tracked
      builder = builder
      |> Builder.add(table: "filter")
      |> Builder.add(chain: "input", type: :filter, hook: :input, priority: 0, policy: :drop)

      # Add rules - automatically uses table and chain from context
      builder = builder
      |> Builder.add(rule: [
          %{match: %{left: %{ct: %{key: "state"}}, right: ["established", "related"], op: "in"}},
          %{accept: nil}
        ])

      # Submit when ready (uses NFTables.Local by default)
      {:ok, pid} = NFTables.start_link()
      Builder.submit(builder, pid: pid)

  ## Setting Builder Context

  Use `set/2` to update multiple builder fields at once:

      # Set context fields directly
      builder = Builder.new()
      |> Builder.set(family: :inet, table: "filter", chain: "INPUT")

      # Switch context mid-pipeline
      builder
      |> Builder.set(table: "filter", chain: "INPUT")
      |> Builder.add(rule: allow_ssh)
      |> Builder.set(chain: "FORWARD")  # Switch to different chain
      |> Builder.add(rule: allow_forwarding)

      # Clear context
      builder |> Builder.set(chain: nil, collection: nil)

  ## Unified API Pattern

  All object types use the same functions: `add/2`, `delete/2`, `insert/2`, `replace/2`, `flush/2`, `rename/2`.
  The object type is automatically detected from the options:

      Builder.new(family: :inet)
      |> Builder.add(table: "filter")                          # Adds table
      |> Builder.add(chain: "input", type: :filter,            # Adds chain
                     hook: :input, priority: 0, policy: :drop)
      |> Builder.add(set: "blocklist", type: :ipv4_addr)       # Adds set
      |> Builder.add(rule: [%{accept: nil}])                   # Adds rule
      |> Builder.submit(pid: pid)

  ## Context Chaining

  The builder automatically tracks context (table, chain, collection) so you don't need to repeat it:

      builder
      |> Builder.add(table: "filter", chain: "input")  # Sets context
      |> Builder.add(rule: [%{accept: nil}])           # Uses filter/input automatically
      |> Builder.add(rule: [%{drop: nil}])             # Still uses filter/input

  ## Automatic Rule Conversion

  Builder automatically converts `NFTables.Expr` structs to expression lists,
  so you don't need to call `to_expr/1` manually:

      import NFTables.Expr

      # No need to call to_expr() - Builder handles it automatically
      ssh_rule = rule() |> tcp() |> dport(22) |> accept()

      builder
      |> Builder.add(table: "filter", chain: "input")
      |> Builder.add(rule: ssh_rule)  # Automatically converted to expression list
      |> Builder.submit(pid: pid)

  This also works with lists of rules:

      rules = [
        rule() |> tcp() |> dport(22) |> accept(),
        rule() |> tcp() |> dport(80) |> accept()
      ]

      # Each rule in the list is automatically converted
      Enum.reduce(rules, builder, fn r, b ->
        Builder.add(b, rule: r)
      end)

  For backwards compatibility, you can still pass expression lists directly:

      # This still works
      expr_list = rule() |> tcp() |> dport(22) |> accept() |> to_expr()
      Builder.add(builder, rule: expr_list)
  """

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type t :: %__MODULE__{
          family: family(),
          requestor: module() | nil,
          table: String.t() | nil,
          chain: String.t() | nil,
          collection: String.t() | nil,
          type: atom() | {atom(), atom()} | nil,
          spec: map(),
          commands: list(map())
        }

  defstruct family: :inet,
            requestor: NFTables.Local,
            table: nil,
            chain: nil,
            collection: nil,
            type: nil,
            spec: nil,
            commands: []

  ## Core Functions

  @doc """
  Create a new builder.

  ## Options

  - `:family` - Address family (default: `:inet`)
  - `:requestor` - Module implementing NFTables.Requestor behaviour (default: `NFTables.Local`)

  ## Examples

      Builder.new()  # Uses NFTables.Local by default
      Builder.new(family: :ip6)
      Builder.new(family: :inet, requestor: MyApp.RemoteRequestor)
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    %__MODULE__{
      family: Keyword.get(opts, :family, :inet),
      requestor: Keyword.get(opts, :requestor, NFTables.Local)
    }
  end

  @doc """
  Set the address family.

  ## Examples

      builder |> Builder.set_family(:ip6)
  """
  @spec set_family(t(), family()) :: t()
  def set_family(%__MODULE__{} = builder, family)
      when family in [:inet, :ip, :ip6, :arp, :bridge, :netdev] do
    %{builder | family: family}
  end

  @doc """
  Set the requestor module for this builder.

  The requestor module must implement the `NFTables.Requestor` behaviour.
  This allows custom submission handlers for use cases like remote execution,
  audit logging, testing, or conditional execution.

  ## Parameters

  - `builder` - The builder instance
  - `requestor` - Module implementing NFTables.Requestor behaviour (or `nil` to clear)

  ## Examples

      builder |> Builder.set_requestor(MyApp.RemoteRequestor)

      # Clear requestor
      builder |> Builder.set_requestor(nil)

      # Chain with other builder operations
      Builder.new()
      |> Builder.add(table: "filter")
      |> Builder.set_requestor(MyApp.AuditRequestor)
      |> Builder.add(chain: "INPUT")
      |> Builder.submit(audit_id: "12345")

  ## See Also

  - `NFTables.Requestor` - Behaviour definition and examples
  - `submit/1` - Submit with builder's requestor
  - `submit/2` - Submit with options/override requestor
  """
  @spec set_requestor(t(), module() | nil) :: t()
  def set_requestor(%__MODULE__{} = builder, requestor) when is_atom(requestor) do
    %{builder | requestor: requestor}
  end

  @doc """
  Set multiple builder fields at once using a keyword list.

  This function provides a convenient way to update multiple builder struct fields
  in a single call. It validates each field and value before updating.

  ## Supported Fields

  - `:family` - Address family (:inet, :ip, :ip6, :arp, :bridge, :netdev)
  - `:requestor` - Requestor module (atom or nil)
  - `:table` - Table name (string or nil)
  - `:chain` - Chain name (string or nil)
  - `:collection` - Set/map name (string or nil)
  - `:type` - Type for sets/maps (atom, tuple, or nil)

  ## Examples

      # Set single field
      builder |> Builder.set(family: :ip6)

      # Set multiple fields at once
      builder |> Builder.set(family: :inet, table: "filter", chain: "INPUT")

      # Chain with other operations
      Builder.new()
      |> Builder.set(table: "nat", chain: "PREROUTING")
      |> Builder.add(rule: expr)
      |> Builder.submit(pid: pid)

      # Clear context
      builder |> Builder.set(chain: nil, collection: nil)

      # Switch context mid-pipeline
      builder
      |> Builder.set(table: "filter", chain: "INPUT")
      |> Builder.add(rule: allow_ssh)
      |> Builder.set(chain: "FORWARD")
      |> Builder.add(rule: allow_forwarding)

  ## Raises

  - `ArgumentError` - If field name is invalid or value doesn't match expected type
  """
  @spec set(t(), keyword()) :: t()
  def set(%__MODULE__{} = builder, opts) when is_list(opts) do
    Enum.reduce(opts, builder, fn {field, value}, acc ->
      validate_and_set_field(acc, field, value)
    end)
  end

  # Validate and set individual fields
  defp validate_and_set_field(builder, :family, value) do
    valid_families = [:inet, :ip, :ip6, :arp, :bridge, :netdev]
    unless value in valid_families do
      raise ArgumentError,
        "Invalid family: #{inspect(value)}. Must be one of: #{inspect(valid_families)}"
    end
    %{builder | family: value}
  end

  defp validate_and_set_field(builder, :requestor, value) when is_atom(value) do
    %{builder | requestor: value}
  end

  defp validate_and_set_field(builder, :table, value) when is_binary(value) or is_nil(value) do
    %{builder | table: value}
  end

  defp validate_and_set_field(builder, :chain, value) when is_binary(value) or is_nil(value) do
    %{builder | chain: value}
  end

  defp validate_and_set_field(builder, :collection, value) when is_binary(value) or is_nil(value) do
    %{builder | collection: value}
  end

  defp validate_and_set_field(builder, :type, value) when is_atom(value) or is_tuple(value) or is_nil(value) do
    %{builder | type: value}
  end

  defp validate_and_set_field(_builder, :spec, _value) do
    raise ArgumentError,
      ":spec is an internal field and cannot be set directly. Use add/2, delete/2, etc. to build commands."
  end

  defp validate_and_set_field(_builder, :commands, _value) do
    raise ArgumentError,
      ":commands cannot be set directly. Use add/2, delete/2, insert/2, etc. to build commands."
  end

  defp validate_and_set_field(_builder, field, value) do
    raise ArgumentError,
      "Invalid field #{inspect(field)} with value #{inspect(value)}. " <>
      "Valid fields: :family, :requestor, :table, :chain, :collection, :type"
  end


  @doc """
  Map object type to nftables JSON object key.

  Converts our internal object type names to the keys used in nftables JSON.
  """
  @spec type_to_obj(atom()) :: atom()
  def type_to_obj(type) do
    %{
      table: :table,
      chain: :chain,
      rule: :rule,
      rules: :rule,      # Both map to :rule
      flowtable: :flowtable,
      set: :set,
      map: :map,
      element: :element,
      counter: :counter,
      quota: :quota,
      limit: :limit
    }
    |> Map.get(type, :unknown)
  end
    

  ################################################################################
  # Generic Command Functions
  #
  # These functions detect the object type from opts and dispatch to build_command.
  ################################################################################

  @doc """
  Apply a command operation using options.

  Automatically detects the object type using priority map and dispatches
  to the unified build_command pipeline.

  ## Examples

      # Add a table
      builder |> add(table: "filter")

      # Add a chain with context
      builder |> add(table: "filter", chain: "input", type: :filter)

      # Add a rule using builder context
      builder |> add(rule: [%{accept: nil}])

      # Delete a rule
      builder |> delete(table: "filter", chain: "input", rule: [...], handle: 123)
  """
  @spec apply_with_opts(t(), atom(), keyword()) :: t()
  def apply_with_opts(builder, cmd_op, opts) when is_list(opts) do
    # Step 1: Detect main object type from opts
    {object_type, _value} = find_highest_priority(opts)

    # Step 2: Validate command is valid for this object type
    validate_command_object(cmd_op, object_type)

    # Step 3: Build command using unified pipeline
    build_command(builder, cmd_op, object_type, opts)
  end

  @doc """
  Validate that a command operation is valid for an object type.

  Raises ArgumentError if the combination is invalid.
  """
  @spec validate_command_object(atom(), atom()) :: :ok
  def validate_command_object(cmd_op, object_type) do
    valid = case cmd_op do
      :add -> true
      :delete -> true
      :flush -> object_type in [:table, :chain, :set, :map]
      :rename -> object_type in [:chain]
      :insert -> object_type in [:rule, :rules]
      :replace -> object_type in [:rule]
      _ -> false
    end

    unless valid do
      raise ArgumentError,
        "Command :#{cmd_op} is not valid for object type :#{object_type}. " <>
        valid_commands_message(object_type)
    end

    :ok
  end

  defp valid_commands_message(object_type) do
    commands = case object_type do
      :table -> "add, delete, flush"
      :chain -> "add, delete, flush, rename"
      :rule -> "add, delete, insert, replace"
      :rules -> "add, insert"
      :flowtable -> "add, delete"
      :set -> "add, delete, flush"
      :map -> "add, delete, flush"
      :counter -> "add, delete"
      :quota -> "add, delete"
      :limit -> "add, delete"
      :element -> "add, delete"
      _ -> "unknown"
    end
    "Valid commands for :#{object_type}: #{commands}"
  end

  ## Generic Command Entry Points

  @doc """
  Add an object (table, chain, rule, set, map, etc.).

  The object type is automatically detected from the options.

  ## Examples

      # Add table
      builder |> add(table: "filter")

      # Add chain
      builder |> add(chain: "input", type: :filter, hook: :input, priority: 0)

      # Add rule
      builder |> add(rule: [%{accept: nil}])

      # Add set
      builder |> add(set: "blocklist", type: :ipv4_addr)
  """
  @spec add(t(), keyword()) :: t()
  def add(%__MODULE__{} = builder, opts), do: apply_with_opts(builder, :add, opts)

  @doc """
  Delete an object.

  ## Examples

      builder |> delete(table: "filter")
      builder |> delete(chain: "input")
      builder |> delete(rule: [...], handle: 123)
  """
  @spec delete(t(), keyword()) :: t()
  def delete(%__MODULE__{} = builder, opts), do: apply_with_opts(builder, :delete, opts)

  @doc """
  Flush an object (remove contents but keep object).

  Valid for: table, chain, set, map

  ## Examples

      builder |> flush(table: "filter")  # Flush all chains/rules in table
      builder |> flush(chain: "input")   # Flush all rules in chain
  """
  @spec flush(t(), keyword()) :: t()
  def flush(%__MODULE__{} = builder, [:all | opts]), do: flush_ruleset(builder, opts)
  def flush(%__MODULE__{} = builder, opts), do: apply_with_opts(builder, :flush, opts)

  @doc """
  Rename a chain.

  ## Examples

      builder |> rename(chain: "input", newname: "INPUT")
  """
  @spec rename(t(), keyword()) :: t()
  def rename(%__MODULE__{} = builder, opts), do: apply_with_opts(builder, :rename, opts)

  @doc """
  Insert a rule at a specific position.

  ## Examples

      builder |> insert(rule: [...], index: 0)
  """
  @spec insert(t(), keyword()) :: t()
  def insert(%__MODULE__{} = builder, opts), do: apply_with_opts(builder, :insert, opts)

  @doc """
  Replace a rule at a specific handle.

  ## Examples

      builder |> replace(rule: [...], handle: 123)
  """
  @spec replace(t(), keyword()) :: t()
  def replace(%__MODULE__{} = builder, opts), do: apply_with_opts(builder, :replace, opts)

  ################################################################################
  # Object Detection via Priority Map
  #
  # The priority map determines which object is the MAIN target of an operation:
  # - Higher priority number = the object being operated on
  # - Lower priority numbers = context specifiers (which table/chain the object belongs to)
  # - Same priority = ERROR (ambiguous, cannot determine main object)
  ################################################################################

  @object_priority_map %{
    table: 0,    # Context: which table
    chain: 1,    # Context: which chain (within a table)
    rule: 2,     # Main object: operate on a rule
    rules: 2,    # Main object: operate on multiple rules (same priority as rule)
    flowtable: 3,  # Main object: operate on a flowtable
    set: 3,      # Main object: operate on a set
    map: 3,      # Main object: operate on a map
    counter: 3,  # Main object: operate on a counter
    quota: 3,    # Main object: operate on a quota
    limit: 3,    # Main object: operate on a limit
    element: 4   # Main object: operate on element(s) in a set/map
  }

  @doc """
  Find the object with highest priority from opts.

  Returns the object type and its value. Higher priority number indicates
  the main object being operated on. Lower priorities are context specifiers.

  ## Examples

      iex> find_highest_priority([table: "filter", chain: "input"])
      {:chain, "input"}  # chain (priority 1) > table (priority 0)

      iex> find_highest_priority([table: "filter", set: "blocklist"])
      {:set, "blocklist"}  # set (priority 3) > table (priority 0)

      iex> find_highest_priority([map: "m", set: "s"])
      ** (ArgumentError) Ambiguous object: both :map and :set have priority 3
  """
  @spec find_highest_priority(keyword()) :: {atom(), any()}
  def find_highest_priority(opts) do
    find_highest_priority(opts, @object_priority_map)
  end

  @spec find_highest_priority(keyword(), map()) :: {atom(), any()}
  def find_highest_priority(opts, obj_priority_map) do
    {max_priority, objects_at_max} =
      Enum.reduce(opts, {-1, []}, fn {key, val}, {max_p, objs} ->
        priority = Map.get(obj_priority_map, key, -1)
        cond do
          priority < 0 -> {max_p, objs}  # Not an object key, skip
          priority > max_p -> {priority, [{key, val}]}  # New max
          priority == max_p -> {max_p, [{key, val} | objs]}  # Same priority
          true -> {max_p, objs}  # Lower priority, skip
        end
      end)

    case objects_at_max do
      [] ->
        raise ArgumentError, "No valid object found in options"
      [{key, val}] ->
        {key, val}  # Unique highest priority
      multiple ->
        keys = Enum.map(multiple, &elem(&1, 0))
        group = find_priority_group(max_priority, obj_priority_map)
        raise ArgumentError,
          "Ambiguous object: only use one object of #{inspect(group)} (found: #{inspect(keys)})"
    end
  end

  @doc """
  Find all objects at a given priority level.
  Used for error messages when multiple objects have the same priority.
  """
  @spec find_priority_group(integer(), map()) :: list(atom())
  def find_priority_group(priority, obj_priority_map) do
    Enum.reduce(obj_priority_map, [], fn
      {id, p}, acc when p == priority -> [id | acc]
      _, acc -> acc
    end)
  end

  @doc """
  Get the object priority map.
  """
  def object_priority_map, do: @object_priority_map

  @doc """
  Extract context objects from opts.

  Returns a map of context objects that have lower priority than the main object.
  These will be used to update the builder state for chaining.

  ## Examples

      iex> extract_context([table: "filter", chain: "input"], :chain)
      %{table: "filter"}  # table has lower priority than chain

      iex> extract_context([table: "filter", chain: "input", rule: [...]], :rule)
      %{table: "filter", chain: "input"}  # both have lower priority than rule
  """
  @spec extract_context(keyword(), atom()) :: map()
  def extract_context(opts, main_object_type) do
    main_priority = Map.get(@object_priority_map, main_object_type, -1)

    Enum.reduce(opts, %{}, fn {key, val}, acc ->
      priority = Map.get(@object_priority_map, key, -1)

      # Only include objects with valid priority AND lower than main
      if priority >= 0 and priority < main_priority do
        Map.put(acc, key, val)
      else
        acc
      end
    end)
  end

  @doc """
  Update builder context from extracted context objects.

  Updates builder.table and builder.chain fields based on context.
  """
  @spec update_builder_context(t(), map()) :: t()
  def update_builder_context(builder, context) do
    builder
    |> maybe_update_table(Map.get(context, :table))
    |> maybe_update_chain(Map.get(context, :chain))
  end

  defp maybe_update_table(builder, nil), do: builder
  defp maybe_update_table(builder, table) when is_binary(table), do: %{builder | table: table}

  defp maybe_update_chain(builder, nil), do: builder
  defp maybe_update_chain(builder, chain) when is_binary(chain), do: %{builder | chain: chain}

  ################################################################################
  # Generic Command Constructor
  #
  # Unified pipeline for building commands from options.
  # Ties together: priority detection → context extraction → spec building →
  # optional field updates → command wrapping → builder updates
  ################################################################################

  @doc """
  Build a complete command from options using the unified pipeline.

  This is the main entry point that orchestrates the entire command building process:
  1. Extract context objects (lower priority than main object)
  2. Update builder with context for chaining
  3. Build base spec using main object + context
  4. Update spec with optional fields
  5. Wrap in command structure
  6. Update builder with main object for next operation
  7. Add command to builder

  ## Examples

      # Build a chain command
      build_command(builder, :add, :chain, table: "filter", chain: "input", type: :filter)
      #=> Updated builder with chain command added

      # Build a rule command (uses builder context)
      build_command(builder, :add, :rule, expr: [...])
      #=> Uses builder.table and builder.chain from context
  """
  @spec build_command(t(), atom(), atom(), keyword()) :: t()
  def build_command(builder, cmd_op, object_type, opts) do
    # Step 1: Extract context objects (lower priority than main object)
    context = extract_context(opts, object_type)

    # Step 2: Update builder with context for chaining
    builder = update_builder_context(builder, context)

    # Step 3: Build base spec using main object + context
    builder_with_spec = spec(builder, cmd_op, object_type, opts)

    # Step 4: Update spec with optional fields based on (object_type, cmd_op)
    updated_spec = update_spec(object_type, cmd_op, builder_with_spec.spec, opts)

    # Step 5: Get the object key for wrapping (:table, :chain, :rule, etc.)
    object_key = type_to_obj(object_type)

    # Step 6: Wrap in command map
    command = %{cmd_op => %{object_key => updated_spec}}

    # Step 7: Update builder with main object for chaining
    builder_updated = update_main_object_context(builder_with_spec, object_type, opts)

    # Step 8: Add command to builder
    add_command(builder_updated, command)
  end


  def validate_builder_opt(builder, opts, key) when key in [:family, :table, :chain] do
    val = Keyword.get(opts, key, Map.get(builder, key))
    is_nil(val) && raise ArgumentError, "#{key} must be specified as an option or set via set_#{key}/2"
    val
  end

  def validate_required_opt(opts, key) do
    val = Keyword.get(opts, key)
    is_nil(val) && raise ArgumentError, "#{key} must be specified as an option"
    val
  end
  
  def validate_opts(builder, opts, expect_list) do
    Enum.reduce(expect_list, %{}, fn key, acc ->
      val = cond do
        key in [:family, :table, :chain] -> validate_builder_opt(builder, opts, key)
        true -> validate_required_opt(opts, key)
      end
      Map.put(acc, key, val)
    end)
  end
  

  @doc """
  Flush the entire ruleset (remove all tables, chains, and rules).

  ## Options

  - `:family` - Optional family to flush (default: all families)

  ## Examples

      # Flush all tables/chains/rules for all families
      builder |> Builder.flush_ruleset()

      # Flush only inet family
      builder |> Builder.flush_ruleset(family: :inet)
  """
  @spec flush_ruleset(t(), keyword()) :: t()
  def flush_ruleset(%__MODULE__{} = builder, opts \\ []) do
    family = Keyword.get(opts, :family)

    command = %{flush: %{ruleset: (if family, do: %{family: family}, else: %{}) }}

    add_command(builder, command)
  end


  # Helper to normalize set/map types for JSON encoding
  # Converts {:concat, [:ipv4_addr, :inet_service]} to just a list for nftables JSON
  defp normalize_set_type({:concat, types}) when is_list(types) do
    Enum.map(types, &to_string/1)
  end
  defp normalize_set_type(type), do: type

  @doc """
  Build base specification for an object.

  Uses priority-based approach: lower-priority objects provide context.
  Builder state is used as fallback when opts don't specify context.

  ## Examples

      # Table (priority 0) - only needs family
      spec(builder, :table, table: "filter")
      #=> %{builder | spec: %{family: :inet, name: "filter"}}

      # Chain (priority 1) - needs table context
      spec(builder, :chain, table: "filter", chain: "input")
      #=> %{builder | spec: %{family: :inet, table: "filter", name: "input"}}

      # Rule (priority 2) - needs table and chain context
      spec(builder, :add, :rule, expr: [...])  # Uses builder.table and builder.chain
      #=> %{builder | spec: %{family: :inet, table: "filter", chain: "input", expr: [...]}}
  """
  @spec spec(t(), atom(), atom(), keyword()) :: t()
  def spec(builder, _cmd_op, :table, opts) do
    req_opts = validate_opts(builder, opts, [:family, :table])
    spec_map = %{family: req_opts.family, name: req_opts.table}
    %{builder | spec: spec_map}
  end

  def spec(builder, _cmd_op, :chain, opts) do
    req_opts = validate_opts(builder, opts, [:family, :table, :chain])
    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      name: req_opts.chain
    }
    %{builder | spec: spec_map}
  end

  def spec(builder, _cmd_op, :rule, opts) do
    req_opts = validate_opts(builder, opts, [:family, :table, :chain, :rule])
    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      chain: req_opts.chain,
      expr: normalize_rule_value(req_opts.rule)
    }
    %{builder | spec: spec_map}
  end

  def spec(builder, _cmd_op, :rules, opts) do
    # Same as :rule but handles multiple rules
    req_opts = validate_opts(builder, opts, [:family, :table, :chain, :rules])
    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      chain: req_opts.chain,
      expr: normalize_rule_value(req_opts.rules)
    }
    %{builder | spec: spec_map}
  end

  def spec(builder, cmd_op, :set, opts) do
    # Don't require :type for delete/flush operations
    required_fields = case cmd_op do
      :add -> [:family, :table, :set, :type]
      _ -> [:family, :table, :set]
    end
    req_opts = validate_opts(builder, opts, required_fields)
    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      name: req_opts.set
    }
    # Add type only if present (for add operations)
    spec_map = if Map.has_key?(req_opts, :type) do
      Map.put(spec_map, :type, normalize_set_type(req_opts.type))
    else
      spec_map
    end
    %{builder | spec: spec_map}
  end

  def spec(builder, _cmd_op, :map, opts) do
    # Don't require :type for delete/flush operations - only for add
    req_opts = validate_opts(builder, opts, [:family, :table, :map])
    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      name: req_opts.map
    }
    # Note: type handling for maps is special (tuple) - handled in update_spec for add
    %{builder | spec: spec_map}
  end

  def spec(builder, _cmd_op, :counter, opts) do
    req_opts = validate_opts(builder, opts, [:family, :table, :counter])
    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      name: req_opts.counter
    }
    %{builder | spec: spec_map}
  end

  def spec(builder, _cmd_op, :quota, opts) do
    req_opts = validate_opts(builder, opts, [:family, :table, :quota])
    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      name: req_opts.quota
    }
    %{builder | spec: spec_map}
  end

  def spec(builder, cmd_op, :limit, opts) do
    # Don't require :rate and :unit for delete/flush operations
    required_fields = case cmd_op do
      :add -> [:family, :table, :limit, :rate, :unit]
      _ -> [:family, :table, :limit]
    end
    req_opts = validate_opts(builder, opts, required_fields)
    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      name: req_opts.limit
    }
    # Add rate and per only if present (for add operations)
    spec_map = if Map.has_key?(req_opts, :rate) and Map.has_key?(req_opts, :unit) do
      spec_map
      |> Map.put(:rate, req_opts.rate)
      |> Map.put(:per, to_string(req_opts.unit))
    else
      spec_map
    end
    %{builder | spec: spec_map}
  end

  def spec(builder, cmd_op, :flowtable, opts) do
    # Don't require :hook, :priority, :devices for delete/flush operations
    required_fields = case cmd_op do
      :add -> [:family, :table, :flowtable, :hook, :priority, :devices]
      _ -> [:family, :table, :flowtable]
    end
    req_opts = validate_opts(builder, opts, required_fields)

    # Validate flowtable-specific fields for add operations
    if cmd_op == :add do
      case NFTables.Validation.validate_flowtable_hook(req_opts.hook) do
        :ok -> :ok
        {:error, msg} -> raise ArgumentError, msg
      end

      case NFTables.Validation.validate_flowtable_devices(req_opts.devices) do
        :ok -> :ok
        {:error, msg} -> raise ArgumentError, msg
      end
    end

    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      name: req_opts.flowtable
    }
    # Add hook, prio, dev only if present (for add operations)
    spec_map = if Map.has_key?(req_opts, :hook) do
      spec_map
      |> Map.put(:hook, to_string(req_opts.hook))
      |> Map.put(:prio, req_opts.priority)
      |> Map.put(:dev, req_opts.devices)
    else
      spec_map
    end
    %{builder | spec: spec_map}
  end

  def spec(builder, _cmd_op, :element, opts) do
    req_opts = validate_opts(builder, opts, [:family, :table, :element])

    # Element needs to know which collection (set or map) it belongs to
    collection_name = Keyword.get(opts, :set) || Keyword.get(opts, :map) || builder.collection

    unless collection_name do
      raise ArgumentError, "element requires :set or :map to be specified"
    end

    # Convert tuples to lists for JSON encoding (map elements are tuples)
    elem_value = normalize_element_value(req_opts.element)

    spec_map = %{
      family: req_opts.family,
      table: req_opts.table,
      name: collection_name,
      elem: elem_value
    }
    %{builder | spec: spec_map}
  end

  # Helper to convert tuples to lists for JSON encoding
  defp normalize_element_value(elements) when is_list(elements) do
    Enum.map(elements, fn
      {key, value} -> [key, value]  # Map element: tuple -> list
      other -> other  # Set element: keep as-is
    end)
  end
  defp normalize_element_value(other), do: other

  ################################################################################
  # Unified Spec Updates
  #
  # Single function to update specs based on (object_type, cmd_op) combination.
  # Replaces all individual *_update_opts functions.
  ################################################################################

  @doc """
  Update spec with optional fields based on object type and command operation.

  Consolidates all *_update_opts functions into a single dispatch function.

  ## Examples

      # Chain with base chain options
      update_spec(:chain, :add, spec, type: :filter, hook: :input, priority: 0)

      # Rule with insert options
      update_spec(:rule, :insert, spec, index: 0, comment: "Allow SSH")

      # Set with flags
      update_spec(:set, :add, spec, flags: [:interval], timeout: 3600)
  """
  @spec update_spec(atom(), atom(), map(), keyword()) :: map()

  ## Chain Updates
  def update_spec(:chain, :add, spec, opts) do
    base_chain_opts = [:type, :hook, :priority]
    if Enum.any?(base_chain_opts, &Keyword.has_key?(opts, &1)) do
      spec
      |> maybe_add(:type, Keyword.get(opts, :type, :filter))
      |> maybe_add(:hook, Keyword.get(opts, :hook))
      |> maybe_add(:prio, Keyword.get(opts, :priority, 0))
      |> maybe_add(:policy, Keyword.get(opts, :policy))
      |> maybe_add(:dev, Keyword.get(opts, :dev))
    else
      spec
    end
  end

  def update_spec(:chain, :rename, spec, opts) do
    newname = Keyword.get(opts, :newname)
    unless newname do
      raise ArgumentError, ":newname must be specified for rename operation"
    end
    Map.put(spec, :newname, newname)
  end

  ## Rule Updates
  def update_spec(:rule, :add, spec, opts) do
    spec
    |> maybe_add(:comment, Keyword.get(opts, :comment))
  end

  def update_spec(:rule, :insert, spec, opts) do
    spec
    |> maybe_add(:index, Keyword.get(opts, :index))
    |> maybe_add(:handle, Keyword.get(opts, :handle))
    |> maybe_add(:comment, Keyword.get(opts, :comment))
  end

  def update_spec(:rule, :replace, spec, opts) do
    handle = Keyword.get(opts, :handle)
    unless handle do
      raise ArgumentError, ":handle must be specified for replace operation"
    end
    spec
    |> Map.put(:handle, handle)
    |> maybe_add(:comment, Keyword.get(opts, :comment))
  end

  def update_spec(:rule, :delete, spec, opts) do
    # Extract handle from various sources
    handle = cond do
      # If rule value is an integer, it's the handle directly
      is_integer(spec.expr) -> spec.expr
      # If rule value is a keyword list with :handle, extract it
      is_list(spec.expr) and Keyword.keyword?(spec.expr) -> Keyword.get(spec.expr, :handle)
      # If handle is in opts, use it
      Keyword.has_key?(opts, :handle) -> Keyword.get(opts, :handle)
      # Otherwise error
      true -> nil
    end

    unless handle do
      raise ArgumentError, ":handle must be specified for delete operation (as rule value or separate option)"
    end

    # For delete, remove expr and add handle
    spec
    |> Map.delete(:expr)
    |> Map.put(:handle, handle)
  end

  ## Set Updates
  def update_spec(:set, :add, spec, opts) do
    spec
    |> maybe_add(:flags, Keyword.get(opts, :flags))
    |> maybe_add(:timeout, Keyword.get(opts, :timeout))
    |> maybe_add(:"gc-interval", Keyword.get(opts, :gc_interval))
    |> maybe_add(:size, Keyword.get(opts, :size))
  end

  ## Map Updates
  def update_spec(:map, :add, spec, opts) do
    type_val = Keyword.get(opts, :type)

    unless is_tuple(type_val) and tuple_size(type_val) == 2 do
      raise ArgumentError, "map :type must be a tuple of 2 elements: {key_type, value_type}"
    end

    {key_type, value_type} = type_val
    spec
    |> Map.put(:type, key_type)
    |> Map.put(:map, to_string(value_type))
  end

  ## Counter Updates
  def update_spec(:counter, :add, spec, opts) do
    spec
    |> maybe_add(:packets, Keyword.get(opts, :packets, 0))
    |> maybe_add(:bytes, Keyword.get(opts, :bytes, 0))
  end

  ## Quota Updates
  def update_spec(:quota, :add, spec, opts) do
    spec
    |> maybe_add(:bytes, Keyword.get(opts, :bytes, 0))
    |> maybe_add(:used, Keyword.get(opts, :used, 0))
    |> maybe_add(:over, Keyword.get(opts, :over, false))
  end

  ## Limit Updates
  def update_spec(:limit, :add, spec, opts) do
    spec
    |> maybe_add(:burst, Keyword.get(opts, :burst, 0))
  end

  ## Flowtable Updates
  def update_spec(:flowtable, :add, spec, opts) do
    flags = Keyword.get(opts, :flags)
    # Convert atom flags to strings for JSON
    flags = if flags, do: Enum.map(flags, &to_string/1), else: nil
    spec
    |> maybe_add(:flags, flags)
  end

  ## Element Updates
  def update_spec(:element, :add, spec, _opts) do
    # Elements don't have additional optional fields for add
    spec
  end

  ## Table Updates
  def update_spec(:table, _cmd_op, spec, _opts) do
    # Tables don't have additional optional fields
    spec
  end

  ## Default - no updates
  def update_spec(_object_type, _cmd_op, spec, _opts), do: spec

  @doc """
  Update builder with main object context for chaining.

  When the main object is :table or :chain, update the builder state
  so subsequent operations can use this context.

  ## Examples

      # After adding a table, builder.table is updated
      update_main_object_context(builder, :table, table: "filter")
      #=> %{builder | table: "filter"}

      # After adding a chain, builder.chain is updated
      update_main_object_context(builder, :chain, chain: "input")
      #=> %{builder | chain: "input"}

      # Other objects don't update builder context
      update_main_object_context(builder, :rule, rule: [...])
      #=> builder  # unchanged
  """
  @spec update_main_object_context(t(), atom(), keyword()) :: t()
  def update_main_object_context(builder, :table, opts) do
    case Keyword.get(opts, :table) do
      nil -> builder
      table -> %{builder | table: table}
    end
  end

  def update_main_object_context(builder, :chain, opts) do
    case Keyword.get(opts, :chain) do
      nil -> builder
      chain -> %{builder | chain: chain}
    end
  end

  def update_main_object_context(builder, :set, opts) do
    # Track set name and type for element operations
    case {Keyword.get(opts, :set), Keyword.get(opts, :type)} do
      {nil, _} -> builder
      {set_name, type} -> %{builder | collection: set_name, type: type}
    end
  end

  def update_main_object_context(builder, :map, opts) do
    # Track map name and type for element operations
    case {Keyword.get(opts, :map), Keyword.get(opts, :type)} do
      {nil, _} -> builder
      {map_name, type} -> %{builder | collection: map_name, type: type}
    end
  end

  def update_main_object_context(builder, _object_type, _opts), do: builder

  ################################################################################
  # Rule Operations
  ################################################################################
  # Note: Individual rule operations have been replaced by the unified API.
  # Use: builder |> add(rule: expr_list, ...)
  # See the top-level add/2, insert/2, replace/2, delete/2 functions.

  @doc """
  Add multiple rules at once.

  ## Examples

      rules = [
        [%{match: ...}, %{accept: nil}],
        [%{match: ...}, %{drop: nil}]
      ]
      builder |> Builder.add_rules(rules)
  """
  @spec add_rules(t(), list(list(map())), keyword()) :: t()
  def add_rules(%__MODULE__{} = builder, rules, opts \\ []) when is_list(rules) do
    Enum.reduce(rules, builder, fn rule_expr, acc ->
      add(acc, Keyword.merge([rule: rule_expr], opts))
    end)
  end


  ## Set Operations
  # Note: Individual set operations have been replaced by the unified API.
  # Use: builder |> add(set: "name", type: :ipv4_addr, ...)
  # See the top-level add/2, delete/2, flush/2 functions.


  ## Maps
  # Note: Individual map operations have been replaced by the unified API.
  # Use: builder |> add(map: "name", type: {:key_type, :value_type}, ...)
  # See the top-level add/2, delete/2, flush/2 functions.

  ## Elements
  # Note: Individual element operations have been replaced by the unified API.
  # Use: builder |> add(element: [...], set: "setname")
  #      builder |> add(element: [...], map: "mapname")
  # See the top-level add/2, delete/2 functions.


  ## Named Counters
  # Note: Individual counter operations have been replaced by the unified API.
  # Use: builder |> add(counter: "name", packets: 0, bytes: 0)
  # See the top-level add/2, delete/2 functions.

  ## Quotas
  # Note: Individual quota operations have been replaced by the unified API.
  # Use: builder |> add(quota: "name", bytes: 1000, ...)
  # See the top-level add/2, delete/2 functions.

  ## Limits
  # Note: Individual limit operations have been replaced by the unified API.
  # Use: builder |> add(limit: "name", rate: 10, unit: :minute, burst: 5)
  # See the top-level add/2, delete/2 functions.

  ## Round-Trip Import (Phase 8)

  @doc """
  Import a table from Query results into the builder.

  Converts a table map from `Query.list_tables/2` into an `add_table` command.

  ## Parameters
  - `builder` - The builder instance
  - `table_map` - Table map from Query.list_tables/2 with keys: `:name`, `:family`

  ## Examples

      {:ok, tables} = Query.list_tables(pid)
      builder = Enum.reduce(tables, Builder.new(), fn table, b ->
        Builder.import_table(b, table)
      end)
  """
  @spec import_table(t(), map()) :: t()
  def import_table(%__MODULE__{} = builder, %{name: name, family: family}) do
    %__MODULE__{builder | family: family}
    |> add(table: name)
  end

  @doc """
  Import a chain from Query results into the builder.

  Converts a chain map from `Query.list_chains/2` into an `add_chain` command.

  ## Parameters
  - `builder` - The builder instance
  - `chain_map` - Chain map from Query.list_chains/2

  ## Examples

      {:ok, chains} = Query.list_chains(pid)
      builder = Enum.reduce(chains, Builder.new(), fn chain, b ->
        Builder.import_chain(b, chain)
      end)
  """
  @spec import_chain(t(), map()) :: t()
  def import_chain(%__MODULE__{} = builder, chain_map) do
    opts = build_chain_opts(chain_map)

    opts
    |> Keyword.put(:table, chain_map.table)
    |> Keyword.put(:chain, chain_map.name)
    |> then(&add(builder, &1))
  end

  defp build_chain_opts(chain_map) do
    []
    |> maybe_add_opt(:type, chain_map[:type])
    |> maybe_add_opt(:hook, chain_map[:hook])
    |> maybe_add_opt(:priority, chain_map[:prio])
    |> maybe_add_opt(:policy, chain_map[:policy])
    |> maybe_add_opt(:family, chain_map[:family])
  end

  @doc false
  def maybe_add_opt(opts, _key, nil), do: opts
  def maybe_add_opt(opts, key, value), do: Keyword.put(opts, key, value)

  @doc """
  Import a rule from Query results into the builder.

  Converts a rule map from `Query.list_rules/4` into an `add_rule` command.
  The `expr` field from the query result is used directly as it matches
  the Builder's expression format.

  ## Parameters
  - `builder` - The builder instance
  - `rule_map` - Rule map from Query.list_rules/4 with keys: `:family`, `:table`, `:chain`, `:expr`

  ## Examples

      {:ok, rules} = Query.list_rules(pid, "filter", "INPUT")
      builder = Enum.reduce(rules, Builder.new(), fn rule, b ->
        Builder.import_rule(b, rule)
      end)
  """
  @spec import_rule(t(), map()) :: t()
  def import_rule(%__MODULE__{} = builder, %{table: table, chain: chain, expr: expr}) do
    add(builder, table: table, chain: chain, rule: expr)
  end

  @doc """
  Import a set from Query results into the builder.

  Converts a set map from `Query.list_sets/3` into an `add_set` command.

  ## Parameters
  - `builder` - The builder instance
  - `set_map` - Set map from Query.list_sets/3

  ## Examples

      {:ok, sets} = Query.list_sets(pid, family: :inet)
      builder = Enum.reduce(sets, Builder.new(), fn set, b ->
        Builder.import_set(b, set)
      end)
  """
  @spec import_set(t(), map()) :: t()
  def import_set(%__MODULE__{} = builder, set_map) do
    opts = build_set_opts(set_map)

    opts
    |> Keyword.put(:table, set_map.table)
    |> Keyword.put(:set, set_map.name)
    |> then(&add(builder, &1))
  end

  defp build_set_opts(set_map) do
    []
    |> maybe_add_opt(:type, set_map[:type])
    |> maybe_add_opt(:family, set_map[:family])
    |> maybe_add_opt(:flags, set_map[:flags])
    |> maybe_add_opt(:timeout, set_map[:timeout])
    |> maybe_add_opt(:gc_interval, set_map[:gc_interval])
    |> maybe_add_opt(:size, set_map[:size])
  end

  @doc """
  Import an entire ruleset from Query results.

  Queries the current ruleset and converts all tables, chains, rules, and sets
  into Builder commands. This allows you to:
  1. Query existing firewall configuration
  2. Modify it programmatically
  3. Reapply the modified configuration

  ## Parameters
  - `pid` - NFTables.Port process pid
  - `opts` - Options:
    - `:family` - Protocol family to import (default: `:inet`)
    - `:exclude_handles` - Exclude handle fields from import (default: `true`)

  ## Examples

      # Import existing ruleset
      {:ok, builder} = Builder.from_ruleset(pid, family: :inet)

      # Modify and reapply
      builder
      |> Builder.add(
        table: "filter",
        chain: "INPUT",
        rule: [
          %{match: %{left: %{payload: %{protocol: "ip", field: "saddr"}}, right: "10.0.0.0/8", op: "=="}},
          %{drop: nil}
        ]
      )
      |> Builder.submit(pid: pid)

      # Or start fresh and import specific elements
      {:ok, tables} = Query.list_tables(pid)
      {:ok, chains} = Query.list_chains(pid)

      builder = Builder.new()
      builder = Enum.reduce(tables, builder, &Builder.import_table(&2, &1))
      builder = Enum.reduce(chains, builder, &Builder.import_chain(&2, &1))
  """
  @spec from_ruleset(pid(), keyword()) :: {:ok, t()} | {:error, term()}
  def from_ruleset(pid, opts \\ []) when is_pid(pid) do
    family = Keyword.get(opts, :family, :inet)

    # Use new pipeline pattern: Query -> NFTables.Local -> Decoder
    with {:ok, decoded} <- NFTables.Query.list_ruleset(family: family)
                          |> NFTables.Local.submit(pid: pid)
                          |> NFTables.Decoder.decode() do

      tables = Map.get(decoded, :tables, [])
      chains = Map.get(decoded, :chains, [])
      sets = Map.get(decoded, :sets, [])
      rules = Map.get(decoded, :rules, [])

      builder = new(family: family)

      # Import in order: tables -> chains -> sets -> rules
      builder = Enum.reduce(tables, builder, fn table, b ->
        import_table(b, table)
      end)

      builder = Enum.reduce(chains, builder, fn chain, b ->
        import_chain(b, chain)
      end)

      builder = Enum.reduce(sets, builder, fn set, b ->
        import_set(b, set)
      end)

      builder = Enum.reduce(rules, builder, fn rule, b ->
        import_rule(b, rule)
      end)

      {:ok, builder}
    end
  end

  ## Submission via Requestor

  @doc """
  Submit the builder configuration using the configured requestor.

  Uses the requestor module specified in the builder's `requestor` field
  (defaults to `NFTables.Local` for local execution).
  The requestor must implement the `NFTables.Requestor` behaviour.

  This function is useful when you want to use custom submission handlers
  for scenarios like remote execution, audit logging, testing, or conditional
  execution strategies.

  ## Parameters

  - `builder` - The builder with accumulated commands and configured requestor

  ## Returns

  - `:ok` - Successful submission
  - `{:ok, result}` - Successful submission with result
  - `{:error, reason}` - Failed submission

  ## Examples

      # Use default local execution (NFTables.Local)
      {:ok, pid} = NFTables.start_link()
      builder = Builder.new()
      |> Builder.add(table: "filter")
      |> Builder.add(chain: "INPUT")
      |> Builder.submit(pid: pid)  # Uses NFTables.Local

      # Configure custom requestor when creating builder
      builder = Builder.new(family: :inet, requestor: MyApp.RemoteRequestor)
      |> Builder.add(table: "filter")
      |> Builder.submit(node: :remote_host)  # Uses MyApp.RemoteRequestor

      # Or set requestor later
      builder = Builder.new()
      |> Builder.add(table: "filter")
      |> Builder.set_requestor(MyApp.AuditRequestor)
      |> Builder.submit(audit_id: "12345")

  ## See Also

  - `NFTables.Requestor` - Behaviour definition and examples
  - `NFTables.Local` - Default local execution requestor
  - `submit/2` - Submit with options or override requestor
  - `set_requestor/2` - Set requestor module
  """
  @spec submit(t()) :: :ok | {:ok, term()} | {:error, term()}
  def submit(%__MODULE__{} = builder) do
    submit(builder, [])
  end

  @doc """
  Submit the builder configuration with options or override requestor.

  This function allows you to:
  - Pass options to the requestor's submit callback
  - Override the builder's requestor for this submission only

  ## Parameters

  - `builder` - The builder with accumulated commands
  - `opts` - Keyword list options:
    - `:requestor` - Override the builder's requestor module (optional)
    - Other options are passed to the requestor's submit callback

  ## Returns

  - `:ok` - Successful submission
  - `{:ok, result}` - Successful submission with result
  - `{:error, reason}` - Failed submission

  ## Raises

  - `ArgumentError` - If no requestor is available (neither in builder nor opts)
  - `UndefinedFunctionError` - If requestor doesn't implement submit/2

  ## Examples

      # Pass options to requestor
      builder
      |> Builder.submit(node: :firewall@server, timeout: 10_000)

      # Override requestor for this submission only
      builder = Builder.new(requestor: MyApp.DefaultRequestor)
      |> Builder.add(table: "filter")
      |> Builder.submit(requestor: MyApp.SpecialRequestor, priority: :high)

      # Use without pre-configured requestor
      builder = Builder.new()
      |> Builder.add(table: "filter")
      |> Builder.submit(requestor: MyApp.RemoteRequestor, node: :remote_host)

  ## See Also

  - `NFTables.Requestor` - Behaviour definition
  - `submit/1` - Submit using builder's requestor
  - `set_requestor/2` - Set requestor on builder
  """
  @spec submit(t(), keyword()) :: :ok | {:ok, term()} | {:error, term()}
  def submit(%__MODULE__{} = builder, opts) when is_list(opts) do
    # Determine requestor: opts override, then builder field
    requestor = Keyword.get(opts, :requestor, builder.requestor)

    unless requestor do
      raise ArgumentError, """
      No requestor module available for submission.

      You must either:
      1. Set requestor in builder: Builder.new(requestor: MyRequestor)
      2. Pass requestor in options: Builder.submit(builder, requestor: MyRequestor)

      See NFTables.Requestor documentation for implementing custom requestors.
      """
    end

    # Ensure module is loaded before checking
    Code.ensure_compiled!(requestor)

    # Validate that the requestor module exists and exports submit/2
    unless function_exported?(requestor, :submit, 2) do
      raise ArgumentError, """
      Module #{inspect(requestor)} does not implement NFTables.Requestor behaviour.

      The requestor must export submit/2 function. Example:

          defmodule #{inspect(requestor)} do
            @behaviour NFTables.Requestor

            @impl true
            def submit(builder, opts) do
              # Your submission logic here
              :ok
            end
          end

      See NFTables.Requestor documentation for more examples.
      """
    end

    # Call the requestor's submit callback
    apply(requestor, :submit, [builder, opts])
  end

  @doc """
  Convert builder to Elixir map structure.

  Returns the raw Elixir data structure that will be sent to nftables.
  No JSON encoding happens here - this is pure Elixir data.

  ## Examples

      builder |> Builder.to_map()
      #=> %{nftables: [%{add: %{table: %{family: "inet", name: "filter"}}}]}

  For backwards compatibility, `to_json/1` is an alias that returns JSON.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{commands: commands}) do
    %{
      nftables: commands
    }
  end

  @doc """
  Convert builder to JSON string for inspection.

  ## Examples

      builder |> Builder.to_json()
      #=> "{\"nftables\":[{\"add\":{\"table\":{...}}}]}"
  """
  @spec to_json(t()) :: String.t()
  def to_json(%__MODULE__{} = builder) do
    builder
    |> to_map()
    |> JSON.encode!()
  end

  ## Private Helpers

  # Normalize rule values - automatically convert Expr structs to expression lists
  defp normalize_rule_value(%NFTables.Expr{} = rule) do
    NFTables.Expr.to_list(rule)
  end

  defp normalize_rule_value(rules) when is_list(rules) do
    # Check if this is a list of Expr structs or already an expression list
    case rules do
      # Empty list - return as-is
      [] -> []
      # List of structs - convert each one
      [%NFTables.Expr{} | _] = rule_list ->
        Enum.map(rule_list, &normalize_rule_value/1)
      # Already an expression list (list of maps) - return as-is
      _ -> rules
    end
  end

  defp normalize_rule_value(expr_list), do: expr_list  # Already a list of expressions

  # Add a command to the builder
  defp add_command(%__MODULE__{commands: commands} = builder, command) do
    %{builder | commands: commands ++ [command]}
  end

  # Conditionally add key to map if value is not nil
  defp maybe_add(map, _key, nil), do: map
  defp maybe_add(map, key, value), do: Map.put(map, key, value)
end
