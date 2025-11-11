defmodule NFTablesEx.Builder do
  @moduledoc """
  Functional builder for constructing nftables configurations.

  This module provides a clean, functional API for building nftables commands.
  The builder accumulates commands and can be executed when ready, separating
  configuration building from execution.

  ## Design Philosophy

  - **Pure Building**: Builder is immutable, no side effects during construction
  - **Explicit Execution**: Commands execute only when `execute/2` is called with a pid
  - **Atom Keys**: All JSON uses atom keys (converted to strings during encoding)
  - **Context Tracking**: Maintains current table/chain for convenience

  ## Basic Usage

      # Create builder
      builder = Builder.new(family: :inet)

      # Add table and chain
      builder = builder
      |> Builder.add_table("filter")
      |> Builder.add_chain("input", type: :filter, hook: :input, priority: 0, policy: :drop)

      # Add rules (using RuleBuilder or raw expressions)
      builder = builder
      |> Builder.add_rule([
          %{match: %{left: %{ct: %{key: "state"}}, right: ["established", "related"], op: "in"}},
          %{accept: nil}
        ])

      # Execute when ready
      {:ok, pid} = NFTablesEx.start_link()
      Builder.execute(builder, pid)

  ## Piping Pattern

      Builder.new(family: :inet)
      |> Builder.add_table("filter")
      |> Builder.add_chain("input", type: :filter, hook: :input, priority: 0, policy: :drop)
      |> Builder.add_chain("forward", type: :filter, hook: :forward, priority: 0, policy: :drop)
      |> Builder.add_chain("output", type: :filter, hook: :output, priority: 0, policy: :accept)
      |> Builder.execute(pid)
  """

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type t :: %__MODULE__{
          family: family(),
          commands: list(map()),
          current_table: String.t() | nil,
          current_chain: String.t() | nil
        }

  defstruct family: :inet,
            commands: [],
            current_table: nil,
            current_chain: nil

  ## Core Functions

  @doc """
  Create a new builder.

  ## Options

  - `:family` - Address family (default: `:inet`)

  ## Examples

      Builder.new()
      Builder.new(family: :ip6)
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    %__MODULE__{
      family: Keyword.get(opts, :family, :inet)
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
  Set the current table context.

  Subsequent operations will use this table unless overridden.

  ## Examples

      builder |> Builder.set_table("filter")
  """
  @spec set_table(t(), String.t()) :: t()
  def set_table(%__MODULE__{} = builder, table) when is_binary(table) do
    %{builder | current_table: table}
  end

  @doc """
  Set the current chain context.

  Subsequent rule operations will use this chain unless overridden.

  ## Examples

      builder |> Builder.set_chain("input")
  """
  @spec set_chain(t(), String.t()) :: t()
  def set_chain(%__MODULE__{} = builder, chain) when is_binary(chain) do
    %{builder | current_chain: chain}
  end

  ## Table Operations

  @doc """
  Add a table.

  ## Examples

      builder |> Builder.add_table("filter")
      builder |> Builder.add_table("nat", family: :ip)
  """
  @spec add_table(t(), String.t(), keyword()) :: t()
  def add_table(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    family = Keyword.get(opts, :family, builder.family)

    command = %{
      add: %{
        table: %{
          family: family,
          name: name
        }
      }
    }

    builder
    |> add_command(command)
    |> set_table(name)
  end

  @doc """
  Delete a table.

  ## Examples

      builder |> Builder.delete_table("old_table")
      builder |> Builder.delete_table("old_table", family: :ip)
  """
  @spec delete_table(t(), String.t(), keyword()) :: t()
  def delete_table(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    family = Keyword.get(opts, :family, builder.family)

    command = %{
      delete: %{
        table: %{
          family: family,
          name: name
        }
      }
    }

    add_command(builder, command)
  end

  @doc """
  Flush a table (remove all chains and rules, keep table).

  ## Examples

      builder |> Builder.flush_table("filter")
  """
  @spec flush_table(t(), String.t(), keyword()) :: t()
  def flush_table(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    family = Keyword.get(opts, :family, builder.family)

    command = %{
      flush: %{
        table: %{
          family: family,
          name: name
        }
      }
    }

    add_command(builder, command)
  end

  ## Chain Operations

  @doc """
  Add a regular chain (not a base chain).

  ## Examples

      builder |> Builder.add_chain("custom_chain")
  """
  @spec add_chain(t(), String.t(), keyword()) :: t()
  def add_chain(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified or set via set_table/2"
    end

    # Check if base chain options are provided
    base_chain_opts = [:type, :hook, :priority]
    is_base_chain = Enum.any?(base_chain_opts, &Keyword.has_key?(opts, &1))

    chain_spec =
      if is_base_chain do
        # Base chain with hook, type, priority, policy
        %{
          family: family,
          table: table,
          name: name,
          type: Keyword.get(opts, :type, :filter),
          hook: Keyword.get(opts, :hook),
          prio: Keyword.get(opts, :priority, 0)
        }
        |> maybe_add(:policy, Keyword.get(opts, :policy))
        |> maybe_add(:dev, Keyword.get(opts, :dev))
      else
        # Regular chain
        %{
          family: family,
          table: table,
          name: name
        }
      end

    command = %{
      add: %{
        chain: chain_spec
      }
    }

    builder
    |> add_command(command)
    |> set_chain(name)
  end

  @doc """
  Delete a chain.

  ## Examples

      builder |> Builder.delete_chain("old_chain")
  """
  @spec delete_chain(t(), String.t(), keyword()) :: t()
  def delete_chain(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified or set via set_table/2"
    end

    command = %{
      delete: %{
        chain: %{
          family: family,
          table: table,
          name: name
        }
      }
    }

    add_command(builder, command)
  end

  @doc """
  Flush a chain (remove all rules, keep chain).

  ## Examples

      builder |> Builder.flush_chain("input")
  """
  @spec flush_chain(t(), String.t(), keyword()) :: t()
  def flush_chain(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified or set via set_table/2"
    end

    command = %{
      flush: %{
        chain: %{
          family: family,
          table: table,
          name: name
        }
      }
    }

    add_command(builder, command)
  end

  @doc """
  Rename a chain.

  ## Examples

      builder |> Builder.rename_chain("old_name", "new_name")
  """
  @spec rename_chain(t(), String.t(), String.t(), keyword()) :: t()
  def rename_chain(%__MODULE__{} = builder, old_name, new_name, opts \\ [])
      when is_binary(old_name) and is_binary(new_name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified or set via set_table/2"
    end

    command = %{
      rename: %{
        chain: %{
          family: family,
          table: table,
          name: old_name,
          newname: new_name
        }
      }
    }

    add_command(builder, command)
  end

  ## Rule Operations

  @doc """
  Add a rule (append to chain).

  ## Parameters

  - `expr` - Expression list (from RuleBuilder or manual construction)
  - `opts` - Options:
    - `:table` - Table name (default: current_table)
    - `:chain` - Chain name (default: current_chain)
    - `:family` - Address family (default: builder family)
    - `:comment` - Rule comment (optional)
    - `:index` - Insert at index (optional, for insert mode)

  ## Examples

      # Using expression list
      builder |> Builder.add_rule([
        %{match: %{left: %{payload: %{protocol: "tcp", field: "dport"}}, right: 22, op: "=="}},
        %{accept: nil}
      ])

      # With comment
      builder |> Builder.add_rule(expr_list, comment: "Allow SSH")
  """
  @spec add_rule(t(), list(map()), keyword()) :: t()
  def add_rule(%__MODULE__{} = builder, expr, opts \\ []) when is_list(expr) do
    table = Keyword.get(opts, :table, builder.current_table)
    chain = Keyword.get(opts, :chain, builder.current_chain)
    family = Keyword.get(opts, :family, builder.family)

    unless table && chain do
      raise ArgumentError, "table and chain must be specified or set via set_table/2 and set_chain/2"
    end

    rule_spec = %{
      family: family,
      table: table,
      chain: chain,
      expr: expr
    }
    |> maybe_add(:comment, Keyword.get(opts, :comment))

    command = %{
      add: %{
        rule: rule_spec
      }
    }

    add_command(builder, command)
  end

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
    Enum.reduce(rules, builder, fn rule, acc ->
      add_rule(acc, rule, opts)
    end)
  end

  @doc """
  Insert a rule at a specific position.

  ## Options

  - `:index` - Insert at this position (0-based)
  - `:handle` - Insert before/after this rule handle
  - `:position` - `:before` or `:after` (used with :handle)

  ## Examples

      # Insert at beginning
      builder |> Builder.insert_rule(expr, index: 0)

      # Insert before rule with handle 42
      builder |> Builder.insert_rule(expr, handle: 42, position: :before)
  """
  @spec insert_rule(t(), list(map()), keyword()) :: t()
  def insert_rule(%__MODULE__{} = builder, expr, opts) when is_list(expr) do
    table = Keyword.get(opts, :table, builder.current_table)
    chain = Keyword.get(opts, :chain, builder.current_chain)
    family = Keyword.get(opts, :family, builder.family)

    unless table && chain do
      raise ArgumentError, "table and chain must be specified"
    end

    rule_spec = %{
      family: family,
      table: table,
      chain: chain,
      expr: expr
    }
    |> maybe_add(:index, Keyword.get(opts, :index))
    |> maybe_add(:handle, Keyword.get(opts, :handle))
    |> maybe_add(:comment, Keyword.get(opts, :comment))

    command = %{
      insert: %{
        rule: rule_spec
      }
    }

    add_command(builder, command)
  end

  @doc """
  Replace a rule by handle.

  ## Examples

      builder |> Builder.replace_rule(new_expr, handle: 42)
  """
  @spec replace_rule(t(), list(map()), keyword()) :: t()
  def replace_rule(%__MODULE__{} = builder, expr, opts) when is_list(expr) do
    table = Keyword.get(opts, :table, builder.current_table)
    chain = Keyword.get(opts, :chain, builder.current_chain)
    family = Keyword.get(opts, :family, builder.family)
    handle = Keyword.fetch!(opts, :handle)

    unless table && chain do
      raise ArgumentError, "table and chain must be specified"
    end

    rule_spec = %{
      family: family,
      table: table,
      chain: chain,
      handle: handle,
      expr: expr
    }
    |> maybe_add(:comment, Keyword.get(opts, :comment))

    command = %{
      replace: %{
        rule: rule_spec
      }
    }

    add_command(builder, command)
  end

  @doc """
  Delete a rule by handle.

  ## Examples

      builder |> Builder.delete_rule(handle: 42)
  """
  @spec delete_rule(t(), keyword()) :: t()
  def delete_rule(%__MODULE__{} = builder, opts) do
    table = Keyword.get(opts, :table, builder.current_table)
    chain = Keyword.get(opts, :chain, builder.current_chain)
    family = Keyword.get(opts, :family, builder.family)
    handle = Keyword.fetch!(opts, :handle)

    unless table && chain do
      raise ArgumentError, "table and chain must be specified"
    end

    command = %{
      delete: %{
        rule: %{
          family: family,
          table: table,
          chain: chain,
          handle: handle
        }
      }
    }

    add_command(builder, command)
  end

  ## Set Operations

  @doc """
  Add a named set.

  ## Options

  - `:type` - Set element type (`:ipv4_addr`, `:ipv6_addr`, `:ether_addr`, `:inet_proto`, `:inet_service`, `:mark`)
  - `:flags` - Set flags (list, e.g., `[:constant]`, `[:interval]`, `[:timeout]`)
  - `:timeout` - Default timeout for elements (seconds)
  - `:gc_interval` - Garbage collection interval (seconds)
  - `:size` - Maximum set size

  ## Examples

      builder |> Builder.add_set("blocklist", type: :ipv4_addr)
      builder |> Builder.add_set("ports", type: :inet_service, flags: [:interval])
  """
  @spec add_set(t(), String.t(), keyword()) :: t()
  def add_set(%__MODULE__{} = builder, name, opts) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)
    type = Keyword.fetch!(opts, :type)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    set_spec = %{
      family: family,
      table: table,
      name: name,
      type: type
    }
    |> maybe_add(:flags, Keyword.get(opts, :flags))
    |> maybe_add(:timeout, Keyword.get(opts, :timeout))
    |> maybe_add(:"gc-interval", Keyword.get(opts, :gc_interval))
    |> maybe_add(:size, Keyword.get(opts, :size))

    command = %{
      add: %{
        set: set_spec
      }
    }

    add_command(builder, command)
  end

  @doc """
  Delete a set.

  ## Examples

      builder |> Builder.delete_set("old_set")
  """
  @spec delete_set(t(), String.t(), keyword()) :: t()
  def delete_set(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    command = %{
      delete: %{
        set: %{
          family: family,
          table: table,
          name: name
        }
      }
    }

    add_command(builder, command)
  end

  @doc """
  Flush a set (remove all elements, keep set structure).

  ## Examples

      builder |> Builder.flush_set("blocklist")
  """
  @spec flush_set(t(), String.t(), keyword()) :: t()
  def flush_set(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    command = %{
      flush: %{
        set: %{
          family: family,
          table: table,
          name: name
        }
      }
    }

    add_command(builder, command)
  end

  @doc """
  Add elements to a set.

  ## Examples

      builder |> Builder.add_elements("blocklist", ["192.168.1.100", "10.0.0.50"])
      builder |> Builder.add_elements("ports", [22, 80, 443])
  """
  @spec add_elements(t(), String.t(), list(term()), keyword()) :: t()
  def add_elements(%__MODULE__{} = builder, set_name, elements, opts \\ [])
      when is_binary(set_name) and is_list(elements) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    command = %{
      add: %{
        element: %{
          family: family,
          table: table,
          name: set_name,
          elem: elements
        }
      }
    }

    add_command(builder, command)
  end

  @doc """
  Delete elements from a set.

  ## Examples

      builder |> Builder.delete_elements("blocklist", ["192.168.1.100"])
  """
  @spec delete_elements(t(), String.t(), list(term()), keyword()) :: t()
  def delete_elements(%__MODULE__{} = builder, set_name, elements, opts \\ [])
      when is_binary(set_name) and is_list(elements) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    command = %{
      delete: %{
        element: %{
          family: family,
          table: table,
          name: set_name,
          elem: elements
        }
      }
    }

    add_command(builder, command)
  end

  ## Maps (Named Dictionaries)

  @doc """
  Add a map (key->value dictionary) to the current table.

  Maps allow mapping keys to values, useful for dynamic routing, NAT, etc.

  ## Parameters
  - `name` - Map name
  - `opts` - Options:
    - `:type` - Key and value types as tuple, e.g., `{:ipv4_addr, :verdict}`
    - `:table` - Table name (defaults to current_table)
    - `:family` - Address family (defaults to builder family)

  ## Examples

      builder
      |> Builder.set_table("filter")
      |> Builder.add_map("port_map", type: {:inet_service, :verdict})
  """
  @spec add_map(t(), String.t(), keyword()) :: t()
  def add_map(%__MODULE__{} = builder, name, opts) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    {key_type, value_type} = Keyword.fetch!(opts, :type)

    map_obj = %{
      family: family,
      table: table,
      name: name,
      type: key_type,
      map: to_string(value_type)
    }

    add_command(builder, %{add: %{map: map_obj}})
  end

  @doc """
  Delete a map from the current table.

  ## Examples

      builder |> Builder.delete_map("port_map")
  """
  @spec delete_map(t(), String.t(), keyword()) :: t()
  def delete_map(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    map_obj = %{
      family: family,
      table: table,
      name: name
    }

    add_command(builder, %{delete: %{map: map_obj}})
  end

  @doc """
  Add elements to a map.

  ## Parameters
  - `map_name` - Name of the map
  - `elements` - List of key-value pairs as 2-tuples

  ## Examples

      builder |> Builder.add_map_elements("port_map", [
        {80, "accept"},
        {443, "accept"},
        {8080, "drop"}
      ])
  """
  @spec add_map_elements(t(), String.t(), list({term(), term()}), keyword()) :: t()
  def add_map_elements(%__MODULE__{} = builder, map_name, elements, opts \\ [])
      when is_binary(map_name) and is_list(elements) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    # Format elements as nftables expects: [key, value]
    formatted_elements =
      Enum.map(elements, fn {key, value} ->
        [key, value]
      end)

    command = %{
      add: %{
        element: %{
          family: family,
          table: table,
          name: map_name,
          elem: formatted_elements
        }
      }
    }

    add_command(builder, command)
  end

  @doc """
  Delete elements from a map.

  ## Examples

      builder |> Builder.delete_map_elements("port_map", [80, 443])
  """
  @spec delete_map_elements(t(), String.t(), list(term()), keyword()) :: t()
  def delete_map_elements(%__MODULE__{} = builder, map_name, keys, opts \\ [])
      when is_binary(map_name) and is_list(keys) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    command = %{
      delete: %{
        element: %{
          family: family,
          table: table,
          name: map_name,
          elem: keys
        }
      }
    }

    add_command(builder, command)
  end

  ## Named Counters

  @doc """
  Add a named counter to the current table.

  Named counters can be referenced by multiple rules and queried separately.

  ## Parameters
  - `name` - Counter name
  - `opts` - Options:
    - `:packets` - Initial packet count (default: 0)
    - `:bytes` - Initial byte count (default: 0)
    - `:table` - Table name (defaults to current_table)
    - `:family` - Address family (defaults to builder family)

  ## Examples

      builder
      |> Builder.set_table("filter")
      |> Builder.add_counter("http_counter")
  """
  @spec add_counter(t(), String.t(), keyword()) :: t()
  def add_counter(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)
    packets = Keyword.get(opts, :packets, 0)
    bytes = Keyword.get(opts, :bytes, 0)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    counter_obj = %{
      family: family,
      table: table,
      name: name,
      packets: packets,
      bytes: bytes
    }

    add_command(builder, %{add: %{counter: counter_obj}})
  end

  @doc """
  Delete a named counter from the current table.

  ## Examples

      builder |> Builder.delete_counter("http_counter")
  """
  @spec delete_counter(t(), String.t(), keyword()) :: t()
  def delete_counter(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    counter_obj = %{
      family: family,
      table: table,
      name: name
    }

    add_command(builder, %{delete: %{counter: counter_obj}})
  end

  ## Quotas

  @doc """
  Add a quota to the current table.

  Quotas limit the amount of traffic (in bytes) that can pass through.

  ## Parameters
  - `name` - Quota name
  - `bytes` - Quota limit in bytes
  - `opts` - Options:
    - `:table` - Table name (defaults to current_table)
    - `:family` - Address family (defaults to builder family)
    - `:used` - Initial used bytes (default: 0)
    - `:over` - Whether quota is over (default: false)

  ## Examples

      builder
      |> Builder.set_table("filter")
      |> Builder.add_quota("monthly_limit", 1_000_000_000)  # 1 GB
  """
  @spec add_quota(t(), String.t(), non_neg_integer(), keyword()) :: t()
  def add_quota(%__MODULE__{} = builder, name, bytes, opts \\ [])
      when is_binary(name) and is_integer(bytes) and bytes >= 0 do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)
    used = Keyword.get(opts, :used, 0)
    over = Keyword.get(opts, :over, false)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    quota_obj = %{
      family: family,
      table: table,
      name: name,
      bytes: bytes,
      used: used,
      over: over
    }

    add_command(builder, %{add: %{quota: quota_obj}})
  end

  @doc """
  Delete a quota from the current table.

  ## Examples

      builder |> Builder.delete_quota("monthly_limit")
  """
  @spec delete_quota(t(), String.t(), keyword()) :: t()
  def delete_quota(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    quota_obj = %{
      family: family,
      table: table,
      name: name
    }

    add_command(builder, %{delete: %{quota: quota_obj}})
  end

  ## Named Limits

  @doc """
  Add a named limit to the current table.

  Named limits can be referenced by multiple rules for rate limiting.

  ## Parameters
  - `name` - Limit name
  - `rate` - Rate value
  - `unit` - Time unit (`:second`, `:minute`, `:hour`, `:day`)
  - `opts` - Options:
    - `:burst` - Burst value (default: 0)
    - `:table` - Table name (defaults to current_table)
    - `:family` - Address family (defaults to builder family)

  ## Examples

      builder
      |> Builder.set_table("filter")
      |> Builder.add_limit("ssh_limit", 10, :minute, burst: 5)
  """
  @spec add_limit(t(), String.t(), non_neg_integer(), atom(), keyword()) :: t()
  def add_limit(%__MODULE__{} = builder, name, rate, unit, opts \\ [])
      when is_binary(name) and is_integer(rate) and rate >= 0 and is_atom(unit) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)
    burst = Keyword.get(opts, :burst, 0)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    limit_obj = %{
      family: family,
      table: table,
      name: name,
      rate: rate,
      per: to_string(unit),
      burst: burst
    }

    add_command(builder, %{add: %{limit: limit_obj}})
  end

  @doc """
  Delete a named limit from the current table.

  ## Examples

      builder |> Builder.delete_limit("ssh_limit")
  """
  @spec delete_limit(t(), String.t(), keyword()) :: t()
  def delete_limit(%__MODULE__{} = builder, name, opts \\ []) when is_binary(name) do
    table = Keyword.get(opts, :table, builder.current_table)
    family = Keyword.get(opts, :family, builder.family)

    unless table do
      raise ArgumentError, "table must be specified"
    end

    limit_obj = %{
      family: family,
      table: table,
      name: name
    }

    add_command(builder, %{delete: %{limit: limit_obj}})
  end

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
    |> add_table(name)
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

    builder
    |> set_table(chain_map.table)
    |> add_chain(chain_map.name, opts)
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
    builder
    |> set_table(table)
    |> set_chain(chain)
    |> add_rule(expr)
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

    builder
    |> set_table(set_map.table)
    |> add_set(set_map.name, opts)
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
  - `pid` - NFTablesEx.Port process pid
  - `opts` - Options:
    - `:family` - Protocol family to import (default: `:inet`)
    - `:exclude_handles` - Exclude handle fields from import (default: `true`)

  ## Examples

      # Import existing ruleset
      {:ok, builder} = Builder.from_ruleset(pid, family: :inet)

      # Modify and reapply
      builder
      |> Builder.set_table("filter")
      |> Builder.set_chain("INPUT")
      |> Builder.add_rule(
        Rule.new()
        |> Rule.source("10.0.0.0/8")
        |> Rule.drop()
        |> Rule.to_expr()
      )
      |> Builder.execute(pid)

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

    with {:ok, tables} <- NFTablesEx.Query.list_tables(pid, family: family),
         {:ok, chains} <- NFTablesEx.Query.list_chains(pid, family: family),
         {:ok, rules} <- NFTablesEx.Query.list_rules(pid, family: family),
         {:ok, sets} <- NFTablesEx.Query.list_sets(pid, family: family) do

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

  ## Execution

  @doc """
  Execute the accumulated commands.

  Converts the builder commands to nftables JSON format and executes them
  via the Executor module.

  ## Parameters

  - `builder` - The builder with accumulated commands
  - `pid` - NFTablesEx.Port process pid

  ## Examples

      {:ok, pid} = NFTablesEx.start_link()
      Builder.new()
      |> Builder.add_table("filter")
      |> Builder.execute(pid)
  """
  @spec execute(t(), pid()) :: :ok | {:error, term()}
  def execute(%__MODULE__{commands: commands}, pid) when is_pid(pid) do
    # Wrap commands in nftables JSON envelope
    nftables_json = %{
      nftables: commands
    }

    # Encode to JSON using Elixir's JSON module (returns binary)
    json_string = JSON.encode!(nftables_json)

    # Execute via Executor
    case NFTablesEx.Executor.execute(json_string, pid: pid) do
      {:ok, _response} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Convert builder to JSON string for inspection.

  ## Examples

      builder |> Builder.to_json()
      #=> "{\"nftables\":[{\"add\":{\"table\":{...}}}]}"
  """
  @spec to_json(t()) :: String.t()
  def to_json(%__MODULE__{commands: commands}) do
    nftables_json = %{
      nftables: commands
    }

    JSON.encode!(nftables_json)
  end

  ## Private Helpers

  # Add a command to the builder
  defp add_command(%__MODULE__{commands: commands} = builder, command) do
    %{builder | commands: commands ++ [command]}
  end

  # Conditionally add key to map if value is not nil
  defp maybe_add(map, _key, nil), do: map
  defp maybe_add(map, key, value), do: Map.put(map, key, value)
end
