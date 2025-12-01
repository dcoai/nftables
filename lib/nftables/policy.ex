defmodule NFTables.Policy do
  @moduledoc """
  Pre-built firewall policies and common rule patterns.

  This module provides high-level functions for common firewall configurations,
  making it easy to set up secure defaults without low-level rule management.

  ## Quick Start

      {:ok, pid} = NFTables.start_link()

      # Create table and chain
      Builder.new()
      |> Builder.add(table: "filter", family: :inet)
      |> Builder.add(
        table: "filter",
        chain: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      )
      |> Builder.submit(pid: pid)

      # Apply common policies
      :ok = NFTables.Policy.accept_loopback(pid)
      :ok = NFTables.Policy.accept_established(pid)
      :ok = NFTables.Policy.allow_ssh(pid)

  ## See Also

  - `NFTables.Match` - Fluent API for custom rules
  - `NFTables.Builder` - Configuration builder
  - `NFTables.Local` - Local execution requestor
  """

  import NFTables.Match
  alias NFTables.Builder

  @doc """
  Accept all loopback traffic.

  Loopback traffic (lo interface) should always be accepted as it's internal
  system communication.

  ## Example

      :ok = NFTables.Policy.accept_loopback(pid)
      :ok = NFTables.Policy.accept_loopback(pid, table: "filter", chain: "INPUT")
  """
  @spec accept_loopback(pid(), keyword()) :: :ok | {:error, term()}
  def accept_loopback(pid, opts \\ []) do
    build_accept_loopback(opts)
    |> execute_rule(pid)
  end

  @doc """
  Build a loopback acceptance rule without executing it.

  Returns a Builder that can be further modified or executed later.
  Useful for testing and composing multiple rules.

  ## Example

      builder = NFTables.Policy.build_accept_loopback()
      json = Builder.to_json(builder)
  """
  @spec build_accept_loopback(keyword()) :: Builder.t()
  def build_accept_loopback(opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)

    expr_list =
      rule(family: family)
      |> iif("lo")
      |> accept()
     

    Builder.new()
    |> Builder.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Accept established and related connections.

  This allows return traffic for existing connections, essential for any
  stateful firewall.

  ## Example

      :ok = NFTables.Policy.accept_established(pid)
  """
  @spec accept_established(pid(), keyword()) :: :ok | {:error, term()}
  def accept_established(pid, opts \\ []) do
    build_accept_established(opts)
    |> execute_rule(pid)
  end

  @doc """
  Build an established/related connection acceptance rule without executing it.
  """
  @spec build_accept_established(keyword()) :: Builder.t()
  def build_accept_established(opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)

    expr_list =
      rule(family: family)
      |> state([:established, :related])
      |> accept()
     

    Builder.new()
    |> Builder.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Allow SSH connections (port 22).

  ## Options

  - `:rate_limit` - Limit connections per minute (default: no limit)
  - `:log` - Log accepted connections (default: false)
  - `:table` - Table name (default: "filter")
  - `:chain` - Chain name (default: "INPUT")
  - `:family` - Protocol family (default: :inet)

  ## Examples

      # Basic SSH allow
      :ok = NFTables.Policy.allow_ssh(pid)

      # With rate limiting
      :ok = NFTables.Policy.allow_ssh(pid, rate_limit: 10)

      # With logging
      :ok = NFTables.Policy.allow_ssh(pid, log: true)
  """
  @spec allow_ssh(pid(), keyword()) :: :ok | {:error, term()}
  def allow_ssh(pid, opts \\ []) do
    build_allow_ssh(opts)
    |> execute_rule(pid)
  end

  @doc """
  Build an SSH allow rule without executing it.
  """
  @spec build_allow_ssh(keyword()) :: Builder.t()
  def build_allow_ssh(opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)
    rate_limit_val = Keyword.get(opts, :rate_limit)
    log_enabled = Keyword.get(opts, :log, false)

    builder =
      rule(family: family)
      |> tcp()
      |> dport(22)

    builder = if rate_limit_val do
      limit(builder, rate_limit_val, :minute)
    else
      builder
    end

    builder = if log_enabled do
      log(builder, "SSH: ")
    else
      builder
    end

    expr_list =
      builder
      |> accept()
     

    Builder.new()
    |> Builder.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Allow HTTP connections (port 80).

  ## Options

  - `:rate_limit` - Limit connections per minute
  - `:log` - Log accepted connections
  - `:table` - Table name (default: "filter")
  - `:chain` - Chain name (default: "INPUT")
  - `:family` - Protocol family (default: :inet)

  ## Example

      :ok = NFTables.Policy.allow_http(pid)
      :ok = NFTables.Policy.allow_http(pid, rate_limit: 100)
  """
  @spec allow_http(pid(), keyword()) :: :ok | {:error, term()}
  def allow_http(pid, opts \\ []) do
    allow_port(pid, 80, Keyword.put(opts, :service, "HTTP"))
  end

  @doc """
  Build an HTTP allow rule without executing it.
  """
  @spec build_allow_http(keyword()) :: Builder.t()
  def build_allow_http(opts \\ []) do
    build_allow_port(80, Keyword.put(opts, :service, "HTTP"))
  end

  @doc """
  Allow HTTPS connections (port 443).

  ## Example

      :ok = NFTables.Policy.allow_https(pid)
  """
  @spec allow_https(pid(), keyword()) :: :ok | {:error, term()}
  def allow_https(pid, opts \\ []) do
    allow_port(pid, 443, Keyword.put(opts, :service, "HTTPS"))
  end

  @doc """
  Build an HTTPS allow rule without executing it.
  """
  @spec build_allow_https(keyword()) :: Builder.t()
  def build_allow_https(opts \\ []) do
    build_allow_port(443, Keyword.put(opts, :service, "HTTPS"))
  end

  @doc """
  Allow DNS queries (port 53, UDP).

  ## Example

      :ok = NFTables.Policy.allow_dns(pid)
  """
  @spec allow_dns(pid(), keyword()) :: :ok | {:error, term()}
  def allow_dns(pid, opts \\ []) do
    allow_port(pid, 53, Keyword.put(opts, :service, "DNS"))
  end

  @doc """
  Build a DNS allow rule without executing it.
  """
  @spec build_allow_dns(keyword()) :: Builder.t()
  def build_allow_dns(opts \\ []) do
    build_allow_port(53, Keyword.put(opts, :service, "DNS"))
  end

  @doc """
  Drop invalid packets.

  Drops packets with invalid connection tracking state.

  ## Example

      :ok = NFTables.Policy.drop_invalid(pid)
  """
  @spec drop_invalid(pid(), keyword()) :: :ok | {:error, term()}
  def drop_invalid(pid, opts \\ []) do
    build_drop_invalid(opts)
    |> execute_rule(pid)
  end

  @doc """
  Build a drop invalid packets rule without executing it.
  """
  @spec build_drop_invalid(keyword()) :: Builder.t()
  def build_drop_invalid(opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)

    expr_list =
      rule(family: family)
      |> ct_state([:invalid])
    |> drop()
   

    Builder.new()
    |> Builder.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Setup stateful firewall rules.

  Combines `accept_established/2` and `drop_invalid/2` to set up basic
  connection tracking rules. This is essential for any stateful firewall,
  allowing return traffic for established connections while dropping
  packets with invalid connection tracking state.

  ## Options

  - `:table` - Table name (default: "filter")
  - `:chain` - Chain name (default: "INPUT")
  - `:family` - Protocol family (default: :inet)

  ## Example

      :ok = NFTables.Policy.stateful(pid)
      :ok = NFTables.Policy.stateful(pid, table: "filter", chain: "INPUT")
  """
  @spec stateful(pid(), keyword()) :: :ok | {:error, term()}
  def stateful(pid, opts \\ []) do
    with :ok <- accept_established(pid, opts),
         :ok <- drop_invalid(pid, opts) do
      :ok
    end
  end

  @doc """
  Accept all traffic.

  Creates a rule that accepts all packets without any matching criteria.
  Useful as a catch-all rule or for testing purposes.

  **Warning**: This creates a permissive rule. Use with caution in production.

  ## Options

  - `:table` - Table name (default: "filter")
  - `:chain` - Chain name (default: "INPUT")
  - `:family` - Protocol family (default: :inet)
  - `:log` - Log accepted packets (default: false)

  ## Example

      :ok = NFTables.Policy.allow_any(pid)
      :ok = NFTables.Policy.allow_any(pid, log: true)
  """
  @spec allow_any(pid(), keyword()) :: :ok | {:error, term()}
  def allow_any(pid, opts \\ []) do
    build_allow_any(opts)
    |> execute_rule(pid)
  end

  @doc """
  Build an allow any traffic rule without executing it.
  """
  @spec build_allow_any(keyword()) :: Builder.t()
  def build_allow_any(opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)
    log_enabled = Keyword.get(opts, :log, false)

    builder = rule(family: family)

    builder = if log_enabled do
      log(builder, "ALLOW ANY: ")
    else
      builder
    end

    expr_list =
      builder
      |> accept()
     

    Builder.new()
    |> Builder.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Drop all traffic.

  Creates a rule that drops all packets without any matching criteria.
  Useful as a catch-all deny rule at the end of a chain or for testing.

  ## Options

  - `:table` - Table name (default: "filter")
  - `:chain` - Chain name (default: "INPUT")
  - `:family` - Protocol family (default: :inet)
  - `:log` - Log dropped packets (default: false)

  ## Example

      :ok = NFTables.Policy.deny_all(pid)
      :ok = NFTables.Policy.deny_all(pid, log: true)
  """
  @spec deny_all(pid(), keyword()) :: :ok | {:error, term()}
  def deny_all(pid, opts \\ []) do
    build_deny_all(opts)
    |> execute_rule(pid)
  end

  @doc """
  Build a deny all traffic rule without executing it.
  """
  @spec build_deny_all(keyword()) :: Builder.t()
  def build_deny_all(opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)
    log_enabled = Keyword.get(opts, :log, false)

    builder = rule(family: family)

    builder = if log_enabled do
      log(builder, "DENY ALL: ")
    else
      builder
    end

    expr_list =
      builder
      |> drop()
     

    Builder.new()
    |> Builder.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Setup basic firewall with common defaults.

  Creates a table and INPUT chain with these rules:
  1. Accept loopback
  2. Accept established/related
  3. Drop invalid packets
  4. Allow SSH (with optional rate limiting)
  5. Default policy: DROP (only in production mode)

  ## Options

  - `:table` - Table name (default: "filter")
  - `:family` - Protocol family (default: :inet)
  - `:ssh_rate_limit` - SSH connections per minute (default: 10)
  - `:allow_services` - List of services to allow (default: [:ssh])
  - `:test_mode` - If true, creates chains WITHOUT hooks (safe for testing) (default: false)

  ## Test Mode

  **IMPORTANT**: When `test_mode: true`, chains are created WITHOUT netfilter hooks.
  This prevents the chains from filtering actual network traffic, making tests safe.

  In test mode, the table name is automatically prefixed with "nftex_test_" if not already prefixed.

  ## Examples

      # Production use (creates hooked chains that filter traffic)
      :ok = NFTables.Policy.setup_basic_firewall(pid)
      :ok = NFTables.Policy.setup_basic_firewall(pid, allow_services: [:ssh, :http, :https])

      # Test use (creates regular chains without hooks - SAFE)
      :ok = NFTables.Policy.setup_basic_firewall(pid, test_mode: true, table: "my_test")
  """
  @spec setup_basic_firewall(pid(), keyword()) :: :ok | {:error, term()}
  def setup_basic_firewall(pid, opts \\ []) do
    test_mode = Keyword.get(opts, :test_mode, false)
    base_table = Keyword.get(opts, :table, "filter")
    family = Keyword.get(opts, :family, :inet)
    ssh_rate_limit = Keyword.get(opts, :ssh_rate_limit, 10)
    services = Keyword.get(opts, :allow_services, [:ssh])

    # In test mode, ensure table has nftables_test_ prefix and create chains without hooks
    table = if test_mode, do: ensure_test_prefix(base_table), else: base_table

    # Build chain attributes as keyword list (Builder expects chain: not name:)
    chain_attrs = if test_mode do
      # Test mode: Create regular chain WITHOUT hook (safe - won't filter traffic)
      [
        table: table,
        chain: "INPUT",
        family: family
      ]
    else
      # Production mode: Create base chain WITH hook (filters traffic)
      [
        table: table,
        chain: "INPUT",
        family: family,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      ]
    end

    # Create table first
    table_result = Builder.new()
    |> Builder.add(table: table, family: family)
    |> execute_rule(pid)

    # Then create chain separately
    result = case table_result do
      :ok ->
        Builder.new(family: family)
        |> Builder.add(table: table)
        |> Builder.add(chain_attrs)
        |> execute_rule(pid)
      error -> error
    end

    case result do
      :ok ->
        with :ok <- accept_loopback(pid, table: table, family: family),
             :ok <- accept_established(pid, table: table, family: family),
             :ok <- drop_invalid(pid, table: table, family: family),
             :ok <- apply_services(pid, services, table: table, family: family, ssh_rate_limit: ssh_rate_limit) do
          :ok
        end
      error -> error
    end
  end

  # Private helpers

  # Execute a Builder and normalize response to :ok for consistent API
  defp execute_rule(builder, pid) do
    case Builder.submit(builder, pid: pid) do
      :ok -> :ok
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp ensure_test_prefix(table_name) do
    if String.starts_with?(table_name, "nftables_test_") do
      table_name
    else
      "nftables_test_#{table_name}"
    end
  end

  defp allow_port(pid, port, opts) do
    build_allow_port(port, opts)
    |> execute_rule(pid)
  end

  defp build_allow_port(port, opts) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)
    rate_limit_val = Keyword.get(opts, :rate_limit)
    log_enabled = Keyword.get(opts, :log, false)
    service = Keyword.get(opts, :service, "PORT #{port}")

    builder =
      rule(family: family)
      |> tcp()
      |> dport(port)

    builder = if rate_limit_val do
      limit(builder, rate_limit_val, :minute)
    else
      builder
    end

    builder = if log_enabled do
      log(builder, "#{service}: ")
    else
      builder
    end

    expr_list =
      builder
      |> accept()
     

    Builder.new()
    |> Builder.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  defp apply_services(pid, services, opts) do
    Enum.reduce_while(services, :ok, fn service, :ok ->
      result = case service do
        :ssh -> allow_ssh(pid, opts)
        :http -> allow_http(pid, opts)
        :https -> allow_https(pid, opts)
        :dns -> allow_dns(pid, opts)
        _ -> {:error, "Unknown service: #{service}"}
      end

      case result do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end
end
