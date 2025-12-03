defmodule NFTables.Policy do
  @moduledoc """
  Pre-built firewall policies and common rule patterns.

  This module provides high-level functions for common firewall configurations,
  making it easy to set up secure defaults without low-level rule management.

  All functions follow a builder-first pattern, taking a Builder as the first
  parameter and returning a modified Builder. This allows composing multiple
  policy rules before submitting them in a single transaction.

  ## Quick Start

      {:ok, pid} = NFTables.start_link()

      # Create table and chain
      Builder.new()
      |> NFTables.add(table: "filter", family: :inet)
      |> NFTables.add(
        table: "filter",
        chain: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      )
      |> NFTables.submit(pid: pid)

      # Apply common policies
      Builder.new()
      |> NFTables.Policy.accept_loopback()
      |> NFTables.Policy.accept_established()
      |> NFTables.Policy.allow_ssh()
      |> NFTables.submit(pid: pid)

  ## See Also

  - `NFTables.Expr` - Fluent API for custom rules
  - `NFTables.Builder` - Configuration builder
  - `NFTables.Local` - Local execution requestor
  """

  import NFTables.Expr
  alias NFTables.Builder

  @doc """
  Accept all loopback traffic.

  Loopback traffic (lo interface) should always be accepted as it's internal
  system communication.

  ## Examples

      # Single rule
      Builder.new()
      |> NFTables.Policy.accept_loopback()
      |> NFTables.submit(pid: pid)

      # Compose with other policies
      Builder.new()
      |> NFTables.Policy.accept_loopback(table: "filter")
      |> NFTables.Policy.accept_established(table: "filter")
      |> NFTables.submit(pid: pid)
  """
  @spec accept_loopback(Builder.t(), keyword()) :: Builder.t()
  def accept_loopback(builder \\ Builder.new(), opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)

    expr_list =
      expr(family: family)
      |> iif("lo")
      |> accept()

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Accept established and related connections.

  This allows return traffic for existing connections, essential for any
  stateful firewall.

  ## Examples

      Builder.new()
      |> NFTables.Policy.accept_established()
      |> NFTables.submit(pid: pid)

      # With custom table
      Builder.new()
      |> NFTables.Policy.accept_established(table: "myfilter")
      |> NFTables.submit(pid: pid)
  """
  @spec accept_established(Builder.t(), keyword()) :: Builder.t()
  def accept_established(builder \\ Builder.new(), opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)

    expr_list =
      expr(family: family)
      |> state([:established, :related])
      |> accept()

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
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
      Builder.new()
      |> NFTables.Policy.allow_ssh()
      |> NFTables.submit(pid: pid)

      # With rate limiting
      Builder.new()
      |> NFTables.Policy.allow_ssh(rate_limit: 10)
      |> NFTables.submit(pid: pid)

      # With logging
      Builder.new()
      |> NFTables.Policy.allow_ssh(log: true)
      |> NFTables.submit(pid: pid)

      # Compose multiple services
      Builder.new()
      |> NFTables.Policy.allow_ssh(rate_limit: 10)
      |> NFTables.Policy.allow_http()
      |> NFTables.Policy.allow_https()
      |> NFTables.submit(pid: pid)
  """
  @spec allow_ssh(Builder.t(), keyword()) :: Builder.t()
  def allow_ssh(builder \\ Builder.new(), opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)
    rate_limit_val = Keyword.get(opts, :rate_limit)
    log_enabled = Keyword.get(opts, :log, false)

    expr_builder =
      expr(family: family)
      |> tcp()
      |> dport(22)

    expr_builder = if rate_limit_val do
      limit(expr_builder, rate_limit_val, :minute)
    else
      expr_builder
    end

    expr_builder = if log_enabled do
      log(expr_builder, "SSH: ")
    else
      expr_builder
    end

    expr_list =
      expr_builder
      |> accept()

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Allow HTTP connections (port 80).

  ## Options

  - `:rate_limit` - Limit connections per minute
  - `:log` - Log accepted connections
  - `:table` - Table name (default: "filter")
  - `:chain` - Chain name (default: "INPUT")
  - `:family` - Protocol family (default: :inet)

  ## Examples

      Builder.new()
      |> NFTables.Policy.allow_http()
      |> NFTables.submit(pid: pid)

      # With rate limiting
      Builder.new()
      |> NFTables.Policy.allow_http(rate_limit: 100)
      |> NFTables.submit(pid: pid)
  """
  @spec allow_http(Builder.t(), keyword()) :: Builder.t()
  def allow_http(builder \\ Builder.new(), opts \\ []) do
    allow_port(builder, 80, Keyword.put(opts, :service, "HTTP"))
  end

  @doc """
  Allow HTTPS connections (port 443).

  ## Examples

      Builder.new()
      |> NFTables.Policy.allow_https()
      |> NFTables.submit(pid: pid)

      # Compose HTTP and HTTPS
      Builder.new()
      |> NFTables.Policy.allow_http()
      |> NFTables.Policy.allow_https()
      |> NFTables.submit(pid: pid)
  """
  @spec allow_https(Builder.t(), keyword()) :: Builder.t()
  def allow_https(builder \\ Builder.new(), opts \\ []) do
    allow_port(builder, 443, Keyword.put(opts, :service, "HTTPS"))
  end

  @doc """
  Allow DNS queries (port 53, UDP).

  ## Examples

      Builder.new()
      |> NFTables.Policy.allow_dns()
      |> NFTables.submit(pid: pid)
  """
  @spec allow_dns(Builder.t(), keyword()) :: Builder.t()
  def allow_dns(builder \\ Builder.new(), opts \\ []) do
    allow_port(builder, 53, Keyword.put(opts, :service, "DNS"))
  end

  @doc """
  Drop invalid packets.

  Drops packets with invalid connection tracking state.

  ## Examples

      Builder.new()
      |> NFTables.Policy.drop_invalid()
      |> NFTables.submit(pid: pid)
  """
  @spec drop_invalid(Builder.t(), keyword()) :: Builder.t()
  def drop_invalid(builder \\ Builder.new(), opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)

    expr_list =
      expr(family: family)
      |> ct_state([:invalid])
      |> drop()

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
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

  ## Examples

      Builder.new()
      |> NFTables.Policy.stateful()
      |> NFTables.submit(pid: pid)

      # With custom options
      Builder.new()
      |> NFTables.Policy.stateful(table: "filter", chain: "INPUT")
      |> NFTables.submit(pid: pid)
  """
  @spec stateful(Builder.t(), keyword()) :: Builder.t()
  def stateful(builder \\ Builder.new(), opts \\ []) do
    builder
    |> accept_established(opts)
    |> drop_invalid(opts)
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

  ## Examples

      Builder.new()
      |> NFTables.Policy.allow_any()
      |> NFTables.submit(pid: pid)

      # With logging
      Builder.new()
      |> NFTables.Policy.allow_any(log: true)
      |> NFTables.submit(pid: pid)
  """
  @spec allow_any(Builder.t(), keyword()) :: Builder.t()
  def allow_any(builder \\ Builder.new(), opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)
    log_enabled = Keyword.get(opts, :log, false)

    expr_builder = expr(family: family)

    expr_builder = if log_enabled do
      log(expr_builder, "ALLOW ANY: ")
    else
      expr_builder
    end

    expr_list =
      expr_builder
      |> accept()

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
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

  ## Examples

      Builder.new()
      |> NFTables.Policy.deny_all()
      |> NFTables.submit(pid: pid)

      # With logging
      Builder.new()
      |> NFTables.Policy.deny_all(log: true)
      |> NFTables.submit(pid: pid)
  """
  @spec deny_all(Builder.t(), keyword()) :: Builder.t()
  def deny_all(builder \\ Builder.new(), opts \\ []) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)
    log_enabled = Keyword.get(opts, :log, false)

    expr_builder = expr(family: family)

    expr_builder = if log_enabled do
      log(expr_builder, "DENY ALL: ")
    else
      expr_builder
    end

    expr_list =
      expr_builder
      |> drop()

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Setup basic firewall with common defaults.

  Creates a table and INPUT chain with these rules:
  1. Accept loopback
  2. Accept established/related
  3. Drop invalid packets
  4. Allow specified services (default: SSH with rate limiting)
  5. Default policy: DROP (only in production mode)

  This is a convenience function that still takes a `pid` and executes
  immediately, as it needs to create infrastructure (table and chain) before
  applying policies. The policy rules themselves are composed using the
  builder pattern internally.

  ## Options

  - `:table` - Table name (default: "filter")
  - `:family` - Protocol family (default: :inet)
  - `:ssh_rate_limit` - SSH connections per minute (default: 10)
  - `:allow_services` - List of services to allow (default: [:ssh])
  - `:test_mode` - If true, creates chains WITHOUT hooks (safe for testing) (default: false)

  ## Test Mode

  **IMPORTANT**: When `test_mode: true`, chains are created WITHOUT netfilter hooks.
  This prevents the chains from filtering actual network traffic, making tests safe.

  In test mode, the table name is automatically prefixed with "nftables_test_" if not already prefixed.

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
    |> NFTables.add(table: table, family: family)
    |> execute_rule(pid)

    # Then create chain separately
    result = case table_result do
      :ok ->
        Builder.new(family: family)
        |> NFTables.add(table: table)
        |> NFTables.add(chain_attrs)
        |> execute_rule(pid)
      error -> error
    end

    # Now apply policy rules using builder composition
    case result do
      :ok ->
        policy_opts = [table: table, family: family]
        service_opts = Keyword.put(policy_opts, :ssh_rate_limit, ssh_rate_limit)

        Builder.new()
        |> accept_loopback(policy_opts)
        |> accept_established(policy_opts)
        |> drop_invalid(policy_opts)
        |> apply_service_rules(services, service_opts)
        |> execute_rule(pid)
      error -> error
    end
  end

  # Private helpers

  # Execute a Builder and normalize response to :ok for consistent API
  defp execute_rule(builder, pid) do
    case NFTables.submit(builder, pid: pid) do
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

  defp allow_port(builder, port, opts) do
    table = Keyword.get(opts, :table, "filter")
    chain = Keyword.get(opts, :chain, "INPUT")
    family = Keyword.get(opts, :family, :inet)
    rate_limit_val = Keyword.get(opts, :rate_limit)
    log_enabled = Keyword.get(opts, :log, false)
    service = Keyword.get(opts, :service, "PORT #{port}")

    expr_builder =
      expr(family: family)
      |> tcp()
      |> dport(port)

    expr_builder = if rate_limit_val do
      limit(expr_builder, rate_limit_val, :minute)
    else
      expr_builder
    end

    expr_builder = if log_enabled do
      log(expr_builder, "#{service}: ")
    else
      expr_builder
    end

    expr_list =
      expr_builder
      |> accept()

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  defp apply_service_rules(builder, services, opts) do
    Enum.reduce(services, builder, fn service, acc ->
      case service do
        :ssh -> allow_ssh(acc, opts)
        :http -> allow_http(acc, opts)
        :https -> allow_https(acc, opts)
        :dns -> allow_dns(acc, opts)
        _ -> acc  # Ignore unknown services
      end
    end)
  end
end
