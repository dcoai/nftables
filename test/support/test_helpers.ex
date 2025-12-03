defmodule NFTables.TestHelpers do
  @moduledoc """
  Test helpers for creating isolated nftables test infrastructure.

  IMPORTANT: All tests MUST use isolated test tables to prevent disrupting
  the host's network connectivity. This module provides utilities for creating
  safe test environments.

  ## Why Isolation is Critical

  Production tables like `filter`, `nat`, `raw`, `mangle`, and `security` are
  actively filtering network traffic on the host. Modifying these tables during
  tests can:

  - Block SSH connections
  - Drop all incoming/outgoing traffic
  - Disrupt NAT/routing
  - Make the host unreachable
  - Require system restart to recover

  ## CRITICAL: Hooks Are GLOBAL

  **WARNING**: Even with isolated test table names, netfilter hooks are GLOBAL.

  A chain with `hook: :input` in table "nftables_test_filter" has the SAME effect
  as a chain with `hook: :input` in the production "filter" table. Both attach
  to the kernel's global netfilter infrastructure and filter ALL traffic.

  **Table names are just namespaces** - they do NOT provide network isolation.

  ## Safe Testing Approach

  1. **ALWAYS use the "nftables_test_" prefix** for all test table names
  2. **NEVER create chains with hooks in tests** (always use `hook: nil` or omit it)
  3. Create regular chains WITHOUT hooks for testing chain logic
  4. Use `test_mode: true` when calling Policy functions
  5. Always clean up test tables in on_exit callbacks
  6. NEVER modify production tables ("filter", "nat", etc.) in tests

  ## Usage

      setup do
        {:ok, pid} = NFTables.Port.start_link()

        # Create isolated test infrastructure WITHOUT hooks (safe)
        {:ok, table, chain} = NFTables.TestHelpers.setup_test_table_and_chain(
          pid,
          "my_test",
          family: :inet,
          hook: nil  # CRITICAL: No hook = safe, won't filter traffic
        )

        on_exit(fn ->
          NFTables.TestHelpers.cleanup_test_table(pid, table, :inet)
        end)

        {:ok, pid: pid, table: table, chain: chain}
      end

  ## Emergency Cleanup

  If tests fail and leave hooked chains active, clean up with:

      sudo nft list ruleset | grep "table inet nftex_test" | awk '{print $3}' | xargs -I {} sudo nft delete table inet {}

  Or use the cleanup script:

      test/support/cleanup_test_tables.sh
  """

  alias NFTables.Builder

  @doc """
  Creates an isolated test table with a safe name.

  Table names are prefixed with "nftables_test_" to clearly identify them as test tables.

  ## Options

    * `:family` - Address family (default: `:inet`)

  ## Examples

      {:ok, table_name} = setup_test_table(pid, "integration", family: :inet)
      # Creates table: "nftables_test_integration"
  """
  def setup_test_table(pid, test_name, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)
    table_name = "nftables_test_#{test_name}"

    # Clean up if exists from previous failed test
    Builder.new()
    |> Builder.delete(table: table_name, family: family)
    |> Builder.submit(pid: pid)

    Builder.new()
    |> Builder.add(table: table_name, family: family)
    |> Builder.submit(pid: pid)
    |> case do
      :ok -> {:ok, table_name}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Creates an isolated test table and chain.

  The chain can be created with or without a hook:

  - **Without hook** (`:hook` is `nil`): Creates a regular chain that doesn't
    filter traffic. This is SAFE and should be used for ALL tests.
  - **With hook** (`:hook` is `:input`, `:output`, etc.): Creates a base chain
    that WILL filter REAL network traffic on the host. **DO NOT USE IN TESTS**.

  ## CRITICAL WARNING ABOUT HOOKS

  **Netfilter hooks are GLOBAL to the kernel**, regardless of table name.

  Even though this function creates an isolated test table with "nftables_test_"
  prefix, a chain with a hook (e.g., `:input`) will attach to the kernel's
  global netfilter infrastructure and filter ALL incoming packets on the host.

  **This can block SSH, drop traffic, and make the host unreachable.**

  **DO NOT pass a hook parameter in tests unless you understand the risk.**

  ## Options

    * `:family` - Address family (default: `:inet`)
    * `:hook` - Hook point (default: `nil` for safety) **DO NOT USE IN TESTS**
    * `:type` - Chain type (default: `:filter`, only used with hook)
    * `:priority` - Chain priority (default: `0`, only used with hook)
    * `:policy` - Chain policy (default: `:accept`, only used with hook)

  ## Examples

      # Safe: Regular chain without hook (won't filter traffic) - USE THIS
      {:ok, table, chain} = setup_test_table_and_chain(pid, "my_test")

      # DANGEROUS: With hook - filters real traffic - DO NOT USE IN TESTS
      {:ok, table, chain} = setup_test_table_and_chain(
        pid,
        "my_test",
        hook: :input,  # ← DANGER: This will filter real network traffic!
        policy: :accept
      )
  """
  def setup_test_table_and_chain(pid, test_name, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)
    hook = Keyword.get(opts, :hook, nil)
    type = Keyword.get(opts, :type, :filter)
    priority = Keyword.get(opts, :priority, 0)
    policy = Keyword.get(opts, :policy, :accept)

    with {:ok, table_name} <- setup_test_table(pid, test_name, family: family),
         {:ok, chain_name} <- create_test_chain(pid, table_name, test_name, hook, type, priority, policy, family) do
      {:ok, table_name, chain_name}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Creates a test chain in the specified table.

  If `hook` is `nil`, creates a regular chain (safe).
  If `hook` is specified, creates a base chain with that hook.
  """
  def create_test_chain(pid, table_name, test_name, hook, type, priority, policy, family) do
    chain_name = "test_#{test_name}_chain"

    # Build base chain attributes as keyword list
    chain_attrs = [
      chain: chain_name,
      table: table_name,
      family: family
    ]

    # Add hook attributes only if hook is specified
    chain_attrs =
      if hook do
        chain_attrs ++
          [
            type: type,
            hook: hook,
            priority: priority,
            policy: policy
          ]
      else
        chain_attrs
      end

    Builder.new()
    |> Builder.add(chain_attrs)
    |> Builder.submit(pid: pid)
    |> case do
      :ok -> {:ok, chain_name}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Cleans up a test table and all its chains.

  Always call this in your test's `on_exit` callback.

  ## Examples

      on_exit(fn ->
        if Process.alive?(pid) do
          cleanup_test_table(pid, table_name, :inet)
        end
      end)
  """
  def cleanup_test_table(pid, table_name, family \\ :inet) do
    Builder.new()
    |> Builder.delete(table: table_name, family: family)
    |> Builder.submit(pid: pid)
  end

  @doc """
  Verifies that a table name is safe for testing.

  Returns `true` if the table is a test table or doesn't exist.
  Returns `false` if it's a production table (filter, nat, etc.).

  ## Examples

      iex> safe_table_name?("nftables_test_integration")
      true

      iex> safe_table_name?("filter")
      false
  """
  def safe_table_name?(table_name) do
    production_tables = ["filter", "nat", "raw", "mangle", "security"]
    not (table_name in production_tables)
  end

  @doc """
  Asserts that a table name is safe for testing.

  Raises if the table is a production table.
  """
  def assert_safe_table!(table_name) do
    unless safe_table_name?(table_name) do
      raise """
      UNSAFE TABLE NAME: #{table_name}

      Tests must NOT modify production tables: filter, nat, raw, mangle, security

      These tables are actively filtering network traffic and modifying them
      during tests can disconnect the host from the network.

      Use NFTables.TestHelpers.setup_test_table/2 to create isolated test tables.
      """
    end
  end

  @doc """
  Ensures a table name has the "nftables_test_" prefix.

  This helps with identifying and cleaning up test tables.

  ## Examples

      iex> ensure_test_prefix("my_table")
      "nftables_test_my_table"

      iex> ensure_test_prefix("nftables_test_already")
      "nftables_test_already"
  """
  def ensure_test_prefix(table_name) do
    if String.starts_with?(table_name, "nftables_test_") do
      table_name
    else
      "nftables_test_#{table_name}"
    end
  end
end
