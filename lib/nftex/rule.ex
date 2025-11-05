defmodule NFTex.Rule do
  @moduledoc """
  High-level rule operations for creating and managing nftables firewall rules.

  This module provides simple, idiomatic Elixir functions for common firewall operations
  such as blocking or allowing IP addresses. Rules are created with proper expressions
  (payload, comparison, counter, verdict) and automatically sent to the kernel.

  ## Quick Example

      {:ok, pid} = NFTex.start_link()

      # Block a malicious IP address
      ip = <<192, 168, 1, 100>>
      :ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", ip)

      # Allow a trusted IP address
      trusted_ip = <<192, 168, 1, 50>>
      :ok = NFTex.Rule.accept_ip(pid, "filter", "INPUT", trusted_ip)

      # List all rules in a chain
      {:ok, rules} = NFTex.Rule.list(pid, "filter", "INPUT", family: :inet)
      IO.inspect(length(rules))  # Number of rules

  ## IP Address Format

  IP addresses must be provided as binaries (4 bytes for IPv4, 16 bytes for IPv6):

      # IPv4: 192.168.1.100
      ip = <<192, 168, 1, 100>>

      # IPv6: 2001:db8::1
      ip6 = <<0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>

  ## How It Works

  When you call `block_ip/4` or `accept_ip/4`, NFTex automatically:

  1. **Allocates a rule** in native memory
  2. **Adds payload expression** to load the source IP address into a register
  3. **Adds comparison expression** to match the specified IP
  4. **Adds counter expression** (optional, enabled by default) to track packets/bytes
  5. **Adds verdict expression** (DROP for block, ACCEPT for allow)
  6. **Sends to kernel** via netlink
  7. **Cleans up** native resources

  ## Options

  Both `block_ip/5` and `accept_ip/5` accept these options:

  - `:family` - Protocol family (default: `:inet`)
    - `:inet` or `:ip` - IPv4
    - `:inet6` or `:ip6` - IPv6
    - `:arp`, `:bridge`, `:netdev` - Other families

  - `:counter` - Add packet/byte counter (default: `true`)

  ## Use Cases

  - **IDS Integration** - Automatically block IPs detected by intrusion detection
  - **Rate Limiting** - Block clients exceeding rate limits
  - **Geographic Filtering** - Block IP ranges by country
  - **Dynamic Allowlists** - Grant access to authenticated users
  - **Security Incident Response** - Rapidly deploy blocking rules

  ## Prerequisites

  Before creating rules, ensure the target table and chain exist:

      # Using nft command
      nft add table filter
      nft add chain filter INPUT '{ type filter hook input priority 0; }'

  Or use the low-level API to create them from Elixir.

  ## Advanced Usage

  For more complex rules (port matching, protocol filtering, connection tracking, NAT),
  use `NFTex.ExpressionBuilder` to build custom expressions and `NFTex.Port` to
  assemble them into rules.

  See `NFTex.ExpressionBuilder` for available expression helpers.

  ## Examples

  See the [firewall_rules.exs](../examples/firewall_rules.exs) example for a complete
  working demonstration of dynamic firewall management.
  """

  alias NFTex.Kernel
  alias NFTex.Validation

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type rule_spec :: %{
          table: String.t(),
          chain: String.t(),
          family: family(),
          expressions: [term()]
        }

  @doc """
  Create a rule.

  NOTE: Currently limited to very simple expressions. For complex rules,
  use `NFTex.Kernel.Rule` directly.

  ## Example

      NFTex.Rule.create(pid, %{
        table: "filter",
        chain: "input",
        family: :inet,
        expressions: [
          {:counter},
          {:verdict, :accept}
        ]
      })

  """
  @spec create(pid(), rule_spec()) :: :ok | {:error, term()}
  def create(_pid, _spec) do
    # TODO: Implement high-level rule creation with expression building
    # This is complex because it needs to:
    # 1. Parse expression specs
    # 2. Allocate and configure each expression
    # 3. Add expressions to rule in correct order
    # 4. Handle register allocation
    # 5. Send to kernel
    {:error, :not_implemented}
  end

  @doc """
  Delete a rule by handle.

  Rules in nftables are identified by their handle, which is a unique identifier
  assigned by the kernel when the rule is created. Use `NFTex.Rule.list/4` to
  get the handles of existing rules.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `chain` - Chain name (string)
  - `family` - Protocol family (`:inet`, `:ip6`, etc.)
  - `handle` - Rule handle (non_neg_integer from kernel)

  ## Examples

      # List rules to get handles
      {:ok, rules} = NFTex.Rule.list(pid, "filter", "INPUT", family: :inet)

      # Delete first rule
      [first_rule | _] = rules
      :ok = NFTex.Rule.delete(pid, "filter", "INPUT", :inet, first_rule.handle)

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec delete(pid(), String.t(), String.t(), family(), non_neg_integer()) ::
          :ok | {:error, term()}
  def delete(pid, table, chain, family, handle) do
    # Validate family
    with {:ok, family_int} <- Validation.validate_family(family) do
      with {:ok, rule_id} <- NFTex.Port.call(pid, {:rule_alloc}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, table}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, chain}),
           :ok <- NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, family_int}),
           :ok <- NFTex.Port.call(pid, {:rule_set_u64, rule_id, :handle, handle}),
           result <-
             NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :delete})
             |> enhance_rule_error(:rule_delete, table, chain) do
        NFTex.Port.call(pid, {:rule_free, rule_id})
        result
      else
        error ->
          error
      end
    end
  end

  @doc """
  List all rules in a chain.

  ## Example

      {:ok, rules} = NFTex.Rule.list(pid, "filter", "INPUT", family: :inet)

  """
  @spec list(pid(), String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list(pid, table, chain, opts \\ []) do
    case NFTex.Query.list_rules(pid, opts) do
      {:ok, rules} ->
        filtered = Enum.filter(rules, fn r ->
          r.table == table and r.chain == chain
        end)
        {:ok, filtered}

      error ->
        error
    end
  end

  @doc """
  Block an IP address by creating a DROP rule.

  This is a convenience function that creates a rule to drop all packets
  from the specified source IP address.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `chain` - Chain name (string)
  - `ip_address` - IP address to block as binary (e.g., `<<192, 168, 1, 100>>`)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:counter` - Add counter to rule (default: `true`)

  ## Examples

      # Block a single IP
      ip = <<192, 168, 1, 100>>
      :ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", ip)

      # Block without counter
      :ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", ip, counter: false)

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec block_ip(pid(), String.t(), String.t(), binary(), keyword()) :: :ok | {:error, term()}
  def block_ip(pid, table, chain, ip_address, opts \\ []) do
    # Validate IP address format
    with :ok <- Validation.validate_ipv4(ip_address),
         {:ok, family} <- Validation.validate_family(Keyword.get(opts, :family, :inet)) do
      add_counter = Keyword.get(opts, :counter, true)

      with {:ok, rule_id} <- NFTex.Port.call(pid, {:rule_alloc}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, table}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, chain}),
           :ok <- NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, family}),
           {:ok, _payload_id} <- add_ipv4_saddr_match(pid, rule_id, ip_address),
           :ok <- maybe_add_counter(pid, rule_id, add_counter),
           {:ok, _verdict_id} <- add_drop_verdict(pid, rule_id),
           result <-
             NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add})
             |> enhance_rule_error(:rule_add, table, chain) do
        NFTex.Port.call(pid, {:rule_free, rule_id})
        result
      else
        error ->
          error
      end
    end
  end

  @doc """
  Accept packets from an IP address by creating an ACCEPT rule.

  This is a convenience function that creates a rule to accept all packets
  from the specified source IP address. Useful for creating allowlists of
  trusted IP addresses.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `chain` - Chain name (string)
  - `ip_address` - IP address to allow as binary (e.g., `<<192, 168, 1, 50>>`)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:counter` - Add counter to rule (default: `true`)

  ## Examples

      # Allow a trusted IP
      ip = <<192, 168, 1, 50>>
      :ok = NFTex.Rule.accept_ip(pid, "filter", "INPUT", ip)

      # Allow an admin workstation
      admin_ip = <<10, 0, 1, 100>>
      :ok = NFTex.Rule.accept_ip(pid, "filter", "INPUT", admin_ip, counter: true)

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.

  ## Rule Structure

  The generated rule has the following expressions:
  1. Payload expression: Load source IP address into register 1
  2. Comparison expression: Check if register 1 matches the specified IP
  3. Counter expression: Count matching packets (if enabled)
  4. Verdict expression: ACCEPT the packet
  """
  @spec accept_ip(pid(), String.t(), String.t(), binary(), keyword()) :: :ok | {:error, term()}
  def accept_ip(pid, table, chain, ip_address, opts \\ []) do
    # Validate IP address format
    with :ok <- Validation.validate_ipv4(ip_address),
         {:ok, family} <- Validation.validate_family(Keyword.get(opts, :family, :inet)) do
      add_counter = Keyword.get(opts, :counter, true)

      with {:ok, rule_id} <- NFTex.Port.call(pid, {:rule_alloc}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, table}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, chain}),
           :ok <- NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, family}),
           {:ok, _payload_id} <- add_ipv4_saddr_match(pid, rule_id, ip_address),
           :ok <- maybe_add_counter(pid, rule_id, add_counter),
           {:ok, _verdict_id} <- add_accept_verdict(pid, rule_id),
           result <-
             NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add})
             |> enhance_rule_error(:rule_add, table, chain) do
        NFTex.Port.call(pid, {:rule_free, rule_id})
        result
      else
        error ->
          error
      end
    end
  end

  @doc """
  Block an IPv6 address by creating a DROP rule.

  This is a convenience function that creates a rule to drop all packets
  from the specified IPv6 source address.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `chain` - Chain name (string)
  - `ipv6_address` - IPv6 address to block as binary (16 bytes)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:ip6`)
    - `:counter` - Add counter to rule (default: `true`)

  ## Examples

      # Block a single IPv6 address (2001:db8::1)
      ipv6 = <<0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>
      :ok = NFTex.Rule.block_ipv6(pid, "filter", "INPUT", ipv6)

      # Block without counter
      :ok = NFTex.Rule.block_ipv6(pid, "filter", "INPUT", ipv6, counter: false)

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec block_ipv6(pid(), String.t(), String.t(), binary(), keyword()) :: :ok | {:error, term()}
  def block_ipv6(pid, table, chain, ipv6_address, opts \\ []) do
    # Validate IPv6 address format
    with :ok <- Validation.validate_ipv6(ipv6_address),
         {:ok, family} <- Validation.validate_family(Keyword.get(opts, :family, :ip6)) do
      add_counter = Keyword.get(opts, :counter, true)

      with {:ok, rule_id} <- NFTex.Port.call(pid, {:rule_alloc}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, table}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, chain}),
           :ok <- NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, family}),
           {:ok, _payload_id} <- add_ipv6_saddr_match(pid, rule_id, ipv6_address),
           :ok <- maybe_add_counter(pid, rule_id, add_counter),
           {:ok, _verdict_id} <- add_drop_verdict(pid, rule_id),
           result <-
             NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add})
             |> enhance_rule_error(:rule_add, table, chain) do
        NFTex.Port.call(pid, {:rule_free, rule_id})
        result
      else
        error ->
          error
      end
    end
  end

  @doc """
  Accept packets from an IPv6 address by creating an ACCEPT rule.

  This is a convenience function that creates a rule to accept all packets
  from the specified IPv6 source address.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `chain` - Chain name (string)
  - `ipv6_address` - IPv6 address to allow as binary (16 bytes)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:ip6`)
    - `:counter` - Add counter to rule (default: `true`)

  ## Examples

      # Allow a trusted IPv6 address (2001:db8::2)
      ipv6 = <<0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2>>
      :ok = NFTex.Rule.accept_ipv6(pid, "filter", "INPUT", ipv6)

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec accept_ipv6(pid(), String.t(), String.t(), binary(), keyword()) :: :ok | {:error, term()}
  def accept_ipv6(pid, table, chain, ipv6_address, opts \\ []) do
    # Validate IPv6 address format
    with :ok <- Validation.validate_ipv6(ipv6_address),
         {:ok, family} <- Validation.validate_family(Keyword.get(opts, :family, :ip6)) do
      add_counter = Keyword.get(opts, :counter, true)

      with {:ok, rule_id} <- NFTex.Port.call(pid, {:rule_alloc}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, table}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, chain}),
           :ok <- NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, family}),
           {:ok, _payload_id} <- add_ipv6_saddr_match(pid, rule_id, ipv6_address),
           :ok <- maybe_add_counter(pid, rule_id, add_counter),
           {:ok, _verdict_id} <- add_accept_verdict(pid, rule_id),
           result <-
             NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add})
             |> enhance_rule_error(:rule_add, table, chain) do
        NFTex.Port.call(pid, {:rule_free, rule_id})
        result
      else
        error ->
          error
      end
    end
  end

  @doc """
  Create a rate limiting rule.

  This is a high-level helper that creates a rule to drop packets exceeding
  a specified rate limit. Useful for DDoS protection and abuse prevention.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `chain` - Chain name (string)
  - `rate` - Number of packets/bytes per unit
  - `unit` - Time unit (`:second`, `:minute`, `:hour`, `:day`, `:week`)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:burst` - Burst size (default: 5)
    - `:type` - `:packets` or `:bytes` (default: `:packets`)
    - `:reject` - Use REJECT instead of DROP (default: `false`)
    - `:counter` - Add counter to rule (default: `true`)

  ## Examples

      # Drop packets exceeding 100 per second
      :ok = NFTex.Rule.rate_limit(pid, "filter", "INPUT", 100, :second)

      # Reject HTTP requests exceeding 10 per minute with burst of 20
      :ok = NFTex.Rule.rate_limit(pid, "filter", "INPUT", 10, :minute,
        burst: 20, reject: true)

      # Bandwidth limiting: 1 MB per second
      :ok = NFTex.Rule.rate_limit(pid, "filter", "FORWARD", 1_000_000, :second,
        type: :bytes)

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.

  ## Note

  This creates a rule that will DROP (or REJECT) packets that exceed the limit.
  Packets within the limit are allowed to continue to the next rule.
  """
  @spec rate_limit(pid(), String.t(), String.t(), non_neg_integer(), atom(), keyword()) ::
          :ok | {:error, term()}
  def rate_limit(pid, table, chain, rate, unit, opts \\ []) do
    with {:ok, family} <- Validation.validate_family(Keyword.get(opts, :family, :inet)) do
      burst = Keyword.get(opts, :burst, 5)
      type = Keyword.get(opts, :type, :packets)
      use_reject = Keyword.get(opts, :reject, false)
      add_counter = Keyword.get(opts, :counter, true)

      with {:ok, rule_id} <- NFTex.Port.call(pid, {:rule_alloc}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, table}),
           :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, chain}),
           :ok <- NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, family}),
           # Add limit expression
           {:ok, limit_id} <-
             NFTex.ExpressionBuilder.limit(pid, rate, unit, burst: burst, type: type),
           :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, limit_id}),
           # Add optional counter
           :ok <- maybe_add_counter(pid, rule_id, add_counter),
           # Add verdict (DROP or REJECT)
           {:ok, _verdict_id} <- add_verdict(pid, rule_id, use_reject),
           result <-
             NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add})
             |> enhance_rule_error(:rule_add, table, chain) do
        NFTex.Port.call(pid, {:rule_free, rule_id})
        result
      else
        error ->
          error
      end
    end
  end

  ## Private Helpers

  defp add_ipv4_saddr_match(pid, rule_id, ip_address) do
    with {:ok, payload_id} <- NFTex.ExpressionBuilder.payload_ipv4_saddr(pid, 1),
         :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, payload_id}),
         {:ok, cmp_id} <- NFTex.ExpressionBuilder.cmp_eq(pid, 1, ip_address),
         :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, cmp_id}) do
      {:ok, cmp_id}
    end
  end

  defp add_ipv6_saddr_match(pid, rule_id, ipv6_address) do
    with {:ok, payload_id} <- NFTex.ExpressionBuilder.payload_ipv6_saddr(pid, 1),
         :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, payload_id}),
         {:ok, cmp_id} <- NFTex.ExpressionBuilder.cmp_eq(pid, 1, ipv6_address),
         :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, cmp_id}) do
      {:ok, cmp_id}
    end
  end

  defp maybe_add_counter(_pid, _rule_id, false), do: :ok

  defp maybe_add_counter(pid, rule_id, true) do
    with {:ok, counter_id} <- NFTex.ExpressionBuilder.counter(pid),
         :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, counter_id}) do
      :ok
    end
  end

  defp add_verdict(pid, rule_id, use_reject) do
    if use_reject do
      add_reject_verdict(pid, rule_id)
    else
      add_drop_verdict(pid, rule_id)
    end
  end

  defp add_drop_verdict(pid, rule_id) do
    with {:ok, verdict_id} <- NFTex.ExpressionBuilder.verdict_drop(pid),
         :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, verdict_id}) do
      {:ok, verdict_id}
    end
  end

  defp add_accept_verdict(pid, rule_id) do
    with {:ok, verdict_id} <- NFTex.ExpressionBuilder.verdict_accept(pid),
         :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, verdict_id}) do
      {:ok, verdict_id}
    end
  end

  defp add_reject_verdict(pid, rule_id) do
    with {:ok, reject_id} <- NFTex.ExpressionBuilder.reject(pid),
         :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, reject_id}) do
      {:ok, reject_id}
    end
  end

  # Enhance netlink error messages with context
  defp enhance_rule_error(:ok, _operation, _table, _chain), do: :ok

  defp enhance_rule_error({:error, error_msg}, operation, table, chain)
       when is_binary(error_msg) do
    enhanced =
      Validation.enhance_netlink_error(error_msg, %{
        operation: operation,
        table: table,
        chain: chain
      })

    {:error, enhanced}
  end

  defp enhance_rule_error(error, _operation, _table, _chain), do: error
end
