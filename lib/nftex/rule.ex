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

  ## Example

      NFTex.Rule.delete(pid, "filter", "input", :inet, handle)

  """
  @spec delete(pid(), String.t(), String.t(), family(), non_neg_integer()) ::
          :ok | {:error, term()}
  def delete(_pid, _table, _chain, _family, _handle) do
    {:error, :not_implemented}
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
  def block_ip(pid, table, chain, ip_address, opts \\ []) when is_binary(ip_address) do
    family = family_to_int(Keyword.get(opts, :family, :inet))
    add_counter = Keyword.get(opts, :counter, true)

    with {:ok, rule_id} <- NFTex.Port.call(pid, {:rule_alloc}),
         :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, table}),
         :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, chain}),
         :ok <- NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, family}),
         {:ok, _payload_id} <- add_ipv4_saddr_match(pid, rule_id, ip_address),
         :ok <- maybe_add_counter(pid, rule_id, add_counter),
         {:ok, _verdict_id} <- add_drop_verdict(pid, rule_id),
         result <- NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add}) do
      NFTex.Port.call(pid, {:rule_free, rule_id})
      result
    else
      error ->
        error
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
  def accept_ip(pid, table, chain, ip_address, opts \\ []) when is_binary(ip_address) do
    family = family_to_int(Keyword.get(opts, :family, :inet))
    add_counter = Keyword.get(opts, :counter, true)

    with {:ok, rule_id} <- NFTex.Port.call(pid, {:rule_alloc}),
         :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, table}),
         :ok <- NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, chain}),
         :ok <- NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, family}),
         {:ok, _payload_id} <- add_ipv4_saddr_match(pid, rule_id, ip_address),
         :ok <- maybe_add_counter(pid, rule_id, add_counter),
         {:ok, _verdict_id} <- add_accept_verdict(pid, rule_id),
         result <- NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add}) do
      NFTex.Port.call(pid, {:rule_free, rule_id})
      result
    else
      error ->
        error
    end
  end

  ## Private Helpers

  defp family_to_int(:inet), do: 2
  defp family_to_int(:ip), do: 2
  defp family_to_int(:ip6), do: 10
  defp family_to_int(:inet6), do: 10
  defp family_to_int(:arp), do: 3
  defp family_to_int(:bridge), do: 7
  defp family_to_int(:netdev), do: 5
  defp family_to_int(n) when is_integer(n), do: n

  defp add_ipv4_saddr_match(pid, rule_id, ip_address) do
    with {:ok, payload_id} <- NFTex.ExpressionBuilder.payload_ipv4_saddr(pid, 1),
         :ok <- NFTex.Port.call(pid, {:rule_add_expr, rule_id, payload_id}),
         {:ok, cmp_id} <- NFTex.ExpressionBuilder.cmp_eq(pid, 1, ip_address),
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
end
