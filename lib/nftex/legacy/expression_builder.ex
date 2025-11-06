defmodule NFTex.ExpressionBuilder do
  @moduledoc """
  Helper functions for building nftables expressions.

  Expressions are the building blocks of nftables rules. Each expression performs
  a specific operation: loading packet data, comparing values, counting packets,
  or setting verdicts. This module provides convenient functions for creating
  common expression patterns.

  ## Overview

  nftables rules consist of a sequence of expressions that are evaluated in order:

  1. **Payload expressions** - Load data from packets into registers
  2. **Comparison expressions** - Match register values against criteria
  3. **Counter expressions** - Count matching packets and bytes
  4. **Verdict expressions** - Take action (DROP, ACCEPT, etc.)

  ## Expression Ordering

  Expressions must be added to rules in the correct order:

      payload → comparison → counter → verdict

  ## Register Usage

  NFT uses numbered registers to store intermediate values during rule evaluation:

  - `NFT_REG_1` (1) - General purpose register (commonly used for payload data)
  - `NFT_REG_2` (2) - General purpose register
  - `NFT_REG_3` (3) - General purpose register
  - `NFT_REG_4` (4) - General purpose register
  - `NFT_REG_VERDICT` (0) - Special register for verdict expressions

  ## Complete Example

  Building a rule to block traffic from a specific IP:

      {:ok, pid} = NFTex.start_link()

      # 1. Allocate a rule
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc})
      :ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, "filter"})
      :ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, "INPUT"})
      :ok = NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, 2})

      # 2. Build and add expressions
      # Load source IP into register 1
      {:ok, payload_id} = NFTex.ExpressionBuilder.payload_ipv4_saddr(pid, 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, payload_id})

      # Compare register 1 with blocked IP
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_eq(pid, 1, <<192, 168, 1, 100>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, cmp_id})

      # Add counter
      {:ok, counter_id} = NFTex.ExpressionBuilder.counter(pid)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, counter_id})

      # Set DROP verdict
      {:ok, verdict_id} = NFTex.ExpressionBuilder.verdict_drop(pid)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, verdict_id})

      # 3. Send to kernel
      :ok = NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add})
      :ok = NFTex.Port.call(pid, {:rule_free, rule_id})

  ## High-Level Alternative

  For common operations like IP blocking, use the high-level helpers instead:

      NFTex.Rule.block_ip(pid, "filter", "INPUT", <<192, 168, 1, 100>>)

  This module is most useful when you need custom rules not covered by the
  high-level API (e.g., port matching, protocol filtering, connection tracking).

  ## Available Expression Types

  ### Payload Expressions
  - `payload_ipv4_saddr/2` - IPv4 source address
  - `payload_ipv4_daddr/2` - IPv4 destination address
  - `payload_ipv4_protocol/2` - IPv4 protocol field
  - `payload_ipv6_saddr/2` - IPv6 source address
  - `payload_ipv6_daddr/2` - IPv6 destination address
  - `payload_sport/2` - Source port
  - `payload_dport/2` - Destination port
  - `payload_network/4` - Generic network header payload
  - `payload_transport/4` - Generic transport header payload

  ### Comparison Expressions
  - `cmp_eq/3` - Equal (==)
  - `cmp_neq/3` - Not equal (!=)
  - `cmp_lt/3` - Less than (<)
  - `cmp_lte/3` - Less than or equal (<=)
  - `cmp_gt/3` - Greater than (>)
  - `cmp_gte/3` - Greater than or equal (>=)
  - `cmp/4` - Generic comparison

  ### Meta Expressions
  - `meta_iifname/2` - Input interface name
  - `meta_oifname/2` - Output interface name
  - `meta_iif/2` - Input interface index
  - `meta_oif/2` - Output interface index

  ### Immediate Expression
  - `immediate_data/3` - Load constant data into register

  ### NAT Expressions
  - `snat/4` - Source NAT
  - `dnat/4` - Destination NAT
  - `masquerade/2` - Masquerade (dynamic SNAT)
  - `redirect/2` - Redirect to local machine

  ### Connection Tracking (CT) Expressions
  - `ct_state/3` - Load connection tracking state
  - `ct_direction/2` - Load connection tracking direction
  - `ct_mark/2` - Load or set connection tracking mark

  ### Advanced Expressions
  - `log/2` - Log packets to kernel log or ulogd
  - `bitwise/6` - Bitwise operations (AND, OR, XOR, shift)
  - `lookup/4` - Set/map lookup
  - `fib/4` - Routing table (FIB) lookup

  ### Counter Expression
  - `counter/1` - Packet and byte counter

  ### Verdict Expressions
  - `verdict_drop/1` - DROP verdict
  - `verdict_accept/1` - ACCEPT verdict
  - `verdict/2` - Generic verdict

  ### Action Expressions
  - `reject/2` - Reject with ICMP/TCP error
  - `limit/4` - Rate limiting

  ## See Also

  - `NFTex.Rule` - High-level rule creation functions
  - `NFTex.Port` - Low-level nftables operations
  """

  alias NFTex.Port

  # Register constants
  @nft_reg_1 1
  @nft_reg_verdict 0

  # Payload bases
  @nft_payload_ll_header 0
  @nft_payload_network_header 1
  @nft_payload_transport_header 2

  # Comparison operators
  @nft_cmp_eq 0
  @nft_cmp_neq 1
  @nft_cmp_lt 2
  @nft_cmp_lte 3
  @nft_cmp_gt 4
  @nft_cmp_gte 5

  # Verdicts
  @nft_continue -1
  @nft_break -2
  @nft_jump -3
  @nft_goto -4
  @nft_return -5
  @nfta_verdict_drop 0
  @nfta_verdict_accept 1

  # Meta keys (for meta expression)
  @nft_meta_iifname 1
  @nft_meta_oifname 2
  @nft_meta_iif 3
  @nft_meta_oif 4
  @nft_meta_protocol 16

  ## Payload Expressions

  @doc """
  Load IPv4 source address into a register.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      {:ok, expr_id} = NFTex.ExpressionBuilder.payload_ipv4_saddr(pid, 1)
  """
  @spec payload_ipv4_saddr(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def payload_ipv4_saddr(pid, dreg \\ @nft_reg_1) do
    # IPv4 saddr is at offset 12 in IP header, 4 bytes
    payload_network(pid, dreg, 12, 4)
  end

  @doc """
  Load IPv4 destination address into a register.
  """
  @spec payload_ipv4_daddr(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def payload_ipv4_daddr(pid, dreg \\ @nft_reg_1) do
    # IPv4 daddr is at offset 16 in IP header, 4 bytes
    payload_network(pid, dreg, 16, 4)
  end

  @doc """
  Load IPv4 protocol field into a register.
  """
  @spec payload_ipv4_protocol(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def payload_ipv4_protocol(pid, dreg \\ @nft_reg_1) do
    # Protocol is at offset 9 in IP header, 1 byte
    payload_network(pid, dreg, 9, 1)
  end

  @doc """
  Load IPv6 source address into a register.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      {:ok, expr_id} = NFTex.ExpressionBuilder.payload_ipv6_saddr(pid, 1)
  """
  @spec payload_ipv6_saddr(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def payload_ipv6_saddr(pid, dreg \\ @nft_reg_1) do
    # IPv6 saddr is at offset 8 in IPv6 header, 16 bytes
    payload_network(pid, dreg, 8, 16)
  end

  @doc """
  Load IPv6 destination address into a register.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      {:ok, expr_id} = NFTex.ExpressionBuilder.payload_ipv6_daddr(pid, 1)
  """
  @spec payload_ipv6_daddr(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def payload_ipv6_daddr(pid, dreg \\ @nft_reg_1) do
    # IPv6 daddr is at offset 24 in IPv6 header, 16 bytes
    payload_network(pid, dreg, 24, 16)
  end

  @doc """
  Load IPv6 next header field into a register.

  The next header field in IPv6 is equivalent to the protocol field in IPv4.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      {:ok, expr_id} = NFTex.ExpressionBuilder.payload_ipv6_nexthdr(pid, 1)
  """
  @spec payload_ipv6_nexthdr(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def payload_ipv6_nexthdr(pid, dreg \\ @nft_reg_1) do
    # Next header is at offset 6 in IPv6 header, 1 byte
    payload_network(pid, dreg, 6, 1)
  end

  @doc """
  Load TCP/UDP source port into a register.

  Works for both TCP and UDP protocols.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      # Match source port 22 (SSH)
      {:ok, port_id} = NFTex.ExpressionBuilder.payload_sport(pid, 1)
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_eq(pid, 1, <<0, 22>>)
  """
  @spec payload_sport(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def payload_sport(pid, dreg \\ @nft_reg_1) do
    # Source port is at offset 0 in TCP/UDP header, 2 bytes
    payload_transport(pid, dreg, 0, 2)
  end

  @doc """
  Load TCP/UDP destination port into a register.

  Works for both TCP and UDP protocols.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      # Match destination port 80 (HTTP)
      {:ok, port_id} = NFTex.ExpressionBuilder.payload_dport(pid, 1)
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_eq(pid, 1, <<0, 80>>)
  """
  @spec payload_dport(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def payload_dport(pid, dreg \\ @nft_reg_1) do
    # Destination port is at offset 2 in TCP/UDP header, 2 bytes
    payload_transport(pid, dreg, 2, 2)
  end

  @doc """
  Generic payload expression for network header.
  """
  @spec payload_network(pid(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def payload_network(pid, dreg, offset, len) do
    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "payload"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :base, @nft_payload_network_header}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :dreg, dreg}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :offset, offset}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :len, len}) do
      {:ok, expr_id}
    end
  end

  @doc """
  Generic payload expression for transport header.
  """
  @spec payload_transport(pid(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def payload_transport(pid, dreg, offset, len) do
    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "payload"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :base, @nft_payload_transport_header}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :dreg, dreg}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :offset, offset}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :len, len}) do
      {:ok, expr_id}
    end
  end

  ## Comparison Expressions

  @doc """
  Compare register value for equality.

  ## Parameters
  - `pid` - NFTex process pid
  - `sreg` - Source register to compare
  - `data` - Binary data to compare against

  ## Example
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_eq(pid, 1, <<192, 168, 1, 100>>)
  """
  @spec cmp_eq(pid(), non_neg_integer(), binary()) :: {:ok, non_neg_integer()} | {:error, term()}
  def cmp_eq(pid, sreg, data) do
    cmp(pid, sreg, @nft_cmp_eq, data)
  end

  @doc """
  Compare register value for inequality.
  """
  @spec cmp_neq(pid(), non_neg_integer(), binary()) :: {:ok, non_neg_integer()} | {:error, term()}
  def cmp_neq(pid, sreg, data) do
    cmp(pid, sreg, @nft_cmp_neq, data)
  end

  @doc """
  Compare register value for less than.

  ## Example
      # Match packets with port < 1024 (privileged ports)
      {:ok, port_id} = NFTex.ExpressionBuilder.payload_dport(pid, 1)
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_lt(pid, 1, <<4, 0>>)
  """
  @spec cmp_lt(pid(), non_neg_integer(), binary()) :: {:ok, non_neg_integer()} | {:error, term()}
  def cmp_lt(pid, sreg, data) do
    cmp(pid, sreg, @nft_cmp_lt, data)
  end

  @doc """
  Compare register value for less than or equal.

  ## Example
      # Match packets with port <= 1024
      {:ok, port_id} = NFTex.ExpressionBuilder.payload_dport(pid, 1)
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_lte(pid, 1, <<4, 0>>)
  """
  @spec cmp_lte(pid(), non_neg_integer(), binary()) :: {:ok, non_neg_integer()} | {:error, term()}
  def cmp_lte(pid, sreg, data) do
    cmp(pid, sreg, @nft_cmp_lte, data)
  end

  @doc """
  Compare register value for greater than.

  ## Example
      # Match packets with port > 1024 (unprivileged ports)
      {:ok, port_id} = NFTex.ExpressionBuilder.payload_dport(pid, 1)
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_gt(pid, 1, <<4, 0>>)
  """
  @spec cmp_gt(pid(), non_neg_integer(), binary()) :: {:ok, non_neg_integer()} | {:error, term()}
  def cmp_gt(pid, sreg, data) do
    cmp(pid, sreg, @nft_cmp_gt, data)
  end

  @doc """
  Compare register value for greater than or equal.

  ## Example
      # Match packets with port >= 49152 (dynamic ports)
      {:ok, port_id} = NFTex.ExpressionBuilder.payload_dport(pid, 1)
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_gte(pid, 1, <<192, 0>>)
  """
  @spec cmp_gte(pid(), non_neg_integer(), binary()) :: {:ok, non_neg_integer()} | {:error, term()}
  def cmp_gte(pid, sreg, data) do
    cmp(pid, sreg, @nft_cmp_gte, data)
  end

  @doc """
  Generic comparison expression.
  """
  @spec cmp(pid(), non_neg_integer(), non_neg_integer(), binary()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def cmp(pid, sreg, op, data) do
    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "cmp"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :sreg, sreg}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :op, op}),
         :ok <- Port.call(pid, {:expr_set_data, expr_id, :data, data}) do
      {:ok, expr_id}
    end
  end

  ## Counter Expression

  @doc """
  Create a counter expression.

  Counters track packets and bytes for a rule.

  ## Example
      {:ok, counter_id} = NFTex.ExpressionBuilder.counter(pid)
  """
  @spec counter(pid()) :: {:ok, non_neg_integer()} | {:error, term()}
  def counter(pid) do
    Port.call(pid, {:expr_alloc, "counter"})
  end

  ## Meta Expressions

  @doc """
  Load input interface name into a register.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      {:ok, meta_id} = NFTex.ExpressionBuilder.meta_iifname(pid, 1)
      # Then compare with interface name, e.g., "eth0"
  """
  @spec meta_iifname(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def meta_iifname(pid, dreg \\ @nft_reg_1) do
    meta(pid, @nft_meta_iifname, dreg)
  end

  @doc """
  Load output interface name into a register.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      {:ok, meta_id} = NFTex.ExpressionBuilder.meta_oifname(pid, 1)
  """
  @spec meta_oifname(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def meta_oifname(pid, dreg \\ @nft_reg_1) do
    meta(pid, @nft_meta_oifname, dreg)
  end

  @doc """
  Load input interface index into a register.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      {:ok, meta_id} = NFTex.ExpressionBuilder.meta_iif(pid, 1)
  """
  @spec meta_iif(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def meta_iif(pid, dreg \\ @nft_reg_1) do
    meta(pid, @nft_meta_iif, dreg)
  end

  @doc """
  Load output interface index into a register.

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      {:ok, meta_id} = NFTex.ExpressionBuilder.meta_oif(pid, 1)
  """
  @spec meta_oif(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def meta_oif(pid, dreg \\ @nft_reg_1) do
    meta(pid, @nft_meta_oif, dreg)
  end

  @doc """
  Load protocol field into a register (from meta layer).

  ## Parameters
  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Example
      {:ok, meta_id} = NFTex.ExpressionBuilder.meta_protocol(pid, 1)
  """
  @spec meta_protocol(pid(), non_neg_integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def meta_protocol(pid, dreg \\ @nft_reg_1) do
    meta(pid, @nft_meta_protocol, dreg)
  end

  @doc """
  Generic meta expression.

  ## Parameters
  - `pid` - NFTex process pid
  - `key` - Meta key constant
  - `dreg` - Destination register

  ## Example
      {:ok, meta_id} = NFTex.ExpressionBuilder.meta(pid, 3, 1)
  """
  @spec meta(pid(), non_neg_integer(), non_neg_integer()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def meta(pid, key, dreg) do
    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "meta"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :key, key}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :dreg, dreg}) do
      {:ok, expr_id}
    end
  end

  ## Verdict Expressions

  @doc """
  Create a DROP verdict expression.

  ## Example
      {:ok, verdict_id} = NFTex.ExpressionBuilder.verdict_drop(pid)
  """
  @spec verdict_drop(pid()) :: {:ok, non_neg_integer()} | {:error, term()}
  def verdict_drop(pid) do
    verdict(pid, @nfta_verdict_drop)
  end

  @doc """
  Create an ACCEPT verdict expression.

  ## Example
      {:ok, verdict_id} = NFTex.ExpressionBuilder.verdict_accept(pid)
  """
  @spec verdict_accept(pid()) :: {:ok, non_neg_integer()} | {:error, term()}
  def verdict_accept(pid) do
    verdict(pid, @nfta_verdict_accept)
  end

  @doc """
  Generic verdict expression.
  """
  @spec verdict(pid(), integer()) :: {:ok, non_neg_integer()} | {:error, term()}
  def verdict(pid, verdict_code) do
    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "immediate"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :dreg, @nft_reg_verdict}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :verdict, verdict_code}) do
      {:ok, expr_id}
    end
  end

  ## Reject Expression

  @doc """
  Create a REJECT expression.

  The reject expression sends an error response back to the sender and then drops
  the packet. This is more informative than DROP, which silently discards packets.

  ## Parameters

  - `pid` - NFTex process pid
  - `type` - Reject type (default: `:icmp_port_unreachable`)

  ## Reject Types

  - `:icmp_net_unreachable` - ICMP network unreachable
  - `:icmp_host_unreachable` - ICMP host unreachable
  - `:icmp_prot_unreachable` - ICMP protocol unreachable
  - `:icmp_port_unreachable` - ICMP port unreachable (default)
  - `:icmp_net_prohibited` - ICMP network prohibited
  - `:icmp_host_prohibited` - ICMP host prohibited
  - `:icmp_admin_prohibited` - ICMP administratively prohibited
  - `:tcp_reset` - TCP RST packet (only for TCP)

  ## Examples

      # Reject with default (ICMP port unreachable)
      {:ok, reject_id} = NFTex.ExpressionBuilder.reject(pid)

      # Reject with TCP RST (for TCP connections)
      {:ok, reject_id} = NFTex.ExpressionBuilder.reject(pid, :tcp_reset)

      # Reject with ICMP administratively prohibited
      {:ok, reject_id} = NFTex.ExpressionBuilder.reject(pid, :icmp_admin_prohibited)

  ## Use Cases

  - **SSH protection** - Reject instead of drop for better client experience
  - **Service unavailable** - Inform clients that service is blocked
  - **Debugging** - Easier to debug than silent drops
  """
  @spec reject(pid(), atom()) :: {:ok, non_neg_integer()} | {:error, term()}
  def reject(pid, type \\ :icmp_port_unreachable) do
    type_code = reject_type_to_code(type)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "reject"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :type, type_code}) do
      {:ok, expr_id}
    end
  end

  # Reject type codes (from linux/netfilter/nf_tables.h)
  defp reject_type_to_code(:icmp_net_unreachable), do: 0
  defp reject_type_to_code(:icmp_host_unreachable), do: 1
  defp reject_type_to_code(:icmp_prot_unreachable), do: 2
  defp reject_type_to_code(:icmp_port_unreachable), do: 3
  defp reject_type_to_code(:icmp_net_prohibited), do: 4
  defp reject_type_to_code(:icmp_host_prohibited), do: 5
  defp reject_type_to_code(:icmp_admin_prohibited), do: 6
  defp reject_type_to_code(:tcp_reset), do: 7

  ## Limit Expression

  @doc """
  Create a LIMIT expression for rate limiting.

  The limit expression restricts the rate of matching packets. This is essential
  for DDoS protection, rate limiting APIs, and preventing abuse.

  ## Parameters

  - `pid` - NFTex process pid
  - `rate` - Number of packets/bytes per unit
  - `unit` - Time unit (`:second`, `:minute`, `:hour`, `:day`, `:week`)
  - `opts` - Optional parameters:
    - `:burst` - Burst size (default: 5)
    - `:type` - `:packets` or `:bytes` (default: `:packets`)
    - `:flags` - Invert flag (default: 0)

  ## Examples

      # Limit to 10 packets per second
      {:ok, limit_id} = NFTex.ExpressionBuilder.limit(pid, 10, :second)

      # Limit to 100 packets per minute with burst of 20
      {:ok, limit_id} = NFTex.ExpressionBuilder.limit(pid, 100, :minute, burst: 20)

      # Limit to 1 MB per second (bandwidth limiting)
      {:ok, limit_id} = NFTex.ExpressionBuilder.limit(pid, 1_000_000, :second, type: :bytes)

  ## Complete Rate Limiting Example

      # Block IPs that send more than 100 packets per second
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc})
      :ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, "filter"})
      :ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, "INPUT"})
      :ok = NFTex.Port.call(pid, {:rule_set_u32, rule_id, :family, 2})

      # Add limit expression
      {:ok, limit_id} = NFTex.ExpressionBuilder.limit(pid, 100, :second, burst: 10)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, limit_id})

      # Drop if limit exceeded
      {:ok, verdict_id} = NFTex.ExpressionBuilder.verdict_drop(pid)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, verdict_id})

      :ok = NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add})

  ## Use Cases

  - **DDoS Protection** - Limit packets per second per source IP
  - **API Rate Limiting** - Limit requests per minute per client
  - **Bandwidth Limiting** - Limit bytes per second
  - **Brute Force Protection** - Limit connection attempts
  """
  @spec limit(pid(), non_neg_integer(), atom(), keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def limit(pid, rate, unit, opts \\ []) do
    burst = Keyword.get(opts, :burst, 5)
    type = Keyword.get(opts, :type, :packets)
    flags = Keyword.get(opts, :flags, 0)

    unit_code = unit_to_code(unit)
    type_code = limit_type_to_code(type)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "limit"}),
         :ok <- Port.call(pid, {:expr_set_u64, expr_id, :rate, rate}),
         :ok <- Port.call(pid, {:expr_set_u64, expr_id, :unit, unit_code}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :burst, burst}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :type, type_code}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, :flags, flags}) do
      {:ok, expr_id}
    end
  end

  # Time unit codes (from linux/netfilter/nf_tables.h)
  # These are in nanoseconds
  defp unit_to_code(:second), do: 1_000_000_000
  defp unit_to_code(:minute), do: 60_000_000_000
  defp unit_to_code(:hour), do: 3_600_000_000_000
  defp unit_to_code(:day), do: 86_400_000_000_000
  defp unit_to_code(:week), do: 604_800_000_000_000

  # Limit type codes
  defp limit_type_to_code(:packets), do: 0
  defp limit_type_to_code(:bytes), do: 1

  ## Immediate Expression

  @doc """
  Load immediate data into a register.

  This expression loads a constant value into a register, which can then be used
  by other expressions (NAT, comparison, etc.).

  ## Parameters

  - `pid` - NFTex process pid
  - `dreg` - Destination register
  - `data` - Binary data to load

  ## Example

      # Load IP address into register 1
      {:ok, imm_id} = NFTex.ExpressionBuilder.immediate_data(pid, 1, <<192, 168, 1, 100>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, imm_id})

      # Load port number into register 2 (big-endian)
      {:ok, imm_id} = NFTex.ExpressionBuilder.immediate_data(pid, 2, <<0, 80>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, imm_id})

  """
  @spec immediate_data(pid(), non_neg_integer(), binary()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def immediate_data(pid, dreg, data) when is_binary(data) do
    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "immediate"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "immediate:dreg", dreg}),
         :ok <- Port.call(pid, {:expr_set_data, expr_id, "immediate:data", data}) do
      {:ok, expr_id}
    end
  end

  ## NAT Expressions

  @doc """
  Source NAT (SNAT) expression.

  Translates the source address and optionally the source port of packets.
  Commonly used for masquerading internal networks behind a public IP.

  ## Parameters

  - `pid` - NFTex process pid
  - `family` - Protocol family (`:inet` or `:inet6`)
  - `addr_reg` - Register containing the new source address (or nil for no address translation)
  - `opts` - Keyword list options:
    - `:port_reg` - Register containing the new source port (default: nil)
    - `:flags` - NAT flags (default: 0)

  ## Example

      # Load new source IP into register 1
      {:ok, imm_id} = NFTex.ExpressionBuilder.immediate_data(pid, 1, <<203, 0, 113, 1>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, imm_id})

      # Apply SNAT
      {:ok, nat_id} = NFTex.ExpressionBuilder.snat(pid, :inet, 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, nat_id})

  """
  @spec snat(pid(), atom(), non_neg_integer() | nil, keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def snat(pid, family, addr_reg, opts \\ []) do
    port_reg = Keyword.get(opts, :port_reg)
    flags = Keyword.get(opts, :flags, 0)
    family_int = family_to_int(family)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "nat"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "nat:type", 0}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "nat:family", family_int}),
         :ok <- maybe_set_reg(pid, expr_id, "nat:reg_addr_min", addr_reg),
         :ok <- maybe_set_reg(pid, expr_id, "nat:reg_addr_max", addr_reg),
         :ok <- maybe_set_reg(pid, expr_id, "nat:reg_proto_min", port_reg),
         :ok <- maybe_set_reg(pid, expr_id, "nat:reg_proto_max", port_reg),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "nat:flags", flags}) do
      {:ok, expr_id}
    end
  end

  @doc """
  Destination NAT (DNAT) expression.

  Translates the destination address and optionally the destination port of packets.
  Commonly used for port forwarding and load balancing.

  ## Parameters

  - `pid` - NFTex process pid
  - `family` - Protocol family (`:inet` or `:inet6`)
  - `addr_reg` - Register containing the new destination address (or nil for no address translation)
  - `opts` - Keyword list options:
    - `:port_reg` - Register containing the new destination port (default: nil)
    - `:flags` - NAT flags (default: 0)

  ## Example

      # Load internal server IP into register 1
      {:ok, imm_id} = NFTex.ExpressionBuilder.immediate_data(pid, 1, <<192, 168, 1, 100>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, imm_id})

      # Apply DNAT
      {:ok, nat_id} = NFTex.ExpressionBuilder.dnat(pid, :inet, 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, nat_id})

  """
  @spec dnat(pid(), atom(), non_neg_integer() | nil, keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def dnat(pid, family, addr_reg, opts \\ []) do
    port_reg = Keyword.get(opts, :port_reg)
    flags = Keyword.get(opts, :flags, 0)
    family_int = family_to_int(family)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "nat"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "nat:type", 1}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "nat:family", family_int}),
         :ok <- maybe_set_reg(pid, expr_id, "nat:reg_addr_min", addr_reg),
         :ok <- maybe_set_reg(pid, expr_id, "nat:reg_addr_max", addr_reg),
         :ok <- maybe_set_reg(pid, expr_id, "nat:reg_proto_min", port_reg),
         :ok <- maybe_set_reg(pid, expr_id, "nat:reg_proto_max", port_reg),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "nat:flags", flags}) do
      {:ok, expr_id}
    end
  end

  @doc """
  Masquerade expression.

  Special form of SNAT that automatically uses the outgoing interface's address.
  Ideal for dynamic IP addresses (DHCP, PPPoE).

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:port_reg` - Register containing the port range (default: nil)
    - `:flags` - NAT flags (default: 0)

  ## Example

      # Simple masquerade (no port translation)
      {:ok, masq_id} = NFTex.ExpressionBuilder.masquerade(pid)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, masq_id})

  """
  @spec masquerade(pid(), keyword()) :: {:ok, non_neg_integer()} | {:error, term()}
  def masquerade(pid, opts \\ []) do
    port_reg = Keyword.get(opts, :port_reg)
    flags = Keyword.get(opts, :flags, 0)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "masq"}),
         :ok <- maybe_set_reg(pid, expr_id, "masq:reg_proto_min", port_reg),
         :ok <- maybe_set_reg(pid, expr_id, "masq:reg_proto_max", port_reg),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "masq:flags", flags}) do
      {:ok, expr_id}
    end
  end

  @doc """
  Redirect expression.

  Redirects packets to the local machine. Useful for transparent proxying.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:port_reg` - Register containing the target port (default: nil)
    - `:flags` - NAT flags (default: 0)

  ## Example

      # Load target port into register 1
      {:ok, imm_id} = NFTex.ExpressionBuilder.immediate_data(pid, 1, <<0, 80>>)  # Port 80
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, imm_id})

      # Redirect to local port
      {:ok, redir_id} = NFTex.ExpressionBuilder.redirect(pid, port_reg: 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, redir_id})

  """
  @spec redirect(pid(), keyword()) :: {:ok, non_neg_integer()} | {:error, term()}
  def redirect(pid, opts \\ []) do
    port_reg = Keyword.get(opts, :port_reg)
    flags = Keyword.get(opts, :flags, 0)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "redir"}),
         :ok <- maybe_set_reg(pid, expr_id, "redir:reg_proto_min", port_reg),
         :ok <- maybe_set_reg(pid, expr_id, "redir:reg_proto_max", port_reg),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "redir:flags", flags}) do
      {:ok, expr_id}
    end
  end

  # Helper function to set register only if not nil
  defp maybe_set_reg(_pid, _expr_id, _attr, nil), do: :ok

  defp maybe_set_reg(pid, expr_id, attr, reg) when is_integer(reg) do
    Port.call(pid, {:expr_set_u32, expr_id, attr, reg})
  end

  # Helper function to convert family atom to integer
  defp family_to_int(:inet), do: 1
  defp family_to_int(:ip), do: 2
  defp family_to_int(:inet6), do: 10
  defp family_to_int(:ip6), do: 10
  defp family_to_int(int) when is_integer(int), do: int

  ## Connection Tracking (CT) Expressions

  @doc """
  Load connection tracking state into a register.

  Loads the conntrack state bitmask into the specified register. This is commonly
  used to match packets based on their connection state (NEW, ESTABLISHED, RELATED).

  ## Parameters

  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)
  - `opts` - Keyword list options:
    - `:dir` - Direction to check (`:original`, `:reply`, or nil for both)

  ## State Bitmask Values

  - `INVALID` - 1 (0x01) - Invalid connection
  - `ESTABLISHED` - 2 (0x02) - Established connection
  - `RELATED` - 4 (0x04) - Related to existing connection
  - `NEW` - 8 (0x08) - New connection
  - `UNTRACKED` - 64 (0x40) - Untracked connection

  ## Example

      # Load CT state into register 1
      {:ok, ct_id} = NFTex.ExpressionBuilder.ct_state(pid, 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, ct_id})

      # Match ESTABLISHED | RELATED (bitmask: 0x06)
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_eq(pid, 1, <<0x06>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, cmp_id})

      # Accept established/related connections
      {:ok, verdict_id} = NFTex.ExpressionBuilder.verdict_accept(pid)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, verdict_id})

  """
  @spec ct_state(pid(), non_neg_integer(), keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def ct_state(pid, dreg \\ @nft_reg_1, opts \\ []) do
    dir = Keyword.get(opts, :dir)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "ct"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "ct:key", 0}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "ct:dreg", dreg}),
         :ok <- maybe_set_ct_dir(pid, expr_id, dir) do
      {:ok, expr_id}
    end
  end

  @doc """
  Load connection tracking direction into a register.

  Loads the conntrack direction (ORIGINAL or REPLY) into the specified register.

  ## Parameters

  - `pid` - NFTex process pid
  - `dreg` - Destination register (default: 1)

  ## Direction Values

  - `ORIGINAL` - 0 - Original direction
  - `REPLY` - 1 - Reply direction

  ## Example

      # Load CT direction into register 1
      {:ok, ct_id} = NFTex.ExpressionBuilder.ct_direction(pid, 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, ct_id})

      # Match ORIGINAL direction (0)
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_eq(pid, 1, <<0>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, cmp_id})

  """
  @spec ct_direction(pid(), non_neg_integer()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def ct_direction(pid, dreg \\ @nft_reg_1) do
    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "ct"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "ct:key", 1}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "ct:dreg", dreg}) do
      {:ok, expr_id}
    end
  end

  @doc """
  Load or set connection tracking mark.

  When used with `dreg`, loads the conntrack mark value into the register.
  When used with `sreg`, sets the conntrack mark from the register value.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:dreg` - Destination register (for loading mark)
    - `:sreg` - Source register (for setting mark)
    - `:dir` - Direction to check (`:original`, `:reply`, or nil for both)

  You must specify either `:dreg` or `:sreg`, but not both.

  ## Example - Loading mark

      # Load CT mark into register 1
      {:ok, ct_id} = NFTex.ExpressionBuilder.ct_mark(pid, dreg: 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, ct_id})

      # Match mark value
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_eq(pid, 1, <<0, 0, 0, 42>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, cmp_id})

  ## Example - Setting mark

      # Load mark value into register 1
      {:ok, imm_id} = NFTex.ExpressionBuilder.immediate_data(pid, 1, <<0, 0, 0, 42>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, imm_id})

      # Set CT mark from register 1
      {:ok, ct_id} = NFTex.ExpressionBuilder.ct_mark(pid, sreg: 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, ct_id})

  """
  @spec ct_mark(pid(), keyword()) :: {:ok, non_neg_integer()} | {:error, term()}
  def ct_mark(pid, opts \\ []) do
    dreg = Keyword.get(opts, :dreg)
    sreg = Keyword.get(opts, :sreg)
    dir = Keyword.get(opts, :dir)

    cond do
      dreg != nil and sreg != nil ->
        {:error, "Cannot specify both :dreg and :sreg"}

      dreg == nil and sreg == nil ->
        {:error, "Must specify either :dreg or :sreg"}

      dreg != nil ->
        with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "ct"}),
             :ok <- Port.call(pid, {:expr_set_u32, expr_id, "ct:key", 3}),
             :ok <- Port.call(pid, {:expr_set_u32, expr_id, "ct:dreg", dreg}),
             :ok <- maybe_set_ct_dir(pid, expr_id, dir) do
          {:ok, expr_id}
        end

      sreg != nil ->
        with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "ct"}),
             :ok <- Port.call(pid, {:expr_set_u32, expr_id, "ct:key", 3}),
             :ok <- Port.call(pid, {:expr_set_u32, expr_id, "ct:sreg", sreg}),
             :ok <- maybe_set_ct_dir(pid, expr_id, dir) do
          {:ok, expr_id}
        end
    end
  end

  # Helper function to set CT direction if specified
  defp maybe_set_ct_dir(_pid, _expr_id, nil), do: :ok

  defp maybe_set_ct_dir(pid, expr_id, dir) when dir in [:original, :reply] do
    dir_value = ct_dir_to_int(dir)
    Port.call(pid, {:expr_set_u32, expr_id, "ct:dir", dir_value})
  end

  # CT direction codes
  defp ct_dir_to_int(:original), do: 0
  defp ct_dir_to_int(:reply), do: 1

  ## Log Expression

  @doc """
  Log packets with optional prefix and other parameters.

  Logs matching packets to the kernel log (dmesg) or netlink logging daemon (ulogd).

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:prefix` - String prefix for log messages (max 127 chars)
    - `:level` - Log level (`:emerg`, `:alert`, `:crit`, `:err`, `:warning`, `:notice`, `:info`, `:debug`)
    - `:group` - Netlink group number for ulogd (0-65535)
    - `:snaplen` - Number of bytes to include in log (0 = entire packet)
    - `:qthreshold` - Queue threshold for netlink logging
    - `:flags` - Logging flags (default: 0)

  ## Log Levels

  - `:emerg` (0) - System is unusable
  - `:alert` (1) - Action must be taken immediately
  - `:crit` (2) - Critical conditions
  - `:err` (3) - Error conditions
  - `:warning` (4) - Warning conditions
  - `:notice` (5) - Normal but significant condition
  - `:info` (6) - Informational
  - `:debug` (7) - Debug-level messages

  ## Example - Simple kernel log

      # Log dropped packets with prefix
      {:ok, log_id} = NFTex.ExpressionBuilder.log(pid, prefix: "DROPPED: ", level: :warning)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, log_id})

      # Then drop
      {:ok, verdict_id} = NFTex.ExpressionBuilder.verdict_drop(pid)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, verdict_id})

  ## Example - Netlink logging (ulogd)

      # Send to ulogd group 1
      {:ok, log_id} = NFTex.ExpressionBuilder.log(pid, prefix: "AUDIT: ", group: 1, snaplen: 128)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, log_id})

  """
  @spec log(pid(), keyword()) :: {:ok, non_neg_integer()} | {:error, term()}
  def log(pid, opts \\ []) do
    prefix = Keyword.get(opts, :prefix)
    level = Keyword.get(opts, :level)
    group = Keyword.get(opts, :group)
    snaplen = Keyword.get(opts, :snaplen)
    qthreshold = Keyword.get(opts, :qthreshold)
    flags = Keyword.get(opts, :flags, 0)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "log"}),
         :ok <- maybe_set_log_prefix(pid, expr_id, prefix),
         :ok <- maybe_set_log_level(pid, expr_id, level),
         :ok <- maybe_set_log_group(pid, expr_id, group),
         :ok <- maybe_set_log_snaplen(pid, expr_id, snaplen),
         :ok <- maybe_set_log_qthreshold(pid, expr_id, qthreshold),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "log:flags", flags}) do
      {:ok, expr_id}
    end
  end

  # Helper functions for log expression
  defp maybe_set_log_prefix(_pid, _expr_id, nil), do: :ok

  defp maybe_set_log_prefix(pid, expr_id, prefix) when is_binary(prefix) do
    Port.call(pid, {:expr_set_str, expr_id, "log:prefix", prefix})
  end

  defp maybe_set_log_level(_pid, _expr_id, nil), do: :ok

  defp maybe_set_log_level(pid, expr_id, level) when is_atom(level) do
    level_int = log_level_to_int(level)
    Port.call(pid, {:expr_set_u32, expr_id, "log:level", level_int})
  end

  defp maybe_set_log_group(_pid, _expr_id, nil), do: :ok

  defp maybe_set_log_group(pid, expr_id, group) when is_integer(group) do
    Port.call(pid, {:expr_set_u32, expr_id, "log:group", group})
  end

  defp maybe_set_log_snaplen(_pid, _expr_id, nil), do: :ok

  defp maybe_set_log_snaplen(pid, expr_id, snaplen) when is_integer(snaplen) do
    Port.call(pid, {:expr_set_u32, expr_id, "log:snaplen", snaplen})
  end

  defp maybe_set_log_qthreshold(_pid, _expr_id, nil), do: :ok

  defp maybe_set_log_qthreshold(pid, expr_id, qthreshold) when is_integer(qthreshold) do
    Port.call(pid, {:expr_set_u32, expr_id, "log:qthreshold", qthreshold})
  end

  # Log level codes
  defp log_level_to_int(:emerg), do: 0
  defp log_level_to_int(:alert), do: 1
  defp log_level_to_int(:crit), do: 2
  defp log_level_to_int(:err), do: 3
  defp log_level_to_int(:warning), do: 4
  defp log_level_to_int(:notice), do: 5
  defp log_level_to_int(:info), do: 6
  defp log_level_to_int(:debug), do: 7

  ## Bitwise Expression

  @doc """
  Bitwise operations on register values.

  Performs bitwise operations (AND, OR, XOR, left shift, right shift) on register values.

  ## Parameters

  - `pid` - NFTex process pid
  - `sreg` - Source register
  - `dreg` - Destination register
  - `len` - Length in bytes (1, 2, 4, or 16)
  - `op` - Operation (`:and`, `:or`, `:xor`, `:lshift`, `:rshift`)
  - `data` - Binary data for operation (mask for AND/OR/XOR, shift count for shifts)

  ## Operations

  - `:and` (0) - Bitwise AND
  - `:or` (1) - Bitwise OR
  - `:xor` (2) - Bitwise XOR
  - `:lshift` (3) - Left shift
  - `:rshift` (4) - Right shift

  ## Example - Extract upper bits

      # Load IP address into register 1
      {:ok, payload_id} = NFTex.ExpressionBuilder.payload_ipv4_saddr(pid, 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, payload_id})

      # Extract network part (mask with 255.255.255.0)
      {:ok, bitwise_id} = NFTex.ExpressionBuilder.bitwise(pid, 1, 1, 4, :and, <<255, 255, 255, 0>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, bitwise_id})

      # Compare with network 192.168.1.0
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_eq(pid, 1, <<192, 168, 1, 0>>)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, cmp_id})

  """
  @spec bitwise(pid(), non_neg_integer(), non_neg_integer(), non_neg_integer(), atom(), binary()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def bitwise(pid, sreg, dreg, len, op, data) when is_binary(data) do
    op_code = bitwise_op_to_int(op)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "bitwise"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "bitwise:sreg", sreg}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "bitwise:dreg", dreg}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "bitwise:len", len}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "bitwise:op", op_code}),
         :ok <- Port.call(pid, {:expr_set_data, expr_id, "bitwise:mask", data}) do
      {:ok, expr_id}
    end
  end

  # Bitwise operation codes
  defp bitwise_op_to_int(:and), do: 0
  defp bitwise_op_to_int(:or), do: 1
  defp bitwise_op_to_int(:xor), do: 2
  defp bitwise_op_to_int(:lshift), do: 3
  defp bitwise_op_to_int(:rshift), do: 4

  ## Lookup Expression

  @doc """
  Lookup a value in a set or map.

  Performs a lookup operation on a set or map, optionally storing the result.

  ## Parameters

  - `pid` - NFTex process pid
  - `set_name` - Name of the set or map
  - `sreg` - Source register (value to lookup)
  - `opts` - Keyword list options:
    - `:dreg` - Destination register for map values (optional)
    - `:flags` - Lookup flags (default: 0)

  ## Example - Set membership test

      # Load source IP into register 1
      {:ok, payload_id} = NFTex.ExpressionBuilder.payload_ipv4_saddr(pid, 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, payload_id})

      # Lookup in blocklist set
      {:ok, lookup_id} = NFTex.ExpressionBuilder.lookup(pid, "blocklist", 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, lookup_id})

      # If found, drop (lookup fails if not found, stopping rule evaluation)
      {:ok, verdict_id} = NFTex.ExpressionBuilder.verdict_drop(pid)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, verdict_id})

  ## Example - Map lookup with result

      # Load source IP into register 1
      {:ok, payload_id} = NFTex.ExpressionBuilder.payload_ipv4_saddr(pid, 1)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, payload_id})

      # Lookup in rate limit map, store result in register 2
      {:ok, lookup_id} = NFTex.ExpressionBuilder.lookup(pid, "ratelimits", 1, dreg: 2)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, lookup_id})

  """
  @spec lookup(pid(), String.t(), non_neg_integer(), keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def lookup(pid, set_name, sreg, opts \\ []) do
    dreg = Keyword.get(opts, :dreg)
    flags = Keyword.get(opts, :flags, 0)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "lookup"}),
         :ok <- Port.call(pid, {:expr_set_str, expr_id, "lookup:set", set_name}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "lookup:sreg", sreg}),
         :ok <- maybe_set_lookup_dreg(pid, expr_id, dreg),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "lookup:flags", flags}) do
      {:ok, expr_id}
    end
  end

  defp maybe_set_lookup_dreg(_pid, _expr_id, nil), do: :ok

  defp maybe_set_lookup_dreg(pid, expr_id, dreg) when is_integer(dreg) do
    Port.call(pid, {:expr_set_u32, expr_id, "lookup:dreg", dreg})
  end

  ## FIB Expression

  @doc """
  Forward Information Base (FIB) lookup.

  Performs a routing table lookup and stores the result in a register. This can be used
  for reverse path filtering, obtaining the output interface, or checking route existence.

  ## Parameters

  - `pid` - NFTex process pid
  - `dreg` - Destination register
  - `result` - What to lookup (`:oif`, `:oifname`, `:addrtype`)
  - `flags` - List of flags (`:saddr`, `:daddr`, `:mark`, `:iif`, `:oif`, `:present`)

  ## Result Types

  - `:oif` (1) - Output interface index
  - `:oifname` (2) - Output interface name
  - `:addrtype` (3) - Address type (local, unicast, broadcast, etc.)

  ## Flags

  - `:saddr` - Look up using source address
  - `:daddr` - Look up using destination address
  - `:mark` - Use packet mark in lookup
  - `:iif` - Restrict to input interface
  - `:oif` - Restrict to output interface
  - `:present` - Only check if route exists (don't store result)

  ## Example - Reverse path filter (anti-spoofing)

      # Get expected output interface for source IP
      {:ok, fib_id} = NFTex.ExpressionBuilder.fib(pid, 1, :oif, [:saddr, :iif])
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, fib_id})

      # Load actual input interface into register 2
      {:ok, meta_id} = NFTex.ExpressionBuilder.meta_iif(pid, 2)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, meta_id})

      # Compare: if oif != iif, packet is spoofed
      {:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_neq(pid, 1, 2)  # Compare registers
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, cmp_id})

      # Drop spoofed packets
      {:ok, verdict_id} = NFTex.ExpressionBuilder.verdict_drop(pid)
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, verdict_id})

  ## Example - Check if route exists

      # Check if route to destination exists
      {:ok, fib_id} = NFTex.ExpressionBuilder.fib(pid, 1, :oif, [:daddr, :present])
      :ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, fib_id})

      # If fib lookup fails, route doesn't exist (rule stops executing)

  """
  @spec fib(pid(), non_neg_integer(), atom(), list(atom())) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def fib(pid, dreg, result, flags) when is_list(flags) do
    result_code = fib_result_to_int(result)
    flags_value = fib_flags_to_int(flags)

    with {:ok, expr_id} <- Port.call(pid, {:expr_alloc, "fib"}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "fib:dreg", dreg}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "fib:result", result_code}),
         :ok <- Port.call(pid, {:expr_set_u32, expr_id, "fib:flags", flags_value}) do
      {:ok, expr_id}
    end
  end

  # FIB result codes
  defp fib_result_to_int(:oif), do: 1
  defp fib_result_to_int(:oifname), do: 2
  defp fib_result_to_int(:addrtype), do: 3

  # FIB flags - convert list of atoms to bitmask
  defp fib_flags_to_int(flags) when is_list(flags) do
    Enum.reduce(flags, 0, fn flag, acc ->
      Bitwise.bor(acc, fib_flag_to_bit(flag))
    end)
  end

  defp fib_flag_to_bit(:saddr), do: Bitwise.bsl(1, 0)
  defp fib_flag_to_bit(:daddr), do: Bitwise.bsl(1, 1)
  defp fib_flag_to_bit(:mark), do: Bitwise.bsl(1, 2)
  defp fib_flag_to_bit(:iif), do: Bitwise.bsl(1, 3)
  defp fib_flag_to_bit(:oif), do: Bitwise.bsl(1, 4)
  defp fib_flag_to_bit(:present), do: Bitwise.bsl(1, 5)
end
