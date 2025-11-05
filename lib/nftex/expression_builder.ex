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
  - `payload_network/4` - Generic network header payload

  ### Comparison Expressions
  - `cmp_eq/3` - Equal (==)
  - `cmp_neq/3` - Not equal (!=)
  - `cmp/4` - Generic comparison (supports LT, GT, LTE, GTE)

  ### Counter Expression
  - `counter/1` - Packet and byte counter

  ### Verdict Expressions
  - `verdict_drop/1` - DROP verdict
  - `verdict_accept/1` - ACCEPT verdict
  - `verdict/2` - Generic verdict

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
end
