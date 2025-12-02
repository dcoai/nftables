defmodule NFTables.Expr do
  @moduledoc """
  Pure expression builder for nftables rules.

  This module provides a fluent, chainable interface for building firewall rule
  expressions. It produces pure data structures that can be used with NFTables
  for building complete configurations.

  ## Quick Example

      import NFTables.Expr

      # Build rule expressions
      expr() |> tcp() |> dport(22) |> accept()
      expr() |> state([:established, :related]) |> accept()
      expr() |> iif("lo") |> accept()

  ## Usage with Builder

      import NFTables.Expr
      alias NFTables.Builder

      # Build rule expressions - Builder automatically converts to expression lists
      ssh_rule = expr() |> tcp() |> dport(22) |> limit(10, :minute) |> accept()
      established_rule = expr() |> state([:established, :related]) |> accept()

      # Use with Builder
      Builder.new()
      |> Builder.add(rule: ssh_rule, table: "filter", chain: "INPUT", family: :inet)
      |> Builder.add(rule: established_rule, table: "filter", chain: "INPUT", family: :inet)
      |> Builder.submit(pid: pid)

  ## Import for Concise Syntax

  This module works well with `import`:

      import NFTables.Expr

      # Now use functions directly
      expr() |> tcp() |> dport(80) |> accept()
      expr() |> state([:invalid]) |> drop()

  ## See Also

  - `NFTables` - Main builder module
  - `NFTables.Local` - Execute configurations
  - `NFTables.Policy` - Pre-built common policies
  """

  alias NFTables.Expr.{IP, Port, TCP, Layer2, CT, Advanced, Actions, NAT, Verdicts, Meter, Protocols}

  defstruct [
    :family,
    :comment,
    :protocol,        # Current protocol context (nil, :tcp, :udp, etc.)
    expr_list: []      # JSON expression maps
  ]

  @type t :: %__MODULE__{
          family: atom(),
          comment: String.t() | nil,
          protocol: atom() | nil,
          expr_list: list(map())
        }

  @doc """
  Start building a new rule expression.

  Returns an empty Expr struct ready for building rule expressions via piping.

  ## Parameters

  - `opts` - Options:
    - `:family` - Protocol family (default: `:inet`)

  ## Examples

      import NFTables.Expr

      # Start a new rule with default family
      expr() |> tcp() |> dport(22) |> accept()

      # Start with specific family
      expr(family: :inet6) |> tcp() |> dport(22) |> accept()

      # Multiple rules
      [
        expr() |> state([:established, :related]) |> accept(),
        expr() |> tcp() |> dport(80) |> accept(),
        expr() |> tcp() |> dport(443) |> accept()
      ]
  """
  @spec expr(keyword()) :: t()
  def expr(opts \\ []) do
    %__MODULE__{
      family: Keyword.get(opts, :family, :inet),
      expr_list: []
    }
  end

  ## IP Matching (delegated to IP)

  defdelegate source_ip(builder, ip), to: IP
  defdelegate dest_ip(builder, ip), to: IP

  ## Port Matching (delegated to Port)

  defdelegate dport(builder, port), to: Port
  defdelegate sport(builder, port), to: Port
  defdelegate dst_port(builder, port), to: Port
  defdelegate src_port(builder, port), to: Port

  ## TCP/Protocol Matching (delegated to TCP)

  defdelegate tcp_flags(builder, flags, mask), to: TCP
  defdelegate length(builder, op, length), to: TCP
  defdelegate ttl(builder, op, ttl), to: TCP
  defdelegate hoplimit(builder, op, hoplimit), to: TCP
  defdelegate protocol(builder, protocol), to: TCP

  ## Layer 2 Matching (delegated to Layer2)

  defdelegate source_mac(builder, mac), to: Layer2
  defdelegate dest_mac(builder, mac), to: Layer2
  defdelegate iif(builder, ifname), to: Layer2
  defdelegate oif(builder, ifname), to: Layer2
  defdelegate vlan_id(builder, vlan_id), to: Layer2
  defdelegate vlan_pcp(builder, pcp), to: Layer2

  ## Connection Tracking Matching (delegated to CT)

  defdelegate ct_state(builder, states), to: CT
  defdelegate ct_status(builder, statuses), to: CT
  defdelegate ct_direction(builder, direction), to: CT
  defdelegate connmark(builder, mark), to: CT
  defdelegate ct_label(builder, label), to: CT
  defdelegate ct_zone(builder, zone), to: CT
  defdelegate ct_helper(builder, helper), to: CT
  defdelegate ct_bytes(builder, op, bytes), to: CT
  defdelegate ct_packets(builder, op, packets), to: CT
  defdelegate ct_original_saddr(builder, addr), to: CT
  defdelegate ct_original_daddr(builder, addr), to: CT
  defdelegate limit_connections(builder, count), to: CT

  ## Advanced Matching (delegated to Advanced)

  defdelegate mark(builder, mark), to: Advanced
  defdelegate dscp(builder, dscp), to: Advanced
  defdelegate fragmented(builder, is_fragmented), to: Advanced
  defdelegate icmp_type(builder, type), to: Advanced
  defdelegate icmp_code(builder, code), to: Advanced
  defdelegate icmpv6_type(builder, type), to: Advanced
  defdelegate icmpv6_code(builder, code), to: Advanced
  defdelegate pkttype(builder, pkttype), to: Advanced
  defdelegate priority(builder, op, priority), to: Advanced
  defdelegate cgroup(builder, cgroup_id), to: Advanced
  defdelegate skuid(builder, uid), to: Advanced
  defdelegate skgid(builder, gid), to: Advanced
  defdelegate ah_spi(builder, spi), to: Advanced
  defdelegate esp_spi(builder, spi), to: Advanced
  defdelegate arp_operation(builder, operation), to: Advanced
  defdelegate set(builder, set_name, match_type), to: Advanced
  defdelegate payload_raw(builder, base, offset, length, value), to: Advanced
  defdelegate payload_raw_masked(builder, base, offset, length, mask, value), to: Advanced
  defdelegate payload_raw_expr(base, offset, length), to: Advanced
  defdelegate socket_transparent(builder), to: Advanced

  ## OSF (OS Fingerprinting) (delegated to Advanced)

  defdelegate osf_name(builder, os_name), to: Advanced
  defdelegate osf_name(builder, os_name, opts), to: Advanced
  defdelegate osf_version(builder, version), to: Advanced
  defdelegate osf_version(builder, version, opts), to: Advanced

  ## Advanced Protocols (delegated to Protocols)

  defdelegate sctp(builder), to: Protocols
  defdelegate dccp(builder), to: Protocols
  defdelegate gre(builder), to: Protocols
  defdelegate gre_version(builder, version), to: Protocols
  defdelegate gre_key(builder, key), to: Protocols
  defdelegate gre_flags(builder, flags), to: Protocols

  ## Actions (delegated to Actions)

  defdelegate counter(builder), to: Actions
  defdelegate log(builder, prefix), to: Actions
  defdelegate log(builder, prefix, opts), to: Actions
  defdelegate rate_limit(builder, rate, unit), to: Actions
  defdelegate rate_limit(builder, rate, unit, opts), to: Actions
  defdelegate set_mark(builder, mark), to: Actions
  defdelegate set_connmark(builder, mark), to: Actions
  defdelegate restore_mark(builder), to: Actions
  defdelegate save_mark(builder), to: Actions
  defdelegate set_ct_label(builder, label), to: Actions
  defdelegate set_ct_helper(builder, helper), to: Actions
  defdelegate set_ct_zone(builder, zone), to: Actions
  defdelegate set_dscp(builder, dscp), to: Actions
  defdelegate set_ttl(builder, ttl), to: Actions
  defdelegate set_hoplimit(builder, hoplimit), to: Actions
  defdelegate increment_ttl(builder), to: Actions
  defdelegate decrement_ttl(builder), to: Actions
  defdelegate increment_hoplimit(builder), to: Actions
  defdelegate decrement_hoplimit(builder), to: Actions

  ## Meter Operations (delegated to Meter)

  defdelegate meter_update(builder, key_expr, set_name, rate, per), to: Meter
  defdelegate meter_update(builder, key_expr, set_name, rate, per, opts), to: Meter
  defdelegate meter_add(builder, key_expr, set_name, rate, per), to: Meter
  defdelegate meter_add(builder, key_expr, set_name, rate, per, opts), to: Meter

  ## NAT Actions (delegated to NAT)

  defdelegate snat_to(builder, ip), to: NAT
  defdelegate snat_to(builder, ip, opts), to: NAT
  defdelegate dnat_to(builder, ip), to: NAT
  defdelegate dnat_to(builder, ip, opts), to: NAT
  defdelegate masquerade(builder), to: NAT
  defdelegate masquerade(builder, opts), to: NAT
  defdelegate redirect_to(builder, port), to: NAT

  ## Verdicts (delegated to Verdicts)

  defdelegate accept(builder), to: Verdicts
  defdelegate drop(builder), to: Verdicts
  defdelegate reject(builder), to: Verdicts
  defdelegate reject(builder, type), to: Verdicts
  defdelegate continue(builder), to: Verdicts
  defdelegate notrack(builder), to: Verdicts
  defdelegate queue_to_userspace(builder, queue_num), to: Verdicts
  defdelegate queue_to_userspace(builder, queue_num, opts), to: Verdicts
  defdelegate synproxy(builder), to: Verdicts
  defdelegate synproxy(builder, opts), to: Verdicts
  defdelegate set_tcp_mss(builder, mss), to: Verdicts
  defdelegate duplicate_to(builder, interface), to: Verdicts
  defdelegate flow_offload(builder), to: Verdicts
  defdelegate flow_offload(builder, opts), to: Verdicts
  defdelegate jump(builder, chain_name), to: Verdicts
  defdelegate goto(builder, chain_name), to: Verdicts
  defdelegate return_from_chain(builder), to: Verdicts
  defdelegate tproxy(builder, opts), to: Verdicts

  ## Convenience Aliases (shorter names for common operations)

  @doc """
  Alias for `source_ip/2`. Match source IP address.

  ## Examples

      expr() |> source("192.168.1.1")
      expr() |> source("10.0.0.0/8")
  """
  @spec source(t(), String.t()) :: t()
  defdelegate source(builder, ip), to: IP, as: :source_ip

  @doc """
  Alias for `dest_ip/2`. Match destination IP address.

  ## Examples

      expr() |> dest("192.168.1.1")
      expr() |> dest("10.0.0.0/8")
  """
  @spec dest(t(), String.t()) :: t()
  defdelegate dest(builder, ip), to: IP, as: :dest_ip

  @doc """
  Convenience function for matching destination port (same as `dport/2`).

  Supports both single ports and port ranges.

  ## Examples

      # Single port
      expr() |> tcp() |> port(22)
      expr() |> udp() |> port(53)

      # Port range
      expr() |> tcp() |> port(8000..9000)
  """
  @spec port(t(), integer() | Range.t()) :: t()
  def port(builder, port), do: dport(builder, port)

  @doc """
  Alias for `ct_state/2`. Match connection tracking state.

  ## Examples

      expr() |> state([:established, :related])
      expr() |> state([:new])
      expr() |> state(:invalid)
  """
  @spec state(t(), list(atom()) | atom()) :: t()
  defdelegate state(builder, states), to: CT, as: :ct_state

  @doc """
  Alias for `rate_limit/3`. Add rate limiting.

  ## Examples

      expr() |> limit(10, :minute)
      expr() |> limit(100, :second)
  """
  @spec limit(t(), non_neg_integer(), atom()) :: t()
  defdelegate limit(builder, rate, unit), to: Actions, as: :rate_limit

  @doc """
  Alias for `rate_limit/4`. Add rate limiting with options.

  ## Examples

      expr() |> limit(10, :minute, burst: 5)
      expr() |> limit(100, :second, burst: 200)
  """
  @spec limit(t(), non_neg_integer(), atom(), keyword()) :: t()
  defdelegate limit(builder, rate, unit, opts), to: Actions, as: :rate_limit

  @doc """
  Match TCP protocol. Convenience for `protocol(:tcp)`.

  ## Examples

      expr() |> tcp() |> dport(80)
  """
  @spec tcp(t()) :: t()
  def tcp(builder), do: TCP.protocol(builder, :tcp)

  @doc """
  Match UDP protocol. Convenience for `protocol(:udp)`.

  ## Examples

      expr() |> udp() |> dport(53)
  """
  @spec udp(t()) :: t()
  def udp(builder), do: TCP.protocol(builder, :udp)

  @doc """
  Match ICMP protocol. Convenience for `protocol(:icmp)`.

  ## Examples

      expr() |> icmp() |> icmp_type(:echo_request)
  """
  @spec icmp(t()) :: t()
  def icmp(builder), do: TCP.protocol(builder, :icmp)

  @doc """
  Alias for `in_set/3`. Match against a named set.

  Delegates to `Advanced.set/3`.

  ## Examples

      expr() |> in_set("blocklist", :saddr)
      expr() |> in_set("allowed_ports", :dport)
  """
  @spec in_set(t(), String.t(), atom()) :: t()
  defdelegate in_set(builder, set_name, match_type), to: Advanced, as: :set

  @doc """
  Alias for `return_from_chain/1`. Return from current chain.

  ## Examples

      expr() |> return()
  """
  @spec return(t()) :: t()
  defdelegate return(builder), to: Verdicts, as: :return_from_chain

  ## Helpers

  @doc """
  Extract the expression list from an expression builder.

  Returns the list of JSON expressions that can be used with Builder.add/2.

  ## Examples

      expression = expr() |> tcp() |> dport(22) |> accept()
      expr_list = to_list(expression)
      # Use expr_list with Builder: Builder.add(builder, rule: expr_list)
  """
  @spec to_list(t()) :: list(map())
  def to_list(%__MODULE__{expr_list: expr_list}), do: expr_list

  @doc """
  Add a comment to the rule.

  Note: Comments are metadata and don't affect rule matching.

  ## Examples

      expr() |> dport(22) |> comment("Allow SSH from trusted network") |> accept()
  """
  @spec comment(t(), String.t()) :: t()
  def comment(rule, text) when is_binary(text) do
    %{rule | comment: text}
  end

  # Private helpers

  @doc false
  def add_expr(builder, expr) when is_map(expr) do
    # Add JSON expression map to expr_list
    %{builder | expr_list: builder.expr_list ++ [expr]}
  end

  @doc """
  Set the protocol context for subsequent port matching.

  This is used internally by tcp(), udp(), etc. to track which protocol
  the rule is matching, allowing sport/dport to work protocol-agnostically.
  """
  @spec set_protocol(t(), atom()) :: t()
  def set_protocol(builder, protocol) when is_atom(protocol) do
    %{builder | protocol: protocol}
  end
end
