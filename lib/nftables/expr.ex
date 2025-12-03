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

  def source_ip(builder \\ expr(), ip), do: IP.source_ip(builder, ip)
  def dest_ip(builder \\ expr(), ip), do: IP.dest_ip(builder, ip)

  ## Port Matching (delegated to Port)

  def dport(builder \\ expr(), port), do: Port.dport(builder, port)
  def sport(builder \\ expr(), port), do: Port.sport(builder, port)
  def dst_port(builder \\ expr(), port), do: Port.dst_port(builder, port)
  def src_port(builder \\ expr(), port), do: Port.src_port(builder, port)

  ## TCP/Protocol Matching (delegated to TCP)

  def tcp_flags(builder \\ expr(), flags, mask), do: TCP.tcp_flags(builder, flags, mask)
  def length(builder \\ expr(), op, length), do: TCP.length(builder, op, length)
  def ttl(builder \\ expr(), op, ttl), do: TCP.ttl(builder, op, ttl)
  def hoplimit(builder \\ expr(), op, hoplimit), do: TCP.hoplimit(builder, op, hoplimit)
  def protocol(builder \\ expr(), protocol), do: TCP.protocol(builder, protocol)

  ## Layer 2 Matching (delegated to Layer2)

  def source_mac(builder \\ expr(), mac), do: Layer2.source_mac(builder, mac)
  def dest_mac(builder \\ expr(), mac), do: Layer2.dest_mac(builder, mac)
  def iif(builder \\ expr(), ifname), do: Layer2.iif(builder, ifname)
  def oif(builder \\ expr(), ifname), do: Layer2.oif(builder, ifname)
  def vlan_id(builder \\ expr(), vlan_id), do: Layer2.vlan_id(builder, vlan_id)
  def vlan_pcp(builder \\ expr(), pcp), do: Layer2.vlan_pcp(builder, pcp)

  ## Connection Tracking Matching (delegated to CT)

  def ct_state(builder \\ expr(), states), do: CT.ct_state(builder, states)
  def ct_status(builder \\ expr(), statuses), do: CT.ct_status(builder, statuses)
  def ct_direction(builder \\ expr(), direction), do: CT.ct_direction(builder, direction)
  def connmark(builder \\ expr(), mark), do: CT.connmark(builder, mark)
  def ct_label(builder \\ expr(), label), do: CT.ct_label(builder, label)
  def ct_zone(builder \\ expr(), zone), do: CT.ct_zone(builder, zone)
  def ct_helper(builder \\ expr(), helper), do: CT.ct_helper(builder, helper)
  def ct_bytes(builder \\ expr(), op, bytes), do: CT.ct_bytes(builder, op, bytes)
  def ct_packets(builder \\ expr(), op, packets), do: CT.ct_packets(builder, op, packets)
  def ct_original_saddr(builder \\ expr(), addr), do: CT.ct_original_saddr(builder, addr)
  def ct_original_daddr(builder \\ expr(), addr), do: CT.ct_original_daddr(builder, addr)
  def limit_connections(builder \\ expr(), count), do: CT.limit_connections(builder, count)

  ## Advanced Matching (delegated to Advanced)

  def mark(builder \\ expr(), mark), do: Advanced.mark(builder, mark)
  def dscp(builder \\ expr(), dscp), do: Advanced.dscp(builder, dscp)
  def fragmented(builder \\ expr(), is_fragmented), do: Advanced.fragmented(builder, is_fragmented)
  def icmp_type(builder \\ expr(), type), do: Advanced.icmp_type(builder, type)
  def icmp_code(builder \\ expr(), code), do: Advanced.icmp_code(builder, code)
  def icmpv6_type(builder \\ expr(), type), do: Advanced.icmpv6_type(builder, type)
  def icmpv6_code(builder \\ expr(), code), do: Advanced.icmpv6_code(builder, code)
  def pkttype(builder \\ expr(), pkttype), do: Advanced.pkttype(builder, pkttype)
  def priority(builder \\ expr(), op, priority), do: Advanced.priority(builder, op, priority)
  def cgroup(builder \\ expr(), cgroup_id), do: Advanced.cgroup(builder, cgroup_id)
  def skuid(builder \\ expr(), uid), do: Advanced.skuid(builder, uid)
  def skgid(builder \\ expr(), gid), do: Advanced.skgid(builder, gid)
  def ah_spi(builder \\ expr(), spi), do: Advanced.ah_spi(builder, spi)
  def esp_spi(builder \\ expr(), spi), do: Advanced.esp_spi(builder, spi)
  def arp_operation(builder \\ expr(), operation), do: Advanced.arp_operation(builder, operation)
  def set(builder \\ expr(), set_name, match_type), do: Advanced.set(builder, set_name, match_type)
  def payload_raw(builder \\ expr(), base, offset, length, value), do: Advanced.payload_raw(builder, base, offset, length, value)
  defdelegate payload_raw_masked(builder, base, offset, length, mask, value), to: Advanced
  defdelegate payload_raw_expr(base, offset, length), to: Advanced
  def socket_transparent(builder \\ expr()), do: Advanced.socket_transparent(builder)

  ## OSF (OS Fingerprinting) (delegated to Advanced)

  def osf_name(builder, os_name), do: Advanced.osf_name(builder, os_name)
  def osf_name(builder, os_name, opts), do: Advanced.osf_name(builder, os_name, opts)
  def osf_version(builder, version), do: Advanced.osf_version(builder, version)
  def osf_version(builder, version, opts), do: Advanced.osf_version(builder, version, opts)

  ## Advanced Protocols (delegated to Protocols)

  def sctp(builder \\ expr()), do: Protocols.sctp(builder)
  def dccp(builder \\ expr()), do: Protocols.dccp(builder)
  def gre(builder \\ expr()), do: Protocols.gre(builder)
  def gre_version(builder \\ expr(), version), do: Protocols.gre_version(builder, version)
  def gre_key(builder \\ expr(), key), do: Protocols.gre_key(builder, key)
  def gre_flags(builder \\ expr(), flags), do: Protocols.gre_flags(builder, flags)

  ## Actions (delegated to Actions)

  def counter(builder \\ expr()), do: Actions.counter(builder)
  def log(builder, prefix), do: Actions.log(builder, prefix)
  def log(builder, prefix, opts), do: Actions.log(builder, prefix, opts)
  def rate_limit(builder, rate, unit), do: Actions.rate_limit(builder, rate, unit)
  def rate_limit(builder, rate, unit, opts), do: Actions.rate_limit(builder, rate, unit, opts)
  def set_mark(builder \\ expr(), mark), do: Actions.set_mark(builder, mark)
  def set_connmark(builder \\ expr(), mark), do: Actions.set_connmark(builder, mark)
  def restore_mark(builder \\ expr()), do: Actions.restore_mark(builder)
  def save_mark(builder \\ expr()), do: Actions.save_mark(builder)
  def set_ct_label(builder \\ expr(), label), do: Actions.set_ct_label(builder, label)
  def set_ct_helper(builder \\ expr(), helper), do: Actions.set_ct_helper(builder, helper)
  def set_ct_zone(builder \\ expr(), zone), do: Actions.set_ct_zone(builder, zone)
  def set_dscp(builder \\ expr(), dscp), do: Actions.set_dscp(builder, dscp)
  def set_ttl(builder \\ expr(), ttl), do: Actions.set_ttl(builder, ttl)
  def set_hoplimit(builder \\ expr(), hoplimit), do: Actions.set_hoplimit(builder, hoplimit)
  def increment_ttl(builder \\ expr()), do: Actions.increment_ttl(builder)
  def decrement_ttl(builder \\ expr()), do: Actions.decrement_ttl(builder)
  def increment_hoplimit(builder \\ expr()), do: Actions.increment_hoplimit(builder)
  def decrement_hoplimit(builder \\ expr()), do: Actions.decrement_hoplimit(builder)

  ## Meter Operations (delegated to Meter)

  def meter_update(builder \\ expr(), key_expr, set_name, rate, per), do: Meter.meter_update(builder, key_expr, set_name, rate, per)
  defdelegate meter_update(builder, key_expr, set_name, rate, per, opts), to: Meter
  def meter_add(builder \\ expr(), key_expr, set_name, rate, per), do: Meter.meter_add(builder, key_expr, set_name, rate, per)
  defdelegate meter_add(builder, key_expr, set_name, rate, per, opts), to: Meter

  ## NAT Actions (delegated to NAT)

  def snat_to(builder, ip), do: NAT.snat_to(builder, ip)
  def snat_to(builder, ip, opts), do: NAT.snat_to(builder, ip, opts)
  def dnat_to(builder, ip), do: NAT.dnat_to(builder, ip)
  def dnat_to(builder, ip, opts), do: NAT.dnat_to(builder, ip, opts)
  def masquerade(builder), do: NAT.masquerade(builder)
  def masquerade(builder, opts), do: NAT.masquerade(builder, opts)
  def redirect_to(builder \\ expr(), port), do: NAT.redirect_to(builder, port)

  ## Verdicts (delegated to Verdicts)

  def accept(builder \\ expr()), do: Verdicts.accept(builder)
  def drop(builder \\ expr()), do: Verdicts.drop(builder)
  def reject(builder), do: Verdicts.reject(builder)
  def reject(builder, type), do: Verdicts.reject(builder, type)
  def continue(builder \\ expr()), do: Verdicts.continue(builder)
  def notrack(builder \\ expr()), do: Verdicts.notrack(builder)
  def queue_to_userspace(builder, queue_num), do: Verdicts.queue_to_userspace(builder, queue_num)
  def queue_to_userspace(builder, queue_num, opts), do: Verdicts.queue_to_userspace(builder, queue_num, opts)
  def synproxy(builder), do: Verdicts.synproxy(builder)
  def synproxy(builder, opts), do: Verdicts.synproxy(builder, opts)
  def set_tcp_mss(builder \\ expr(), mss), do: Verdicts.set_tcp_mss(builder, mss)
  def duplicate_to(builder \\ expr(), interface), do: Verdicts.duplicate_to(builder, interface)
  def flow_offload(builder), do: Verdicts.flow_offload(builder)
  def flow_offload(builder, opts), do: Verdicts.flow_offload(builder, opts)
  def jump(builder \\ expr(), chain_name), do: Verdicts.jump(builder, chain_name)
  def goto(builder \\ expr(), chain_name), do: Verdicts.goto(builder, chain_name)
  def return_from_chain(builder \\ expr()), do: Verdicts.return_from_chain(builder)
  def tproxy(builder \\ expr(), opts), do: Verdicts.tproxy(builder, opts)

  ## Convenience Aliases (shorter names for common operations)

  @doc """
  Alias for `source_ip/2`. Match source IP address.

  ## Examples

      expr() |> source("192.168.1.1")
      expr() |> source("10.0.0.0/8")
  """
  @spec source(t(), String.t()) :: t()
  def source(builder \\ expr(), ip), do: IP.source_ip(builder, ip)

  @doc """
  Alias for `dest_ip/2`. Match destination IP address.

  ## Examples

      expr() |> dest("192.168.1.1")
      expr() |> dest("10.0.0.0/8")
  """
  @spec dest(t(), String.t()) :: t()
  def dest(builder \\ expr(), ip), do: IP.dest_ip(builder, ip)

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
  def state(builder \\ expr(), states), do: CT.ct_state(builder, states)

  @doc """
  Alias for `rate_limit/3`. Add rate limiting.

  ## Examples

      expr() |> limit(10, :minute)
      expr() |> limit(100, :second)
  """
  @spec limit(t(), non_neg_integer(), atom()) :: t()
  def limit(builder, rate, unit), do: Actions.rate_limit(builder, rate, unit)

  @doc """
  Alias for `rate_limit/4`. Add rate limiting with options.

  ## Examples

      expr() |> limit(10, :minute, burst: 5)
      expr() |> limit(100, :second, burst: 200)
  """
  @spec limit(t(), non_neg_integer(), atom(), keyword()) :: t()
  def limit(builder, rate, unit, opts), do: Actions.rate_limit(builder, rate, unit, opts)

  @doc """
  Match TCP protocol. Convenience for `protocol(:tcp)`.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Examples

      # Start new expression
      tcp() |> dport(80)

      # Continue existing expression
      expr() |> tcp() |> dport(80)
  """
  @spec tcp(t()) :: t()
  def tcp(builder \\ expr()), do: TCP.protocol(builder, :tcp)

  @doc """
  Match UDP protocol. Convenience for `protocol(:udp)`.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Examples

      # Start new expression
      udp() |> dport(53)

      # Continue existing expression
      expr() |> udp() |> dport(53)
  """
  @spec udp(t()) :: t()
  def udp(builder \\ expr()), do: TCP.protocol(builder, :udp)

  @doc """
  Match ICMP protocol. Convenience for `protocol(:icmp)`.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Examples

      # Start new expression
      icmp() |> icmp_type(:echo_request)

      # Continue existing expression
      expr() |> icmp() |> icmp_type(:echo_request)
  """
  @spec icmp(t()) :: t()
  def icmp(builder \\ expr()), do: TCP.protocol(builder, :icmp)

  @doc """
  Alias for `in_set/3`. Match against a named set.

  Delegates to `Advanced.set/3`.

  ## Examples

      expr() |> in_set("blocklist", :saddr)
      expr() |> in_set("allowed_ports", :dport)
  """
  @spec in_set(t(), String.t(), atom()) :: t()
  def in_set(builder \\ expr(), set_name, match_type), do: Advanced.set(builder, set_name, match_type)

  @doc """
  Alias for `return_from_chain/1`. Return from current chain.

  ## Examples

      expr() |> return()
  """
  @spec return(t()) :: t()
  def return(builder \\ expr()), do: Verdicts.return_from_chain(builder)

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
