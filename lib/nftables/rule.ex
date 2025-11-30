defmodule NFTables.Rule do
  @moduledoc """
  High-level fluent API for building firewall rules.

  This module provides clean, concise functions for building nftables rules
  with a functional, pipeable interface. Function names are short and intuitive.

  ## Design Philosophy

  - **Short Names**: `state()` instead of `match_ct_state()`
  - **Pipeable**: Every function returns updated rule struct
  - **Type Safe**: Full typespecs and guards
  - **Flexible**: Can be used standalone or with Builder

  ## Basic Usage

      # Create and build a rule
      ssh_rule = Rule.new()
      |> Rule.protocol(:tcp)
      |> Rule.port(22)
      |> Rule.state([:new])
      |> Rule.log("SSH: ")
      |> Rule.accept()

      # Use with Builder - automatically converts to expression list
      Builder.new()
      |> Builder.add(table: "filter")
      |> Builder.add(chain: "input")
      |> Builder.add(rule: ssh_rule)
      |> Builder.execute(pid)

  ## Common Patterns

      # Allow established connections
      Rule.new()
      |> Rule.state([:established, :related])
      |> Rule.accept()

      # Block specific IP with logging
      Rule.new()
      |> Rule.source("192.168.1.100")
      |> Rule.log("BLOCKED: ")
      |> Rule.drop()

      # Rate-limited SSH
      Rule.new()
      |> Rule.protocol(:tcp)
      |> Rule.port(22)
      |> Rule.limit(10, :minute)
      |> Rule.accept()
  """

  alias NFTables.Expr

  @type t :: %__MODULE__{
          family: atom(),
          table: String.t() | nil,
          chain: String.t() | nil,
          expr_list: list(map()),
          comment: String.t() | nil
        }

  defstruct family: :inet,
            table: nil,
            chain: nil,
            expr_list: [],
            comment: nil

  ## Core Functions

  @doc """
  Create a new rule.

  ## Options

  - `:family` - Address family (default: `:inet`)
  - `:table` - Table name (optional)
  - `:chain` - Chain name (optional)

  ## Examples

      Rule.new()
      Rule.new(family: :ip6)
      Rule.new(table: "filter", chain: "input")
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    %__MODULE__{
      family: Keyword.get(opts, :family, :inet),
      table: Keyword.get(opts, :table),
      chain: Keyword.get(opts, :chain)
    }
  end

  @doc """
  Extract the expression list from a rule.

  Returns the list of JSON expressions that can be used with Builder.add/2.

  ## Examples

      rule = Rule.new() |> Rule.protocol(:tcp) |> Rule.accept()
      expr_list = Rule.to_expr(rule)
      Builder.add(builder, rule: expr_list)
  """
  @spec to_expr(t()) :: list(map())
  def to_expr(%__MODULE__{expr_list: expr_list}), do: expr_list

  ## Basic Matching

  @doc """
  Match protocol.

  ## Examples

      rule |> Rule.protocol(:tcp)
      rule |> Rule.protocol(:udp)
      rule |> Rule.protocol(:icmp)
  """
  @spec protocol(t(), atom() | String.t()) :: t()
  def protocol(rule, proto) when is_atom(proto) do
    protocol(rule, Atom.to_string(proto))
  end

  def protocol(rule, proto) when is_binary(proto) do
    expr = Expr.meta_match("l4proto", proto)
    add_expr(rule, expr)
  end

  @doc """
  Match source IP address.

  Supports single IPs, CIDR notation, and ranges.

  ## Examples

      rule |> Rule.source("192.168.1.1")
      rule |> Rule.source("10.0.0.0/8")
  """
  @spec source(t(), String.t()) :: t()
  def source(rule, ip) when is_binary(ip) do
    expr =
      case String.split(ip, "/") do
        [addr, prefix_len] ->
          # CIDR notation
          Expr.payload_match_prefix("ip", "saddr", addr, String.to_integer(prefix_len))
        _ ->
          # Single IP
          Expr.payload_match("ip", "saddr", ip)
      end

    add_expr(rule, expr)
  end

  @doc """
  Match destination IP address.

  ## Examples

      rule |> Rule.dest("192.168.1.1")
      rule |> Rule.dest("10.0.0.0/8")
  """
  @spec dest(t(), String.t()) :: t()
  def dest(rule, ip) when is_binary(ip) do
    expr =
      case String.split(ip, "/") do
        [addr, prefix_len] ->
          # CIDR notation
          Expr.payload_match_prefix("ip", "daddr", addr, String.to_integer(prefix_len))
        _ ->
          # Single IP
          Expr.payload_match("ip", "daddr", ip)
      end

    add_expr(rule, expr)
  end

  @doc """
  Match source port.

  ## Examples

      rule |> Rule.sport(1024)
  """
  @spec sport(t(), integer()) :: t()
  def sport(rule, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = Expr.payload_match("tcp", "sport", port)
    add_expr(rule, expr)
  end

  @doc """
  Match destination port.

  ## Examples

      rule |> Rule.dport(80)
      rule |> Rule.dport(443)
  """
  @spec dport(t(), integer()) :: t()
  def dport(rule, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = Expr.payload_match("tcp", "dport", port)
    add_expr(rule, expr)
  end

  @doc """
  Match port (both source and destination).

  Convenience function that matches destination port by default.

  ## Examples

      rule |> Rule.port(22)
      rule |> Rule.port(80)
  """
  @spec port(t(), integer()) :: t()
  def port(rule, port) when is_integer(port) do
    dport(rule, port)
  end

  @doc """
  Match port range.

  ## Examples

      rule |> Rule.port_range(1024, 65535)
      rule |> Rule.port_range(8000, 9000)
  """
  @spec port_range(t(), integer(), integer()) :: t()
  def port_range(rule, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) do
    expr = Expr.payload_match_range("tcp", "dport", min_port, max_port)
    add_expr(rule, expr)
  end

  @doc """
  Match input interface.

  ## Examples

      rule |> Rule.iif("eth0")
      rule |> Rule.iif("wlan0")
  """
  @spec iif(t(), String.t()) :: t()
  def iif(rule, interface) when is_binary(interface) do
    expr = Expr.meta_match("iifname", interface)
    add_expr(rule, expr)
  end

  @doc """
  Match output interface.

  ## Examples

      rule |> Rule.oif("eth0")
  """
  @spec oif(t(), String.t()) :: t()
  def oif(rule, interface) when is_binary(interface) do
    expr = Expr.meta_match("oifname", interface)
    add_expr(rule, expr)
  end

  ## Connection Tracking

  @doc """
  Match connection tracking state.

  ## States

  - `:invalid`, `:established`, `:related`, `:new`, `:untracked`

  ## Examples

      rule |> Rule.state([:established, :related])
      rule |> Rule.state([:new])
      rule |> Rule.state(:invalid)
  """
  @spec state(t(), list(atom()) | atom()) :: t()
  def state(rule, states) when is_list(states) do
    state_strings = Enum.map(states, &Atom.to_string/1)
    expr = Expr.ct_match("state", state_strings)
    add_expr(rule, expr)
  end

  def state(rule, state) when is_atom(state) do
    state(rule, [state])
  end

  @doc """
  Match connection tracking status.

  ## Examples

      rule |> Rule.status([:assured])
      rule |> Rule.status([:snat])
  """
  @spec status(t(), list(atom())) :: t()
  def status(rule, statuses) when is_list(statuses) do
    status_strings = Enum.map(statuses, &Atom.to_string/1)
    expr = Expr.ct_match("status", status_strings)
    add_expr(rule, expr)
  end

  @doc """
  Match connection mark.

  ## Examples

      rule |> Rule.connmark(42)
  """
  @spec connmark(t(), non_neg_integer()) :: t()
  def connmark(rule, mark) when is_integer(mark) and mark >= 0 do
    expr = Expr.ct_match("mark", mark)
    add_expr(rule, expr)
  end

  ## Advanced Matching

  @doc """
  Match packet mark.

  ## Examples

      rule |> Rule.mark(100)
  """
  @spec mark(t(), non_neg_integer()) :: t()
  def mark(rule, mark_val) when is_integer(mark_val) and mark_val >= 0 do
    expr = Expr.meta_match("mark", mark_val)
    add_expr(rule, expr)
  end

  @doc """
  Match DSCP value.

  ## Examples

      rule |> Rule.dscp(46)  # Expedited forwarding
  """
  @spec dscp(t(), non_neg_integer()) :: t()
  def dscp(rule, dscp_val) when is_integer(dscp_val) and dscp_val >= 0 and dscp_val <= 63 do
    expr = Expr.payload_match("ip", "dscp", dscp_val)
    add_expr(rule, expr)
  end

  @doc """
  Match ICMP type.

  ## Examples

      rule |> Rule.icmp_type(:echo_request)
      rule |> Rule.icmp_type(8)
  """
  @spec icmp_type(t(), atom() | non_neg_integer()) :: t()
  def icmp_type(rule, type) when is_atom(type) do
    type_val =
      case type do
        :echo_reply -> "echo-reply"
        :dest_unreachable -> "destination-unreachable"
        :echo_request -> "echo-request"
        :time_exceeded -> "time-exceeded"
        other -> Atom.to_string(other)
      end

    expr = Expr.payload_match("icmp", "type", type_val)
    add_expr(rule, expr)
  end

  def icmp_type(rule, type) when is_integer(type) do
    expr = Expr.payload_match("icmp", "type", type)
    add_expr(rule, expr)
  end

  @doc """
  Match against a named set.

  ## Examples

      rule |> Rule.in_set("@blocklist", :saddr)
      rule |> Rule.in_set("@allowed_ports", :dport)
  """
  @spec in_set(t(), String.t(), atom()) :: t()
  def in_set(rule, set_name, match_type) when is_binary(set_name) do
    # Ensure set name starts with @
    set_ref = if String.starts_with?(set_name, "@"), do: set_name, else: "@#{set_name}"

    {protocol, field} =
      case match_type do
        :saddr -> {"ip", "saddr"}
        :daddr -> {"ip", "daddr"}
        :sport -> {"tcp", "sport"}
        :dport -> {"tcp", "dport"}
      end

    expr = Expr.set_match(protocol, field, set_ref)
    add_expr(rule, expr)
  end

  ## Actions

  @doc """
  Add counter.

  ## Examples

      rule |> Rule.counter()
  """
  @spec counter(t()) :: t()
  def counter(rule) do
    expr = Expr.counter()
    add_expr(rule, expr)
  end

  @doc """
  Add log statement.

  ## Examples

      rule |> Rule.log("SSH: ")
      rule |> Rule.log("DROP: ", level: "warn")
  """
  @spec log(t(), String.t(), keyword()) :: t()
  def log(rule, prefix, opts \\ []) when is_binary(prefix) do
    level = Keyword.get(opts, :level)

    json_opts =
      if level do
        [level: level]
      else
        []
      end

    expr = Expr.log(prefix, json_opts)
    add_expr(rule, expr)
  end

  @doc """
  Add rate limiting.

  ## Examples

      rule |> Rule.limit(10, :minute)
      rule |> Rule.limit(100, :second, burst: 200)
  """
  @spec limit(t(), non_neg_integer(), atom(), keyword()) :: t()
  def limit(rule, rate, unit, opts \\ [])
      when is_integer(rate) and is_atom(unit) do
    unit_str = Atom.to_string(unit)

    json_opts =
      if burst = Keyword.get(opts, :burst) do
        [burst: burst]
      else
        []
      end

    expr = Expr.limit(rate, unit_str, json_opts)
    add_expr(rule, expr)
  end

  @doc """
  Set packet mark.

  ## Examples

      rule |> Rule.set_mark(100)
  """
  @spec set_mark(t(), non_neg_integer()) :: t()
  def set_mark(rule, mark_val) when is_integer(mark_val) and mark_val >= 0 do
    expr = Expr.meta_set("mark", mark_val)
    add_expr(rule, expr)
  end

  @doc """
  Set connection mark.

  ## Examples

      rule |> Rule.set_connmark(42)
  """
  @spec set_connmark(t(), non_neg_integer()) :: t()
  def set_connmark(rule, mark_val) when is_integer(mark_val) and mark_val >= 0 do
    expr = Expr.ct_set("mark", mark_val)
    add_expr(rule, expr)
  end

  ## Verdicts

  @doc """
  Accept the packet.

  ## Examples

      rule |> Rule.accept()
  """
  @spec accept(t()) :: t()
  def accept(rule) do
    expr = Expr.verdict("accept")
    add_expr(rule, expr)
  end

  @doc """
  Drop the packet silently.

  ## Examples

      rule |> Rule.drop()
  """
  @spec drop(t()) :: t()
  def drop(rule) do
    expr = Expr.verdict("drop")
    add_expr(rule, expr)
  end

  @doc """
  Reject the packet with ICMP message.

  ## Examples

      rule |> Rule.reject()
      rule |> Rule.reject("tcp reset")
  """
  @spec reject(t(), String.t() | nil) :: t()
  def reject(rule, type \\ nil) do
    expr = Expr.reject(type)
    add_expr(rule, expr)
  end

  @doc """
  Jump to another chain.

  ## Examples

      rule |> Rule.jump("custom_chain")
  """
  @spec jump(t(), String.t()) :: t()
  def jump(rule, chain_name) when is_binary(chain_name) do
    expr = Expr.jump(chain_name)
    add_expr(rule, expr)
  end

  @doc """
  Return from chain.

  ## Examples

      rule |> Rule.return()
  """
  @spec return(t()) :: t()
  def return(rule) do
    expr = Expr.verdict("return")
    add_expr(rule, expr)
  end

  ## NAT

  @doc """
  Apply source NAT.

  ## Examples

      rule |> Rule.snat("203.0.113.1")
      rule |> Rule.snat("203.0.113.1", port: 1024)
  """
  @spec snat(t(), String.t(), keyword()) :: t()
  def snat(rule, addr, opts \\ []) when is_binary(addr) do
    expr = Expr.snat(addr, opts)
    add_expr(rule, expr)
  end

  @doc """
  Apply destination NAT.

  ## Examples

      rule |> Rule.dnat("192.168.1.10")
      rule |> Rule.dnat("192.168.1.10", port: 8080)
  """
  @spec dnat(t(), String.t(), keyword()) :: t()
  def dnat(rule, addr, opts \\ []) when is_binary(addr) do
    expr = Expr.dnat(addr, opts)
    add_expr(rule, expr)
  end

  @doc """
  Apply masquerading (dynamic SNAT).

  ## Examples

      rule |> Rule.masquerade()
      rule |> Rule.masquerade(port_range: "1024-65535")
  """
  @spec masquerade(t(), keyword()) :: t()
  def masquerade(rule, opts \\ []) do
    expr = Expr.masquerade(opts)
    add_expr(rule, expr)
  end

  @doc """
  Add a comment to the rule.

  ## Examples

      rule |> Rule.comment("Allow SSH from trusted network")
  """
  @spec comment(t(), String.t()) :: t()
  def comment(rule, text) when is_binary(text) do
    %{rule | comment: text}
  end

  ## Private Helpers

  # Add an expression to the rule's expression list
  defp add_expr(%__MODULE__{expr_list: expr_list} = rule, expr) when is_map(expr) do
    %{rule | expr_list: expr_list ++ [expr]}
  end
end
