defmodule NFTables.Expr do
  @moduledoc """
  Pure expression builder for nftables rules.

  This module provides the core expression builder struct and entry points.
  All match and action functions are organized into specialized sub-modules.

  ## Usage

  Import the main module for the core `expr/1` function and protocol shortcuts,
  then import the specific sub-modules you need:

      import NFTables.Expr           # Core: expr/1
      import NFTables.Expr.{IP, Port, TCP, Verdicts}

      # Build rule expressions
      rule = tcp() |> dport(22) |> accept()

  ## Module Organization

  Expression building functions are organized into specialized modules:

  - `NFTables.Expr` - Core entry points and helpers (this module)
  - `NFTables.Expr.IP` - IP address matching (`source_ip/2`, `dest_ip/2`)
  - `NFTables.Expr.Port` - Port matching (`dport/2`, `sport/2`)
  - `NFTables.Expr.TCP` - TCP/protocol matching (`tcp/1`, `udp/1`, `tcp_flags/3`, `ttl/3`)
  - `NFTables.Expr.Layer2` - MAC, interface, VLAN (`source_mac/2`, `iif/2`, `vlan_id/2`)
  - `NFTables.Expr.CT` - Connection tracking (`ct_state/2`, `ct_status/2`, `connmark/2`)
  - `NFTables.Expr.ICMP` - ICMP/ICMPv6 matching (`icmp_type/2`, `icmpv6_type/2`)
  - `NFTables.Expr.Metadata` - Packet metadata (`mark/2`, `dscp/2`, `fragmented/2`, `pkttype/2`)
  - `NFTables.Expr.Socket` - Socket/process filtering (`skuid/2`, `skgid/2`, `cgroup/2`)
  - `NFTables.Expr.IPsec` - IPsec AH/ESP matching (`ah_spi/2`, `esp_spi/2`)
  - `NFTables.Expr.ARP` - ARP operation matching (`arp_operation/2`)
  - `NFTables.Expr.Sets` - Named set matching (`set/3`)
  - `NFTables.Expr.Payload` - Raw payload inspection (`payload_raw/5`, `payload_raw_masked/6`)
  - `NFTables.Expr.OSF` - OS fingerprinting (`osf_name/3`, `osf_version/3`)
  - `NFTables.Expr.Actions` - Counters, logging, rate limiting (`counter/1`, `log/2-3`, `rate_limit/3-4`)
  - `NFTables.Expr.NAT` - NAT operations (`snat_to/2-3`, `dnat_to/2-3`, `masquerade/1-2`)
  - `NFTables.Expr.Verdicts` - Terminal verdicts (`accept/1`, `drop/1`, `reject/1-2`, `jump/2`)
  - `NFTables.Expr.Meter` - Per-key rate limiting (`meter_update/5-6`, `meter_add/5-6`)
  - `NFTables.Expr.Protocols` - Specialized protocols (`sctp/1`, `dccp/1`, `gre/1`)

  ## Common Import Patterns

  ### Basic Firewall Rules

      import NFTables.Expr
      import NFTables.Expr.{IP, Port, TCP, Verdicts}

      rule = tcp() |> dport(22) |> accept()

  ### With Connection Tracking

      import NFTables.Expr
      import NFTables.Expr.{IP, Port, TCP, CT, Actions, Verdicts}

      rule = tcp() |> dport(22) |> ct_state([:new]) |> counter() |> accept()

  ### NAT Rules

      import NFTables.Expr
      import NFTables.Expr.{IP, Port, TCP, NAT, Verdicts}

      rule = tcp() |> dport(8080) |> dnat_to("192.168.1.100:80")

  ### Complete Firewall (Import Everything)

      import NFTables.Expr
      import NFTables.Expr.{IP, Port, TCP, Layer2, CT, ICMP, Metadata, Socket, Actions, NAT, Verdicts}

  ## Quick Example

      import NFTables.Expr
      import NFTables.Expr.{Port, TCP, CT, Actions, Verdicts}

      # Build rule expressions
      ssh_rule = tcp() |> dport(22) |> ct_state([:new]) |> rate_limit(10, :minute) |> accept()
      established_rule = ct_state([:established, :related]) |> accept()

      # Use with NFTables
      NFTables.add(table: "filter", family: :inet)
      |> NFTables.add(chain: "INPUT", type: :filter, hook: :input)
      |> NFTables.add(rule: ssh_rule)
      |> NFTables.add(rule: established_rule)
      |> NFTables.submit(pid: pid)

  ## Expression Structure

  All sub-modules work with the same `%NFTables.Expr{}` struct, which contains:

  - `expr_list` - List of JSON expression maps
  - `family` - Protocol family (`:inet`, `:inet6`, etc.)
  - `protocol` - Current protocol context (`:tcp`, `:udp`, etc.)
  - `comment` - Optional rule comment

  Functions from sub-modules can be chained together via the pipeline operator:

      expr()
      |> IP.source_ip("10.0.0.0/8")
      |> TCP.tcp()
      |> Port.dport(22)
      |> CT.ct_state([:new])
      |> Actions.log("New SSH connection")
      |> Verdicts.accept()

  When fully imported, this becomes:

      expr()
      |> source_ip("10.0.0.0/8")
      |> tcp()
      |> dport(22)
      |> ct_state([:new])
      |> log("New SSH connection")
      |> accept()

  ## See Also

  - `NFTables` - Main builder module
  - `NFTables.Port` - Port process management
  - `NFTables.Policy` - Pre-built common policies
  - `NFTables.NAT` - High-level NAT helpers
  """

  defstruct [
    :family,
    :comment,
    # Current protocol context (nil, :tcp, :udp, etc.)
    :protocol,
    # JSON expression maps
    expr_list: []
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
      import NFTables.Expr.{TCP, Port, Verdicts}

      # Start a new rule with default family
      tcp() |> dport(22) |> accept()

      # Start with specific family
      expr(family: :inet6) |> tcp() |> dport(22) |> accept()

      # Multiple rules
      ssh = tcp() |> dport(22) |> accept()
      http = tcp() |> dport(80) |> accept()
  """
  @spec expr(keyword()) :: t()
  def expr(opts \\ []) do
    %__MODULE__{
      family: Keyword.get(opts, :family, :inet),
      expr_list: []
    }
  end

  @doc """
  Convert an expression to a list of JSON expression maps.

  This is used internally by Builder when extracting expression lists from
  Expr structs. Most users won't need to call this directly.

  ## Examples

      import NFTables.Expr
      import NFTables.Expr.{TCP, Port, Verdicts}

      expression = tcp() |> dport(22) |> accept()
      expr_list = to_list(expression)
      # Use expr_list with Builder: NFTables.add(builder, rule: expr_list)
  """
  @spec to_list(t()) :: list(map())
  def to_list(%__MODULE__{expr_list: expr_list}), do: expr_list

  @doc """
  Add a comment to the rule.

  Note: Comments are metadata and don't affect rule matching.

  ## Examples

      import NFTables.Expr
      import NFTables.Expr.{Port, TCP, Verdicts}

      tcp() |> dport(22) |> comment("Allow SSH from trusted network") |> accept()
  """
  @spec comment(t(), String.t()) :: t()
  def comment(rule, text) when is_binary(text), do: %{rule | comment: text}

  # Private helpers

  @doc false
  def add_expr(builder, expr) when is_map(expr) do
    # Add JSON expression map to expr_list
    %{builder | expr_list: builder.expr_list ++ [expr]}
  end

  @doc """
  Set the protocol context for subsequent port matching.

  This is used internally by `tcp()`, `udp()`, etc. in the TCP module to track
  which protocol the rule is matching, allowing sport/dport to work protocol-agnostically.

  Most users won't need to call this directly.
  """
  @spec set_protocol(t(), atom()) :: t()
  def set_protocol(builder, protocol) when is_atom(protocol) do
    %{builder | protocol: protocol}
  end
end
