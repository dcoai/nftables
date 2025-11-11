defmodule NFTablesEx.RuleBuilder.Verdicts do
  @moduledoc """
  Verdict and control flow functions for RuleBuilder.

  Provides terminal verdicts (accept, drop, reject), non-terminal actions (continue, notrack),
  advanced features (queue, synproxy, flow offload), and chain control flow (jump, goto, return).
  """

  alias NFTablesEx.{RuleBuilder, JsonExpr}

  # Terminal verdicts

  @doc "Accept packets"
  @spec accept(RuleBuilder.t()) :: RuleBuilder.t()
  def accept(builder) do
    expr = JsonExpr.verdict("accept")
    RuleBuilder.add_expr(builder, expr)
  end

  @doc "Drop packets silently"
  @spec drop(RuleBuilder.t()) :: RuleBuilder.t()
  def drop(builder) do
    expr = JsonExpr.verdict("drop")
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Reject packets with ICMP error.

  ## Example

      builder |> reject()
      builder |> reject(:tcp_reset)
  """
  @spec reject(RuleBuilder.t(), atom()) :: RuleBuilder.t()
  def reject(builder, type \\ :icmp_port_unreachable) do
    expr = case type do
      :tcp_reset -> JsonExpr.reject("tcp reset")
      :icmp_port_unreachable -> JsonExpr.reject()
      :icmpx_port_unreachable -> JsonExpr.reject("icmpx type port-unreachable")
      other -> JsonExpr.reject(to_string(other))
    end

    RuleBuilder.add_expr(builder, expr)
  end

  # Non-terminal actions

  @doc """
  Continue to next rule.

  Unlike accept/drop/reject, this verdict continues rule evaluation.
  Useful for complex rule flows where you want to apply actions but
  continue processing.

  ## Example

      # Log and continue (don't stop processing)
      builder
      |> match_dest_port(22)
      |> log("SSH: ")
      |> continue()

      # Apply action and continue
      builder
      |> match_source_ip("192.168.1.0/24")
      |> set_mark(100)
      |> continue()

  ## Use Cases

  - Logging without terminal verdict
  - Multi-stage packet processing
  - Complex action chains
  - Audit trails with continued filtering
  """
  @spec continue(RuleBuilder.t()) :: RuleBuilder.t()
  def continue(builder) do
    expr = JsonExpr.verdict("continue")
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Disable connection tracking for packets.

  Marks packets as untracked, bypassing the connection tracking system.
  This improves performance but disables stateful features.

  ## Example

      # Disable tracking for high-volume traffic
      builder
      |> match_dest_port(443)
      |> notrack()

      # Skip tracking for local traffic
      builder
      |> match_source_ip("127.0.0.0/8")
      |> notrack()

  ## Use Cases

  - High-throughput servers (performance optimization)
  - Stateless firewalls
  - Reducing conntrack table load
  - Local/loopback traffic optimization

  ## WARNING

  Disabling connection tracking means:
  - No stateful filtering (NEW/ESTABLISHED states)
  - No NAT for these packets
  - No connection limits
  """
  @spec notrack(RuleBuilder.t()) :: RuleBuilder.t()
  def notrack(builder) do
    expr = %{"notrack" => nil}
    RuleBuilder.add_expr(builder, expr)
  end

  # Advanced features

  @doc """
  Queue packets to userspace for inspection.

  Sends packets to a userspace program (IDS/IPS) via NFQUEUE.
  The userspace program decides the final verdict.

  ## Options

  - `:bypass` - If queue is full, accept the packet (default: drop)
  - `:fanout` - Distribute packets across multiple queues

  ## Example

      # Queue to IDS on queue 0
      builder
      |> match_dest_port(80)
      |> queue_to_userspace(0)

      # Queue with bypass (don't drop on queue full)
      builder
      |> match_dest_port(443)
      |> queue_to_userspace(1, bypass: true)

      # Queue with fanout
      builder
      |> match_protocol(:tcp)
      |> queue_to_userspace(0, fanout: true)

  ## Use Cases

  - IDS/IPS integration (Suricata, Snort)
  - Custom packet inspection
  - Deep packet inspection
  - Application-level filtering
  """
  @spec queue_to_userspace(RuleBuilder.t(), non_neg_integer(), keyword()) :: RuleBuilder.t()
  def queue_to_userspace(builder, queue_num, opts \\ []) when is_integer(queue_num) and queue_num >= 0 do
    bypass = Keyword.get(opts, :bypass, false)
    fanout = Keyword.get(opts, :fanout, false)

    queue_expr = %{"num" => queue_num}

    flags = []
    flags = if bypass, do: ["bypass" | flags], else: flags
    flags = if fanout, do: ["fanout" | flags], else: flags

    queue_expr = if not Enum.empty?(flags) do
      Map.put(queue_expr, "flags", Enum.join(flags, ","))
    else
      queue_expr
    end

    expr = %{"queue" => queue_expr}
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Enable SYN proxy for DDoS protection.

  Implements SYN cookie-based protection against SYN flood attacks.
  The firewall handles the TCP handshake, protecting backend servers.

  ## Options

  - `:mss` - Maximum segment size (default: auto)
  - `:wscale` - Window scaling (default: auto)
  - `:sack_perm` - SACK permitted (default: auto)
  - `:timestamp` - TCP timestamp (default: auto)

  ## Example

      # Basic synproxy
      builder
      |> match_dest_port(80)
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> synproxy()

      # With custom MSS
      builder
      |> match_dest_port(443)
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> synproxy(mss: 1460)

      # Full options
      builder
      |> match_dest_port(22)
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> synproxy(mss: 1460, wscale: 7, sack_perm: true, timestamp: true)

  ## Use Cases

  - SYN flood DDoS protection
  - High-volume web servers
  - Public-facing services
  - Attack mitigation

  ## WARNING

  - Only use on SYN packets (match_tcp_flags required)
  - May break some TCP options
  - Backend servers see firewall as client
  """
  @spec synproxy(RuleBuilder.t(), keyword()) :: RuleBuilder.t()
  def synproxy(builder, opts \\ []) do
    synproxy_expr = %{}

    synproxy_expr = if mss = Keyword.get(opts, :mss) do
      Map.put(synproxy_expr, "mss", mss)
    else
      synproxy_expr
    end

    synproxy_expr = if wscale = Keyword.get(opts, :wscale) do
      Map.put(synproxy_expr, "wscale", wscale)
    else
      synproxy_expr
    end

    synproxy_expr = if Keyword.get(opts, :sack_perm) do
      Map.put(synproxy_expr, "sack-perm", true)
    else
      synproxy_expr
    end

    synproxy_expr = if Keyword.get(opts, :timestamp) do
      Map.put(synproxy_expr, "timestamp", true)
    else
      synproxy_expr
    end

    synproxy_expr = if map_size(synproxy_expr) == 0, do: nil, else: synproxy_expr
    expr = %{"synproxy" => synproxy_expr}
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Set TCP Maximum Segment Size (MSS).

  Modifies or clamps the TCP MSS option. Useful for fixing PMTU issues
  with PPPoE or VPN connections.

  ## Example

      # Clamp MSS to 1400 (for PPPoE)
      builder
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> set_tcp_mss(1400)
      |> accept()

      # Clamp to PMTU
      builder
      |> match_oif("pppoe0")
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> set_tcp_mss(:pmtu)
      |> accept()

  ## Use Cases

  - PPPoE connections (typically 1492 MTU → 1452 MSS)
  - VPN tunnels with reduced MTU
  - Fixing PMTU black holes
  - WAN interface MSS clamping
  """
  @spec set_tcp_mss(RuleBuilder.t(), non_neg_integer() | :pmtu) :: RuleBuilder.t()
  def set_tcp_mss(builder, :pmtu) do
    # TCP MSS clamping to PMTU
    expr = %{
      "mangle" => %{
        "key" => %{"tcp option" => %{"name" => "maxseg", "field" => "size"}},
        "value" => %{"rt" => "mtu"}
      }
    }
    RuleBuilder.add_expr(builder, expr)
  end
  def set_tcp_mss(builder, mss) when is_integer(mss) and mss > 0 and mss <= 65535 do
    # TCP MSS clamping to specific value
    expr = %{
      "mangle" => %{
        "key" => %{"tcp option" => %{"name" => "maxseg", "field" => "size"}},
        "value" => mss
      }
    }
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Duplicate packet to another interface.

  Sends a copy of the packet to a different interface while the original
  continues normal processing. Used for traffic mirroring and monitoring.

  ## Example

      # Mirror to monitoring interface
      builder
      |> match_dest_port(443)
      |> duplicate_to("monitor0")
      |> accept()

      # Mirror suspicious traffic to IDS
      builder
      |> match_source_ip("203.0.113.0/24")
      |> duplicate_to("ids0")
      |> continue()

  ## Use Cases

  - Network traffic monitoring
  - IDS/IPS analysis
  - Traffic analysis and debugging
  - Compliance and auditing
  """
  @spec duplicate_to(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def duplicate_to(builder, interface) when is_binary(interface) do
    expr = %{"dup" => %{"device" => interface}}
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Enable flow offloading to hardware.

  Offloads established connections to hardware for fast-path processing.
  Dramatically improves throughput for forwarded traffic on supported hardware.

  ## Options

  - `:table` - Flowtable name (required if using named flowtable)

  ## Example

      # Basic flow offload
      builder
      |> match_ct_state([:established])
      |> flow_offload()

      # Named flowtable
      builder
      |> match_ct_state([:established])
      |> flow_offload(table: "fastpath")

  ## Use Cases

  - Router throughput optimization
  - Hardware acceleration (if supported)
  - Multi-gigabit routing
  - Reducing CPU load on forwarding

  ## Requirements

  - Hardware support (not all NICs support offloading)
  - Flowtable must be created first
  - Only works for ESTABLISHED connections
  """
  @spec flow_offload(RuleBuilder.t(), keyword()) :: RuleBuilder.t()
  def flow_offload(builder, opts \\ []) do
    table = Keyword.get(opts, :table)

    expr = if table do
      %{"flow" => %{"op" => "add", "flowtable" => "@#{table}"}}
    else
      %{"flow" => %{"op" => "offload"}}
    end

    RuleBuilder.add_expr(builder, expr)
  end

  # Chain control flow

  @doc """
  Jump to another chain.

  Transfers control to the specified chain. If the chain accepts the packet,
  processing continues in the current chain after the jump. If the chain
  drops/rejects the packet, it terminates immediately.

  ## Example

      # Jump to custom logging chain
      builder
      |> match_dest_port(22)
      |> jump("ssh_logging")
      |> accept()

      # Complex rule organization
      builder
      |> match_source_ip("192.168.1.0/24")
      |> jump("internal_rules")

  ## Use Cases

  - Organize complex rulesets into logical chains
  - Reusable rule groups
  - Conditional rule application
  """
  @spec jump(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def jump(builder, chain_name) when is_binary(chain_name) do
    expr = JsonExpr.jump(chain_name)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Go to another chain (non-returning jump).

  Transfers control to the specified chain permanently. Unlike jump,
  control never returns to the current chain.

  ## Example

      # Permanent transfer to specialized chain
      builder
      |> match_dest_port(443)
      |> goto("https_chain")

  ## Difference from jump/1

  - `jump/1`: Returns after chain processing (like a function call)
  - `goto/1`: Never returns (like a goto statement)
  """
  @spec goto(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def goto(builder, chain_name) when is_binary(chain_name) do
    expr = JsonExpr.goto(chain_name)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Return from chain.

  Returns control to the calling chain. Only valid in chains that
  were entered via jump (not base chains).

  ## Example

      # In a custom chain, return early
      builder
      |> match_source_ip("192.168.1.100")
      |> return_from_chain()

      # Continue processing in calling chain
  """
  @spec return_from_chain(RuleBuilder.t()) :: RuleBuilder.t()
  def return_from_chain(builder) do
    expr = JsonExpr.verdict("return")
    RuleBuilder.add_expr(builder, expr)
  end
end
