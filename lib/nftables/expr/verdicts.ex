defmodule NFTables.Expr.Verdicts do
  @moduledoc """
  Verdict and control flow functions for Expr.

  Provides terminal verdicts (accept, drop, reject), non-terminal actions (continue, notrack),
  advanced features (queue, synproxy, flow offload), and chain control flow (jump, goto, return).
  """

  alias NFTables.Expr

  # Terminal verdicts

  @doc "Accept packets"
  @spec accept(Expr.t()) :: Expr.t()
  def accept(builder \\ Expr.expr()) do
    expr = Expr.Structs.verdict("accept")
    Expr.add_expr(builder, expr)
  end

  @doc "Drop packets silently"
  @spec drop(Expr.t()) :: Expr.t()
  def drop(builder \\ Expr.expr()) do
    expr = Expr.Structs.verdict("drop")
    Expr.add_expr(builder, expr)
  end

  @doc """
  Reject packets with ICMP error.

  ## Example

      builder |> reject()
      builder |> reject(:tcp_reset)
  """
  @spec reject(Expr.t(), atom()) :: Expr.t()
  def reject(builder \\ Expr.expr(), type \\ :icmp_port_unreachable) do
    expr = case type do
      :tcp_reset -> Expr.Structs.reject("tcp reset")
      :icmp_port_unreachable -> Expr.Structs.reject()
      :icmpx_port_unreachable -> Expr.Structs.reject("icmpx type port-unreachable")
      other -> Expr.Structs.reject(to_string(other))
    end

    Expr.add_expr(builder, expr)
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
      |> tcp()
      |> dport(22)
      |> log("SSH: ")
      |> continue()

      # Apply action and continue
      builder
      |> source_ip("192.168.1.0/24")
      |> set_mark(100)
      |> continue()

  ## Use Cases

  - Logging without terminal verdict
  - Multi-stage packet processing
  - Complex action chains
  - Audit trails with continued filtering
  """
  @spec continue(Expr.t()) :: Expr.t()
  def continue(builder \\ Expr.expr()) do
    expr = Expr.Structs.verdict("continue")
    Expr.add_expr(builder, expr)
  end

  @doc """
  Disable connection tracking for packets.

  Marks packets as untracked, bypassing the connection tracking system.
  This improves performance but disables stateful features.

  ## Example

      # Disable tracking for high-volume traffic
      builder
      |> tcp()
      |> dport(443)
      |> notrack()

      # Skip tracking for local traffic
      builder
      |> source_ip("127.0.0.0/8")
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
  @spec notrack(Expr.t()) :: Expr.t()
  def notrack(builder \\ Expr.expr()) do
    expr = %{"notrack" => nil}
    Expr.add_expr(builder, expr)
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
      |> tcp()
      |> dport(80)
      |> queue_to_userspace(0)

      # Queue with bypass (don't drop on queue full)
      builder
      |> tcp()
      |> dport(443)
      |> queue_to_userspace(1, bypass: true)

      # Queue with fanout
      builder
      |> protocol(:tcp)
      |> queue_to_userspace(0, fanout: true)

  ## Use Cases

  - IDS/IPS integration (Suricata, Snort)
  - Custom packet inspection
  - Deep packet inspection
  - Application-level filtering
  """
  @spec queue_to_userspace(Expr.t(), non_neg_integer(), keyword()) :: Expr.t()
  def queue_to_userspace(builder \\ Expr.expr(), queue_num, opts \\ []) when is_integer(queue_num) and queue_num >= 0 do
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
    Expr.add_expr(builder, expr)
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
      |> tcp()
      |> dport(80)
      |> tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> synproxy()

      # With custom MSS
      builder
      |> tcp()
      |> dport(443)
      |> tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> synproxy(mss: 1460)

      # Full options
      builder
      |> tcp()
      |> dport(22)
      |> tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> synproxy(mss: 1460, wscale: 7, sack_perm: true, timestamp: true)

  ## Use Cases

  - SYN flood DDoS protection
  - High-volume web servers
  - Public-facing services
  - Attack mitigation

  ## WARNING

  - Only use on SYN packets (tcp_flags required)
  - May break some TCP options
  - Backend servers see firewall as client
  """
  @spec synproxy(Expr.t(), keyword()) :: Expr.t()
  def synproxy(builder \\ Expr.expr(), opts \\ []) do
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
    Expr.add_expr(builder, expr)
  end

  @doc """
  Set TCP Maximum Segment Size (MSS).

  Modifies or clamps the TCP MSS option. Useful for fixing PMTU issues
  with PPPoE or VPN connections.

  ## Example

      # Clamp MSS to 1400 (for PPPoE)
      builder
      |> tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> set_tcp_mss(1400)
      |> accept()

      # Clamp to PMTU
      builder
      |> oif("pppoe0")
      |> tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> set_tcp_mss(:pmtu)
      |> accept()

  ## Use Cases

  - PPPoE connections (typically 1492 MTU → 1452 MSS)
  - VPN tunnels with reduced MTU
  - Fixing PMTU black holes
  - WAN interface MSS clamping
  """
  @spec set_tcp_mss(Expr.t(), non_neg_integer() | :pmtu) :: Expr.t()
  def set_tcp_mss(builder \\ Expr.expr(), mss)
  def set_tcp_mss(builder, :pmtu) do
    # TCP MSS clamping to PMTU
    expr = %{
      "mangle" => %{
        "key" => %{"tcp option" => %{"name" => "maxseg", "field" => "size"}},
        "value" => %{"rt" => "mtu"}
      }
    }
    Expr.add_expr(builder, expr)
  end
  def set_tcp_mss(builder, mss) when is_integer(mss) and mss > 0 and mss <= 65535 do
    # TCP MSS clamping to specific value
    expr = %{
      "mangle" => %{
        "key" => %{"tcp option" => %{"name" => "maxseg", "field" => "size"}},
        "value" => mss
      }
    }
    Expr.add_expr(builder, expr)
  end

  @doc """
  Duplicate packet to another interface.

  Sends a copy of the packet to a different interface while the original
  continues normal processing. Used for traffic mirroring and monitoring.

  ## Example

      # Mirror to monitoring interface
      builder
      |> tcp()
      |> dport(443)
      |> duplicate_to("monitor0")
      |> accept()

      # Mirror suspicious traffic to IDS
      builder
      |> source_ip("203.0.113.0/24")
      |> duplicate_to("ids0")
      |> continue()

  ## Use Cases

  - Network traffic monitoring
  - IDS/IPS analysis
  - Traffic analysis and debugging
  - Compliance and auditing
  """
  @spec duplicate_to(Expr.t(), String.t()) :: Expr.t()
  def duplicate_to(builder \\ Expr.expr(), interface) when is_binary(interface) do
    expr = %{"dup" => %{"device" => interface}}
    Expr.add_expr(builder, expr)
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
      |> ct_state([:established])
      |> flow_offload()

      # Named flowtable
      builder
      |> ct_state([:established])
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
  @spec flow_offload(Expr.t(), keyword()) :: Expr.t()
  def flow_offload(builder \\ Expr.expr(), opts \\ []) do
    table = Keyword.get(opts, :table)

    expr = if table do
      %{"flow" => %{"op" => "add", "flowtable" => "@#{table}"}}
    else
      %{"flow" => %{"op" => "offload"}}
    end

    Expr.add_expr(builder, expr)
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
      |> tcp()
      |> dport(22)
      |> jump("ssh_logging")
      |> accept()

      # Complex rule organization
      builder
      |> source_ip("192.168.1.0/24")
      |> jump("internal_rules")

  ## Use Cases

  - Organize complex rulesets into logical chains
  - Reusable rule groups
  - Conditional rule application
  """
  @spec jump(Expr.t(), String.t()) :: Expr.t()
  def jump(builder \\ Expr.expr(), chain_name) when is_binary(chain_name) do
    expr = Expr.Structs.jump(chain_name)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Go to another chain (non-returning jump).

  Transfers control to the specified chain permanently. Unlike jump,
  control never returns to the current chain.

  ## Example

      # Permanent transfer to specialized chain
      builder
      |> tcp()
      |> dport(443)
      |> goto("https_chain")

  ## Difference from jump/1

  - `jump/1`: Returns after chain processing (like a function call)
  - `goto/1`: Never returns (like a goto statement)
  """
  @spec goto(Expr.t(), String.t()) :: Expr.t()
  def goto(builder \\ Expr.expr(), chain_name) when is_binary(chain_name) do
    expr = Expr.Structs.goto(chain_name)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Return from chain.

  Returns control to the calling chain. Only valid in chains that
  were entered via jump (not base chains).

  ## Example

      # In a custom chain, return early
      builder
      |> source_ip("192.168.1.100")
      |> return_from_chain()

      # Continue processing in calling chain
  """
  @spec return_from_chain(Expr.t()) :: Expr.t()
  def return_from_chain(builder \\ Expr.expr()) do
    expr = Expr.Structs.verdict("return")
    Expr.add_expr(builder, expr)
  end

  @doc """
  Redirect to local transparent proxy (TPROXY).

  Redirects packets to a local socket without changing the destination address.
  Used for transparent proxy setups where the proxy needs to see the original
  destination.

  ## Parameters

  - `builder` - Match builder
  - `opts` - Options:
    - `:to` - Port number to redirect to (required)
    - `:addr` - Local IP address to redirect to (optional)
    - `:family` - Address family (`:ipv4` or `:ipv6`, optional)

  ## Examples

      # Redirect HTTP to local transparent proxy on port 8080
      rule()
      |> tcp()
      |> dport(80)
      |> tproxy(to: 8080)
      |> accept()

      # With specific address
      rule()
      |> tcp()
      |> dport(80)
      |> tproxy(to: 8080, addr: "127.0.0.1")

      # IPv6 transparent proxy
      rule()
      |> tcp()
      |> dport(443)
      |> tproxy(to: 8443, addr: "::1", family: :ipv6)

  ## Use Cases

  - Transparent HTTP/HTTPS proxies
  - Deep packet inspection
  - Content filtering
  - Traffic monitoring without changing destinations

  ## Requirements

  - Requires special routing and iptables setup
  - Socket must have IP_TRANSPARENT option
  - Usually combined with socket_transparent() matching
  - Requires CAP_NET_ADMIN capability

  ## Typical Transparent Proxy Setup

      # 1. Mark packets with existing transparent socket
      prerouting_mark = rule()
        |> tcp()
        |> socket_transparent()
        |> set_mark(1)
        |> accept()

      # 2. Redirect unmarked packets to proxy
      prerouting_tproxy = rule()
        |> tcp()
        |> dport(80)
        |> mark(0)
        |> tproxy(to: 8080)

      # 3. Accept marked packets in input
      input_accept = rule()
        |> mark(1)
        |> accept()
  """
  @spec tproxy(Expr.t(), keyword()) :: Expr.t()
  def tproxy(builder \\ Expr.expr(), opts) do
    port = Keyword.fetch!(opts, :to)
    addr = Keyword.get(opts, :addr)
    family = Keyword.get(opts, :family)

    tproxy_map = %{port: port}
    tproxy_map = if addr, do: Map.put(tproxy_map, :addr, addr), else: tproxy_map
    tproxy_map = if family, do: Map.put(tproxy_map, :family, to_string(family)), else: tproxy_map

    expr = %{tproxy: tproxy_map}
    Expr.add_expr(builder, expr)
  end
end
