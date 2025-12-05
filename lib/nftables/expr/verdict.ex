defmodule NFTables.Expr.Verdict do
  @moduledoc """
  Verdict and control flow functions for Expr.

  Provides terminal verdicts (accept, drop, reject), non-terminal actions (continue, notrack),
  advanced features (queue, flow offload), and chain control flow (jump, goto, return).
  Verdicts determine the final fate of packets and control how rules are processed.

  ## Import

      import NFTables.Expr.Verdict

  ## Examples

      # Basic verdicts
      tcp() |> dport(22) |> accept()
      source_ip("10.0.0.0/8") |> drop()
      tcp() |> dport(23) |> reject(:tcp_reset)

      # Non-terminal actions
      tcp() |> dport(80) |> log("HTTP: ") |> continue()
      tcp() |> dport(443) |> notrack() |> accept()

      # Chain control flow
      source_ip("192.168.1.0/24") |> jump("trusted_chain")
      tcp() |> dport(8080) |> goto("app_chain")

      # Advanced features
      tcp() |> dport(80) |> tcp_flags([:syn], [:syn, :ack, :rst, :fin]) |> synproxy()
      ct_state([:established]) |> flow_offload()

  For more information, see the [nftables verdicts wiki](https://wiki.nftables.org/wiki-nftables/index.php/Verdicts).
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
    expr =
      case type do
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
  def queue_to_userspace(builder \\ Expr.expr(), queue_num, opts \\ [])
      when is_integer(queue_num) and queue_num >= 0 do
    bypass = Keyword.get(opts, :bypass, false)
    fanout = Keyword.get(opts, :fanout, false)

    queue_expr = %{"num" => queue_num}

    flags = []
    flags = if bypass, do: ["bypass" | flags], else: flags
    flags = if fanout, do: ["fanout" | flags], else: flags

    queue_expr =
      if not Enum.empty?(flags) do
        Map.put(queue_expr, "flags", Enum.join(flags, ","))
      else
        queue_expr
      end

    expr = %{"queue" => queue_expr}
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

    expr =
      if table do
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

end
