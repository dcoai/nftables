defmodule NFTables.Expr.Metadata do
  @moduledoc """
  Packet metadata matching functions for firewall rules.

  This module provides functions to match various packet metadata attributes such as
  packet marks, DSCP values, fragmentation status, packet types, and priority levels.
  These are useful for QoS, policy routing, and advanced traffic classification.

  ## Common Use Cases

  - Policy routing based on packet marks
  - QoS and traffic prioritization
  - Filtering fragmented packets
  - Blocking broadcast/multicast traffic

  ## Import

      import NFTables.Expr.Metadata

  For more information, see the [nftables meta expressions wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation).
  """

  alias NFTables.Expr

  @doc """
  Match packet mark (SO_MARK).

  Useful for policy routing and traffic control. Marks are set by other firewall
  rules or applications and can be used for advanced routing decisions.

  ## Example

      # Match packets with mark 100
      mark(100) |> accept()

      # Use with policy routing
      mark(100) |> accept()
  """
  @spec mark(Expr.t(), non_neg_integer()) :: Expr.t()
  def mark(builder \\ Expr.expr(), mark) when is_integer(mark) and mark >= 0 do
    expr = Expr.Structs.meta_match("mark", mark)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match DSCP (Differentiated Services Code Point).

  DSCP is used for QoS classification in IPv4 and IPv6 networks.

  ## Example

      # Match expedited forwarding (EF)
      dscp(46) |> accept()

      # Match assured forwarding class 1 (AF11)
      dscp(10) |> accept()
  """
  @spec dscp(Expr.t(), non_neg_integer()) :: Expr.t()
  def dscp(builder \\ Expr.expr(), dscp) when is_integer(dscp) and dscp >= 0 and dscp <= 63 do
    expr = Expr.Structs.payload_match("ip", "dscp", dscp)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match fragmented packets.

  Matches packets based on their fragmentation status. Useful for security
  policies that want to drop fragmented packets or handle them specially.

  ## Example

      # Match and drop fragmented packets
      fragmented(true) |> drop()

      # Match non-fragmented packets
      fragmented(false) |> accept()

      # Security: Drop all fragments (common security policy)
      fragmented(true) |> log("Fragment detected") |> drop()
  """
  @spec fragmented(Expr.t(), boolean()) :: Expr.t()
  def fragmented(builder \\ Expr.expr(), is_fragmented)

  def fragmented(builder, true) do
    # ip frag-off & 0x1fff != 0
    expr = %{
      "match" => %{
        "left" => %{
          "&" => [
            %{"payload" => %{"protocol" => "ip", "field" => "frag-off"}},
            0x1FFF
          ]
        },
        "right" => 0,
        "op" => "!="
      }
    }

    Expr.add_expr(builder, expr)
  end

  def fragmented(builder, false) do
    # ip frag-off & 0x1fff == 0
    expr = %{
      "match" => %{
        "left" => %{
          "&" => [
            %{"payload" => %{"protocol" => "ip", "field" => "frag-off"}},
            0x1FFF
          ]
        },
        "right" => 0,
        "op" => "=="
      }
    }

    Expr.add_expr(builder, expr)
  end

  @doc """
  Match packet type (unicast, broadcast, multicast).

  ## Packet Types

  - `:unicast` - Unicast packet (point-to-point)
  - `:broadcast` - Broadcast packet (all hosts)
  - `:multicast` - Multicast packet (group communication)
  - `:other` - Other packet types

  ## Example

      # Drop broadcast packets
      pkttype(:broadcast) |> drop()

      # Rate limit multicast
      pkttype(:multicast) |> rate_limit(100, :second) |> accept()

      # Allow only unicast
      pkttype(:unicast) |> accept()
  """
  @spec pkttype(Expr.t(), atom()) :: Expr.t()
  def pkttype(builder \\ Expr.expr(), pkttype)
      when pkttype in [:unicast, :broadcast, :multicast, :other] do
    expr = Expr.Structs.meta_match("pkttype", to_string(pkttype))
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match packet priority (SO_PRIORITY).

  Packet priority is used for QoS and traffic shaping. Priority values range
  from 0 (lowest) to higher values (higher priority).

  ## Operators

  - `:eq` - Equal to
  - `:ne` - Not equal to
  - `:lt` - Less than
  - `:gt` - Greater than
  - `:le` - Less than or equal to
  - `:ge` - Greater than or equal to

  ## Example

      # Match high priority traffic
      priority(:gt, 5) |> accept()

      # Match specific priority
      priority(:eq, 7) |> log("PRIO-7")

      # QoS: Lower priority for bulk traffic
      priority(:lt, 2) |> set_dscp(10)
  """
  @spec priority(Expr.t(), atom(), non_neg_integer()) :: Expr.t()
  def priority(builder \\ Expr.expr(), op, priority)
      when is_integer(priority) and priority >= 0 do
    op_str =
      case op do
        :eq -> "=="
        :ne -> "!="
        :lt -> "<"
        :gt -> ">"
        :le -> "<="
        :ge -> ">="
      end

    expr = Expr.Structs.meta_match("priority", priority, op_str)
    Expr.add_expr(builder, expr)
  end
end
