defmodule NFTablesEx.RuleBuilder.PortMatching do
  @moduledoc """
  Port matching functions for RuleBuilder.

  Provides functions to match TCP and UDP ports, including single ports and port ranges.
  """

  alias NFTablesEx.{RuleBuilder, JsonExpr}

  @doc "Match TCP source port"
  @spec match_source_port(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_source_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = JsonExpr.payload_match("tcp", "sport", port)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc "Match TCP destination port"
  @spec match_dest_port(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_dest_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = JsonExpr.payload_match("tcp", "dport", port)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc "Match UDP source port"
  @spec match_udp_sport(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_udp_sport(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = JsonExpr.payload_match("udp", "sport", port)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc "Match UDP destination port"
  @spec match_udp_dport(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_udp_dport(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = JsonExpr.payload_match("udp", "dport", port)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match TCP port range.

  ## Example

      # Match high ports (1024-65535)
      builder |> match_port_range(1024, 65535)

      # Match specific range
      builder |> match_port_range(8000, 9000)
  """
  @spec match_port_range(RuleBuilder.t(), non_neg_integer(), non_neg_integer()) :: RuleBuilder.t()
  def match_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    expr = JsonExpr.payload_match("tcp", "dport", {:range, min_port, max_port})
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match TCP source port range.

  ## Example

      builder |> match_source_port_range(1024, 65535)
  """
  @spec match_source_port_range(RuleBuilder.t(), non_neg_integer(), non_neg_integer()) :: RuleBuilder.t()
  def match_source_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    expr = JsonExpr.payload_match("tcp", "sport", {:range, min_port, max_port})
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match UDP port range.

  ## Example

      # Match RTP media range
      builder |> match_udp_port_range(10000, 20000)
  """
  @spec match_udp_port_range(RuleBuilder.t(), non_neg_integer(), non_neg_integer()) :: RuleBuilder.t()
  def match_udp_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    expr = JsonExpr.payload_match("udp", "dport", {:range, min_port, max_port})
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match UDP source port range.

  ## Example

      builder |> match_udp_source_port_range(1024, 65535)
  """
  @spec match_udp_source_port_range(RuleBuilder.t(), non_neg_integer(), non_neg_integer()) :: RuleBuilder.t()
  def match_udp_source_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    expr = JsonExpr.payload_match("udp", "sport", {:range, min_port, max_port})
    RuleBuilder.add_expr(builder, expr)
  end
end
