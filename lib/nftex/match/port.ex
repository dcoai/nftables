defmodule NFTablesEx.Match.Port do
  @moduledoc """
  Port matching functions for Match.

  Provides functions to match TCP and UDP ports, including single ports and port ranges.
  """

  alias NFTablesEx.{Match, JsonExpr}

  @doc "Match TCP source port"
  @spec source_port(Match.t(), non_neg_integer()) :: Match.t()
  def source_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = JsonExpr.payload_match("tcp", "sport", port)
    Match.add_expr(builder, expr)
  end

  @doc "Match TCP destination port"
  @spec dest_port(Match.t(), non_neg_integer()) :: Match.t()
  def dest_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = JsonExpr.payload_match("tcp", "dport", port)
    Match.add_expr(builder, expr)
  end

  @doc "Match UDP source port"
  @spec udp_sport(Match.t(), non_neg_integer()) :: Match.t()
  def udp_sport(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = JsonExpr.payload_match("udp", "sport", port)
    Match.add_expr(builder, expr)
  end

  @doc "Match UDP destination port"
  @spec udp_dport(Match.t(), non_neg_integer()) :: Match.t()
  def udp_dport(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = JsonExpr.payload_match("udp", "dport", port)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match TCP port range.

  ## Example

      # Match high ports (1024-65535)
      builder |> port_range(1024, 65535)

      # Match specific range
      builder |> port_range(8000, 9000)
  """
  @spec port_range(Match.t(), non_neg_integer(), non_neg_integer()) :: Match.t()
  def port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    expr = JsonExpr.payload_match_range("tcp", "dport", min_port, max_port)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match TCP source port range.

  ## Example

      builder |> source_port_range(1024, 65535)
  """
  @spec source_port_range(Match.t(), non_neg_integer(), non_neg_integer()) :: Match.t()
  def source_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    expr = JsonExpr.payload_match("tcp", "sport", {:range, min_port, max_port})
    Match.add_expr(builder, expr)
  end

  @doc """
  Match UDP port range.

  ## Example

      # Match RTP media range
      builder |> udp_port_range(10000, 20000)
  """
  @spec udp_port_range(Match.t(), non_neg_integer(), non_neg_integer()) :: Match.t()
  def udp_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    expr = JsonExpr.payload_match_range("udp", "dport", min_port, max_port)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match UDP source port range.

  ## Example

      builder |> udp_source_port_range(1024, 65535)
  """
  @spec udp_source_port_range(Match.t(), non_neg_integer(), non_neg_integer()) :: Match.t()
  def udp_source_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    expr = JsonExpr.payload_match("udp", "sport", {:range, min_port, max_port})
    Match.add_expr(builder, expr)
  end
end
