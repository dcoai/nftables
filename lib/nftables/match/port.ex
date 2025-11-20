defmodule NFTables.Match.Port do
  @moduledoc """
  Port matching functions for Match.

  Provides protocol-agnostic port matching for TCP, UDP, SCTP, and DCCP.
  The protocol context is determined by earlier protocol calls (tcp(), udp(),
  sctp(), or dccp()) in the match chain.

  Supports both single ports and port ranges using Elixir ranges.

  ## Examples

      # TCP port matching
      rule() |> tcp() |> dport(80)
      rule() |> tcp() |> sport(1024)

      # UDP port matching
      rule() |> udp() |> dport(53)
      rule() |> udp() |> sport(5353)

      # SCTP port matching
      rule() |> sctp() |> dport(9899)
      rule() |> sctp() |> sport(5000)

      # DCCP port matching
      rule() |> dccp() |> dport(6000)

      # Port ranges (all protocols)
      rule() |> tcp() |> dport(8000..9000)
      rule() |> sctp() |> sport(1024..65535)
  """

  alias NFTables.{Match, Expr}

  @doc """
  Match destination port.

  Works with TCP, UDP, SCTP, and DCCP based on the protocol context set by
  tcp(), udp(), sctp(), or dccp(). Supports single ports (integer) or port
  ranges (Range).

  ## Examples

      # Single port
      rule() |> tcp() |> dport(80)
      rule() |> udp() |> dport(53)
      rule() |> sctp() |> dport(9899)
      rule() |> dccp() |> dport(6000)

      # Port range
      rule() |> tcp() |> dport(8000..9000)
      rule() |> sctp() |> dport(1024..65535)

  ## Errors

  Raises ArgumentError if called without a protocol context (tcp/udp/sctp/dccp).
  """
  @spec dport(Match.t(), non_neg_integer() | Range.t()) :: Match.t()
  def dport(builder, port) when is_integer(port) do
    protocol = get_protocol!(builder, "dport")
    validate_port!(port)
    expr = Expr.payload_match(protocol, "dport", port)
    Match.add_expr(builder, expr)
  end

  def dport(builder, first..last//_ = _range) do
    protocol = get_protocol!(builder, "dport")
    validate_port!(first)
    validate_port!(last)

    if first > last do
      raise ArgumentError, "Invalid port range: #{first}..#{last} (first must be <= last)"
    end

    expr = Expr.payload_match_range(protocol, "dport", first, last)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match source port.

  Works with TCP, UDP, SCTP, and DCCP based on the protocol context set by
  tcp(), udp(), sctp(), or dccp(). Supports single ports (integer) or port
  ranges (Range).

  ## Examples

      # Single port
      rule() |> tcp() |> sport(1024)
      rule() |> udp() |> sport(5353)
      rule() |> sctp() |> sport(5000)
      rule() |> dccp() |> sport(4000)

      # Port range
      rule() |> tcp() |> sport(1024..65535)
      rule() |> udp() |> sport(10000..20000)

  ## Errors

  Raises ArgumentError if called without tcp() or udp() first.
  """
  @spec sport(Match.t(), non_neg_integer() | Range.t()) :: Match.t()
  def sport(builder, port) when is_integer(port) do
    protocol = get_protocol!(builder, "sport")
    validate_port!(port)
    expr = Expr.payload_match(protocol, "sport", port)
    Match.add_expr(builder, expr)
  end

  def sport(builder, first..last//_ = _range) do
    protocol = get_protocol!(builder, "sport")
    validate_port!(first)
    validate_port!(last)

    if first > last do
      raise ArgumentError, "Invalid port range: #{first}..#{last} (first must be <= last)"
    end

    expr = Expr.payload_match_range(protocol, "sport", first, last)
    Match.add_expr(builder, expr)
  end

  @doc """
  Alias for dport/2. Match destination port.

  ## Examples

      rule() |> tcp() |> dst_port(443)
      rule() |> udp() |> dst_port(53)
  """
  @spec dst_port(Match.t(), non_neg_integer() | Range.t()) :: Match.t()
  def dst_port(builder, port), do: dport(builder, port)

  @doc """
  Alias for sport/2. Match source port.

  ## Examples

      rule() |> tcp() |> src_port(1024)
      rule() |> tcp() |> src_port(1024..65535)
  """
  @spec src_port(Match.t(), non_neg_integer() | Range.t()) :: Match.t()
  def src_port(builder, port), do: sport(builder, port)

  # Private helpers

  defp get_protocol!(builder, function_name) do
    case builder.protocol do
      nil ->
        raise ArgumentError,
              "#{function_name}/2 requires protocol context. Call tcp(), udp(), sctp(), or dccp() before using #{function_name}/2.\n\n" <>
              "Example: rule() |> tcp() |> #{function_name}(80)"

      protocol when protocol in [:tcp, :udp, :sctp, :dccp] ->
        to_string(protocol)

      other ->
        raise ArgumentError,
              "#{function_name}/2 requires a protocol with port fields (tcp, udp, sctp, dccp), got: #{inspect(other)}\n\n" <>
              "Use tcp(), udp(), sctp(), or dccp() before calling #{function_name}/2."
    end
  end

  defp validate_port!(port) when is_integer(port) and port >= 0 and port <= 65535, do: :ok
  defp validate_port!(port) when is_integer(port) do
    raise ArgumentError, "Port must be between 0 and 65535, got: #{port}"
  end
end
