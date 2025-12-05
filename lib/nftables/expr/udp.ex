defmodule NFTables.Expr.UDP do
  @moduledoc """
  UDP protocol matching functions for Expr.

  Provides the UDP protocol matcher for rule expressions. Works with port
  matching functions from the Port module.

  ## Import

      import NFTables.Expr.UDP

  ## Examples

      # Match UDP traffic
      udp() |> accept()

      # UDP with destination port
      udp() |> dport(53) |> accept()

      # UDP with port range
      udp() |> dport(10000..20000) |> accept()

  For more information, see the [nftables payload expressions wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers).
  """

  alias NFTables.Expr

  @doc """
  Match UDP protocol.

  Sets the protocol context to UDP, allowing subsequent port matching with
  dport/sport from the Port module.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Examples

      # Start a new expression
      udp()

      # Continue an existing expression
      builder |> udp() |> dport(53)

      # UDP DNS query
      udp() |> dport(53) |> accept()

  ## Protocol Context

  After calling this function, the expression's protocol context is set to `:udp`,
  enabling port matching functions to work correctly.
  """
  @spec udp(Expr.t()) :: Expr.t()
  def udp(builder \\ Expr.expr()) do
    expr = Expr.Structs.payload_match("ip", "protocol", "udp")

    builder
    |> Expr.add_expr(expr)
    |> Expr.set_protocol(:udp)
  end
end
