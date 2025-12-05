defmodule NFTables.Expr.TCP do
  @moduledoc """
  TCP protocol matching functions for Expr.

  Provides functions for TCP-specific matching (flags, protocol).

  ## Import

      import NFTables.Expr.TCP

  ## Examples

      # TCP with SYN flag
      tcp() |> tcp_flags([:syn], [:syn, :ack, :rst, :fin]) |> accept()

      # TCP with ports
      tcp() |> dport(22) |> accept()

      # General protocol matching
      protocol(:tcp) |> dport(80)

  For more information, see the [nftables TCP wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_TCP_options_and_flags).
  """

  alias NFTables.Expr

  @doc """
  Match TCP flags.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Flags
  - `:syn` - Synchronize
  - `:ack` - Acknowledgment
  - `:fin` - Finish
  - `:rst` - Reset
  - `:psh` - Push
  - `:urg` - Urgent

  ## Example

      # Start a new expression
      tcp_flags([:syn], [:syn, :ack, :rst, :fin])

      # Continue an existing expression
      builder |> tcp_flags([:syn], [:syn, :ack, :rst, :fin])

      # Match SYN-ACK
      builder |> tcp_flags([:syn, :ack], [:syn, :ack, :rst, :fin])
  """
  @spec tcp_flags(Expr.t(), list(atom()), list(atom())) :: Expr.t()
  def tcp_flags(builder \\ Expr.expr(), flags, mask) when is_list(flags) and is_list(mask) do
    flags_list = Enum.map(flags, &to_string/1)
    mask_list = Enum.map(mask, &to_string/1)

    # Build JSON expression for TCP flags
    expr = %{
      "match" => %{
        "left" => %{
          "&" => [
            %{"payload" => %{"protocol" => "tcp", "field" => "flags"}},
            mask_list
          ]
        },
        "right" => flags_list,
        "op" => "=="
      }
    }

    Expr.add_expr(builder, expr)
  end

  @doc """
  Match protocol.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Example

      # Start a new expression
      protocol(:tcp)

      # Continue an existing expression
      builder |> protocol(:tcp)

      # Using string
      builder |> protocol("udp")
  """
  @spec protocol(Expr.t(), atom() | String.t()) :: Expr.t()
  def protocol(builder \\ Expr.expr(), protocol) do
    protocol_atom = if is_binary(protocol), do: String.to_atom(protocol), else: protocol
    protocol_str = if is_atom(protocol), do: to_string(protocol), else: protocol
    expr = Expr.Structs.payload_match("ip", "protocol", protocol_str)

    builder
    |> Expr.add_expr(expr)
    |> Expr.set_protocol(protocol_atom)
  end

  @doc """
  Match TCP protocol. Convenience for `protocol(:tcp)`.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Example

      # Start a new expression
      tcp()

      # Continue an existing expression
      builder |> tcp() |> dport(22)
  """
  @spec tcp(Expr.t()) :: Expr.t()
  def tcp(builder \\ Expr.expr()), do: protocol(builder, :tcp)
end
