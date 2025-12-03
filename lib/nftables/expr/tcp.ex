defmodule NFTables.Expr.TCP do
  @moduledoc """
  TCP and protocol matching functions for Expr.

  Provides functions for TCP flags, packet length, TTL, hop limit, and protocol matching.
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
  Match packet length.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Example

      # Start a new expression
      length(:gt, 1000)

      # Continue an existing expression
      builder |> length(:gt, 1000)

      # Match packets exactly 64 bytes
      builder |> length(:eq, 64)
  """
  @spec length(Expr.t(), atom(), non_neg_integer()) :: Expr.t()
  def length(builder \\ Expr.expr(), op, length) when is_integer(length) and length >= 0 do
    op_str = atom_to_op(op)
    expr = Expr.Structs.meta_match("length", length, op_str)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match IP TTL (time to live).

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Example

      # Start a new expression
      ttl(:eq, 1)

      # Continue an existing expression and chain
      builder |> ttl(:eq, 1) |> drop()

      # Match packets with TTL > 64
      builder |> ttl(:gt, 64)
  """
  @spec ttl(Expr.t(), atom(), non_neg_integer()) :: Expr.t()
  def ttl(builder \\ Expr.expr(), op, ttl) when is_integer(ttl) and ttl >= 0 and ttl <= 255 do
    op_str = atom_to_op(op)
    expr = Expr.Structs.payload_match("ip", "ttl", ttl, op_str)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match IPv6 hop limit.

  IPv6 equivalent of TTL (Time To Live).

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Example

      # Start a new expression
      hoplimit(:eq, 1)

      # Continue an existing expression and chain
      builder |> hoplimit(:eq, 1) |> drop()

      # Block low hop limit (potential spoofing)
      builder |> hoplimit(:lt, 10) |> drop()

  ## Use Cases

  - IPv6 traceroute blocking
  - Anti-spoofing (low hop limits)
  - TTL normalization checks
  """
  @spec hoplimit(Expr.t(), atom(), non_neg_integer()) :: Expr.t()
  def hoplimit(builder \\ Expr.expr(), op, hoplimit) when is_integer(hoplimit) and hoplimit >= 0 and hoplimit <= 255 do
    op_str = atom_to_op(op)
    expr = Expr.Structs.payload_match("ip6", "hoplimit", hoplimit, op_str)
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

  # Helper to convert atom operators to string
  defp atom_to_op(:eq), do: "=="
  defp atom_to_op(:ne), do: "!="
  defp atom_to_op(:lt), do: "<"
  defp atom_to_op(:gt), do: ">"
  defp atom_to_op(:le), do: "<="
  defp atom_to_op(:ge), do: ">="
end
