defmodule NFTables.Match.TCP do
  @moduledoc """
  TCP and protocol matching functions for Match.

  Provides functions for TCP flags, packet length, TTL, hop limit, and protocol matching.
  """

  alias NFTables.{Match, Expr}

  @doc """
  Match TCP flags.

  ## Flags
  - `:syn` - Synchronize
  - `:ack` - Acknowledgment
  - `:fin` - Finish
  - `:rst` - Reset
  - `:psh` - Push
  - `:urg` - Urgent

  ## Example

      # Match SYN packets (new connections)
      builder |> tcp_flags([:syn], [:syn, :ack, :rst, :fin])

      # Match SYN-ACK
      builder |> tcp_flags([:syn, :ack], [:syn, :ack, :rst, :fin])
  """
  @spec tcp_flags(Match.t(), list(atom()), list(atom())) :: Match.t()
  def tcp_flags(builder, flags, mask) when is_list(flags) and is_list(mask) do
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
    Match.add_expr(builder, expr)
  end

  @doc """
  Match packet length.

  ## Example

      # Match packets larger than 1000 bytes
      builder |> length(:gt, 1000)

      # Match packets exactly 64 bytes
      builder |> length(:eq, 64)
  """
  @spec length(Match.t(), atom(), non_neg_integer()) :: Match.t()
  def length(builder, op, length) when is_integer(length) and length >= 0 do
    op_str = atom_to_op(op)
    expr = Expr.meta_match("length", length, op_str)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match IP TTL (time to live).

  ## Example

      # Drop packets with TTL = 1 (traceroute)
      builder |> ttl(:eq, 1) |> drop()

      # Match packets with TTL > 64
      builder |> ttl(:gt, 64)
  """
  @spec ttl(Match.t(), atom(), non_neg_integer()) :: Match.t()
  def ttl(builder, op, ttl) when is_integer(ttl) and ttl >= 0 and ttl <= 255 do
    op_str = atom_to_op(op)
    expr = Expr.payload_match("ip", "ttl", ttl, op_str)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match IPv6 hop limit.

  IPv6 equivalent of TTL (Time To Live).

  ## Example

      # Drop packets with hop limit = 1 (traceroute)
      builder |> hoplimit(:eq, 1) |> drop()

      # Block low hop limit (potential spoofing)
      builder |> hoplimit(:lt, 10) |> drop()

  ## Use Cases

  - IPv6 traceroute blocking
  - Anti-spoofing (low hop limits)
  - TTL normalization checks
  """
  @spec hoplimit(Match.t(), atom(), non_neg_integer()) :: Match.t()
  def hoplimit(builder, op, hoplimit) when is_integer(hoplimit) and hoplimit >= 0 and hoplimit <= 255 do
    op_str = atom_to_op(op)
    expr = Expr.payload_match("ip6", "hoplimit", hoplimit, op_str)
    Match.add_expr(builder, expr)
  end

  @doc "Match protocol"
  @spec protocol(Match.t(), atom() | String.t()) :: Match.t()
  def protocol(builder, protocol) do
    protocol_atom = if is_binary(protocol), do: String.to_atom(protocol), else: protocol
    protocol_str = if is_atom(protocol), do: to_string(protocol), else: protocol
    expr = Expr.payload_match("ip", "protocol", protocol_str)

    builder
    |> Match.add_expr(expr)
    |> Match.set_protocol(protocol_atom)
  end

  # Helper to convert atom operators to string
  defp atom_to_op(:eq), do: "=="
  defp atom_to_op(:ne), do: "!="
  defp atom_to_op(:lt), do: "<"
  defp atom_to_op(:gt), do: ">"
  defp atom_to_op(:le), do: "<="
  defp atom_to_op(:ge), do: ">="
end
