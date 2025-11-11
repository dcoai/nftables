defmodule NFTablesEx.RuleBuilder.TCPMatching do
  @moduledoc """
  TCP and protocol matching functions for RuleBuilder.

  Provides functions for TCP flags, packet length, TTL, hop limit, and protocol matching.
  """

  alias NFTablesEx.{RuleBuilder, JsonExpr}

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
      builder |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])

      # Match SYN-ACK
      builder |> match_tcp_flags([:syn, :ack], [:syn, :ack, :rst, :fin])
  """
  @spec match_tcp_flags(RuleBuilder.t(), list(atom()), list(atom())) :: RuleBuilder.t()
  def match_tcp_flags(builder, flags, mask) when is_list(flags) and is_list(mask) do
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
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match packet length.

  ## Example

      # Match packets larger than 1000 bytes
      builder |> match_length(:gt, 1000)

      # Match packets exactly 64 bytes
      builder |> match_length(:eq, 64)
  """
  @spec match_length(RuleBuilder.t(), atom(), non_neg_integer()) :: RuleBuilder.t()
  def match_length(builder, op, length) when is_integer(length) and length >= 0 do
    op_str = atom_to_op(op)
    expr = JsonExpr.meta_match("length", length, op_str)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match IP TTL (time to live).

  ## Example

      # Drop packets with TTL = 1 (traceroute)
      builder |> match_ttl(:eq, 1) |> drop()

      # Match packets with TTL > 64
      builder |> match_ttl(:gt, 64)
  """
  @spec match_ttl(RuleBuilder.t(), atom(), non_neg_integer()) :: RuleBuilder.t()
  def match_ttl(builder, op, ttl) when is_integer(ttl) and ttl >= 0 and ttl <= 255 do
    op_str = atom_to_op(op)
    expr = JsonExpr.payload_match("ip", "ttl", ttl, op_str)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match IPv6 hop limit.

  IPv6 equivalent of TTL (Time To Live).

  ## Example

      # Drop packets with hop limit = 1 (traceroute)
      builder |> match_hoplimit(:eq, 1) |> drop()

      # Block low hop limit (potential spoofing)
      builder |> match_hoplimit(:lt, 10) |> drop()

  ## Use Cases

  - IPv6 traceroute blocking
  - Anti-spoofing (low hop limits)
  - TTL normalization checks
  """
  @spec match_hoplimit(RuleBuilder.t(), atom(), non_neg_integer()) :: RuleBuilder.t()
  def match_hoplimit(builder, op, hoplimit) when is_integer(hoplimit) and hoplimit >= 0 and hoplimit <= 255 do
    op_str = atom_to_op(op)
    expr = JsonExpr.payload_match("ip6", "hoplimit", hoplimit, op_str)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc "Match protocol"
  @spec match_protocol(RuleBuilder.t(), atom() | String.t()) :: RuleBuilder.t()
  def match_protocol(builder, protocol) do
    protocol_str = if is_atom(protocol), do: to_string(protocol), else: protocol
    expr = JsonExpr.payload_match("ip", "protocol", protocol_str)
    RuleBuilder.add_expr(builder, expr)
  end

  # Helper to convert atom operators to string
  defp atom_to_op(:eq), do: "=="
  defp atom_to_op(:ne), do: "!="
  defp atom_to_op(:lt), do: "<"
  defp atom_to_op(:gt), do: ">"
  defp atom_to_op(:le), do: "<="
  defp atom_to_op(:ge), do: ">="
end
