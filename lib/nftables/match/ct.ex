defmodule NFTables.Match.CT do
  @moduledoc """
  Connection tracking (CT) matching functions for Match.

  Provides functions for matching based on connection tracking state, status,
  direction, labels, zones, helpers, and other CT-related attributes.
  """

  alias NFTables.{Match, Expr}

  @doc """
  Match connection tracking state.

  ## States

  - `:invalid` - Invalid connection
  - `:established` - Established connection
  - `:related` - Related to existing connection
  - `:new` - New connection
  - `:untracked` - Untracked connection

  ## Example

      builder |> ct_state([:established, :related])
  """
  @spec ct_state(Match.t(), list(atom())) :: Match.t()
  def ct_state(builder, states) when is_list(states) do
    state_list = Enum.map(states, &to_string/1)
    expr = Expr.ct_match("state", state_list)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking status.

  ## Statuses
  - `:expected` - Connection is expected
  - `:seen_reply` - Packets seen in both directions
  - `:assured` - Connection is assured (will not be deleted on timeout)
  - `:confirmed` - Connection is confirmed
  - `:snat` - Source NAT applied
  - `:dnat` - Destination NAT applied
  - `:dying` - Connection is dying

  ## Example

      # Match assured connections
      builder |> ct_status([:assured])

      # Match NATed connections
      builder |> ct_status([:snat])
  """
  @spec ct_status(Match.t(), list(atom())) :: Match.t()
  def ct_status(builder, statuses) when is_list(statuses) do
    status_list = Enum.map(statuses, &to_string/1)
    expr = Expr.ct_match("status", status_list)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking direction.

  ## Example

      # Match original direction (outgoing)
      builder |> ct_direction(:original)

      # Match reply direction (incoming)
      builder |> ct_direction(:reply)
  """
  @spec ct_direction(Match.t(), atom()) :: Match.t()
  def ct_direction(builder, direction) when direction in [:original, :reply] do
    expr = Expr.ct_match("direction", to_string(direction))
    Match.add_expr(builder, expr)
  end

  @doc """
  Match connection mark.

  Connection marks are persistent across packets in a connection.

  ## Example

      builder |> connmark(42)
  """
  @spec connmark(Match.t(), non_neg_integer()) :: Match.t()
  def connmark(builder, mark) when is_integer(mark) and mark >= 0 do
    expr = Expr.ct_match("mark", mark)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking label.

  CT labels are 128-bit bitmaps for complex stateful tracking.

  ## Example

      # Match connections labeled as suspicious
      builder |> ct_label("suspicious") |> drop()

      # Match numeric label bit
      builder |> ct_label(5) |> log("LABELED: ")
  """
  @spec ct_label(Match.t(), String.t() | non_neg_integer()) :: Match.t()
  def ct_label(builder, label) when is_binary(label) or is_integer(label) do
    expr = Expr.ct_match("label", label)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking zone.

  CT zones provide isolation for multi-tenant or namespace scenarios.

  ## Example

      # Match zone 1
      builder |> ct_zone(1) |> accept()

      # Match zone for specific tenant
      builder |> ct_zone(100) |> jump("tenant_100")
  """
  @spec ct_zone(Match.t(), non_neg_integer()) :: Match.t()
  def ct_zone(builder, zone) when is_integer(zone) and zone >= 0 do
    expr = Expr.ct_match("zone", zone)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking helper.

  Matches connections assigned to a specific CT helper (FTP, SIP, etc.).

  ## Example

      # Match FTP connections
      builder |> ct_helper("ftp") |> accept()

      # Match SIP connections
      builder |> ct_helper("sip") |> log("SIP: ")
  """
  @spec ct_helper(Match.t(), String.t()) :: Match.t()
  def ct_helper(builder, helper) when is_binary(helper) do
    expr = Expr.ct_match("helper", helper)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match connection byte count.

  ## Example

      # Block connections exceeding 1GB
      builder |> ct_bytes(:gt, 1_000_000_000) |> drop()

      # Match large downloads
      builder |> ct_bytes(:ge, 100_000_000) |> log("BIG-DL: ")
  """
  @spec ct_bytes(Match.t(), atom(), non_neg_integer()) :: Match.t()
  def ct_bytes(builder, op, bytes) when is_integer(bytes) and bytes >= 0 do
    op_str = atom_to_op(op)
    expr = Expr.ct_match("bytes", bytes, op_str)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match connection packet count.

  ## Example

      # Match connections with many packets
      builder |> ct_packets(:gt, 10000) |> log("HIGH-PKT: ")

      # Block after packet limit
      builder |> ct_packets(:ge, 50000) |> drop()
  """
  @spec ct_packets(Match.t(), atom(), non_neg_integer()) :: Match.t()
  def ct_packets(builder, op, packets) when is_integer(packets) and packets >= 0 do
    op_str = atom_to_op(op)
    expr = Expr.ct_match("packets", packets, op_str)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match original (pre-NAT) source address.

  ## Example

      # Match original source before SNAT
      builder |> ct_original_saddr("192.168.1.100") |> accept()

      # Track pre-NAT source
      builder |> ct_original_saddr("10.0.0.0/8") |> log("INTERNAL: ")
  """
  @spec ct_original_saddr(Match.t(), String.t()) :: Match.t()
  def ct_original_saddr(builder, addr) when is_binary(addr) do
    # CT original address requires special structure
    expr = %{
      "match" => %{
        "left" => %{"ct" => %{"key" => "ip saddr", "dir" => "original"}},
        "right" => addr,
        "op" => "=="
      }
    }
    Match.add_expr(builder, expr)
  end

  @doc """
  Match original (pre-NAT) destination address.

  ## Example

      # Match original destination before DNAT
      builder |> ct_original_daddr("203.0.113.100") |> accept()
  """
  @spec ct_original_daddr(Match.t(), String.t()) :: Match.t()
  def ct_original_daddr(builder, addr) when is_binary(addr) do
    # CT original address requires special structure
    expr = %{
      "match" => %{
        "left" => %{"ct" => %{"key" => "ip daddr", "dir" => "original"}},
        "right" => addr,
        "op" => "=="
      }
    }
    Match.add_expr(builder, expr)
  end

  @doc """
  Limit number of connections per source IP.

  ## Example

      # Limit to 10 concurrent connections per IP
      builder
      |> tcp()
      |> dport(80)
      |> ct_state([:new])
      |> limit_connections(10)
      |> reject()

      # Limit SSH connections per IP
      builder
      |> tcp()
      |> dport(22)
      |> ct_state([:new])
      |> limit_connections(3)
      |> drop()
  """
  @spec limit_connections(Match.t(), non_neg_integer()) :: Match.t()
  def limit_connections(builder, count) when is_integer(count) and count > 0 do
    expr = Expr.ct_match("count", count)
    Match.add_expr(builder, expr)
  end

  # Helper to convert atom operators to string
  defp atom_to_op(:eq), do: "=="
  defp atom_to_op(:ne), do: "!="
  defp atom_to_op(:lt), do: "<"
  defp atom_to_op(:gt), do: ">"
  defp atom_to_op(:le), do: "<="
  defp atom_to_op(:ge), do: ">="
end
