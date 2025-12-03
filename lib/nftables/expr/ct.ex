defmodule NFTables.Expr.CT do
  @moduledoc """
  Connection tracking (CT) matching functions for Expr.

  Provides functions for matching based on connection tracking state, status,
  direction, labels, zones, helpers, and other CT-related attributes.
  """

  alias NFTables.Expr

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
  @spec ct_state(Expr.t(), list(atom())) :: Expr.t()
  def ct_state(builder \\ Expr.expr(), states) when is_list(states) do
    state_list = Enum.map(states, &to_string/1)
    expr = Expr.Structs.ct_match("state", state_list)
    Expr.add_expr(builder, expr)
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
  @spec ct_status(Expr.t(), list(atom())) :: Expr.t()
  def ct_status(builder \\ Expr.expr(), statuses) when is_list(statuses) do
    status_list = Enum.map(statuses, &to_string/1)
    expr = Expr.Structs.ct_match("status", status_list)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking direction.

  ## Example

      # Match original direction (outgoing)
      builder |> ct_direction(:original)

      # Match reply direction (incoming)
      builder |> ct_direction(:reply)
  """
  @spec ct_direction(Expr.t(), atom()) :: Expr.t()
  def ct_direction(builder \\ Expr.expr(), direction) when direction in [:original, :reply] do
    expr = Expr.Structs.ct_match("direction", to_string(direction))
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match connection mark.

  Connection marks are persistent across packets in a connection.

  ## Example

      builder |> connmark(42)
  """
  @spec connmark(Expr.t(), non_neg_integer()) :: Expr.t()
  def connmark(builder \\ Expr.expr(), mark) when is_integer(mark) and mark >= 0 do
    expr = Expr.Structs.ct_match("mark", mark)
    Expr.add_expr(builder, expr)
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
  @spec ct_label(Expr.t(), String.t() | non_neg_integer()) :: Expr.t()
  def ct_label(builder \\ Expr.expr(), label) when is_binary(label) or is_integer(label) do
    expr = Expr.Structs.ct_match("label", label)
    Expr.add_expr(builder, expr)
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
  @spec ct_zone(Expr.t(), non_neg_integer()) :: Expr.t()
  def ct_zone(builder \\ Expr.expr(), zone) when is_integer(zone) and zone >= 0 do
    expr = Expr.Structs.ct_match("zone", zone)
    Expr.add_expr(builder, expr)
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
  @spec ct_helper(Expr.t(), String.t()) :: Expr.t()
  def ct_helper(builder \\ Expr.expr(), helper) when is_binary(helper) do
    expr = Expr.Structs.ct_match("helper", helper)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match connection byte count.

  ## Example

      # Block connections exceeding 1GB
      builder |> ct_bytes(:gt, 1_000_000_000) |> drop()

      # Match large downloads
      builder |> ct_bytes(:ge, 100_000_000) |> log("BIG-DL: ")
  """
  @spec ct_bytes(Expr.t(), atom(), non_neg_integer()) :: Expr.t()
  def ct_bytes(builder \\ Expr.expr(), op, bytes) when is_integer(bytes) and bytes >= 0 do
    op_str = atom_to_op(op)
    expr = Expr.Structs.ct_match("bytes", bytes, op_str)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match connection packet count.

  ## Example

      # Match connections with many packets
      builder |> ct_packets(:gt, 10000) |> log("HIGH-PKT: ")

      # Block after packet limit
      builder |> ct_packets(:ge, 50000) |> drop()
  """
  @spec ct_packets(Expr.t(), atom(), non_neg_integer()) :: Expr.t()
  def ct_packets(builder \\ Expr.expr(), op, packets) when is_integer(packets) and packets >= 0 do
    op_str = atom_to_op(op)
    expr = Expr.Structs.ct_match("packets", packets, op_str)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match original (pre-NAT) source address.

  ## Example

      # Match original source before SNAT
      builder |> ct_original_saddr("192.168.1.100") |> accept()

      # Track pre-NAT source
      builder |> ct_original_saddr("10.0.0.0/8") |> log("INTERNAL: ")
  """
  @spec ct_original_saddr(Expr.t(), String.t()) :: Expr.t()
  def ct_original_saddr(builder \\ Expr.expr(), addr) when is_binary(addr) do
    # CT original address requires special structure
    expr = %{
      "match" => %{
        "left" => %{"ct" => %{"key" => "ip saddr", "dir" => "original"}},
        "right" => addr,
        "op" => "=="
      }
    }
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match original (pre-NAT) destination address.

  ## Example

      # Match original destination before DNAT
      builder |> ct_original_daddr("203.0.113.100") |> accept()
  """
  @spec ct_original_daddr(Expr.t(), String.t()) :: Expr.t()
  def ct_original_daddr(builder \\ Expr.expr(), addr) when is_binary(addr) do
    # CT original address requires special structure
    expr = %{
      "match" => %{
        "left" => %{"ct" => %{"key" => "ip daddr", "dir" => "original"}},
        "right" => addr,
        "op" => "=="
      }
    }
    Expr.add_expr(builder, expr)
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
  @spec limit_connections(Expr.t(), non_neg_integer()) :: Expr.t()
  def limit_connections(builder \\ Expr.expr(), count) when is_integer(count) and count > 0 do
    expr = Expr.Structs.ct_match("count", count)
    Expr.add_expr(builder, expr)
  end

  # Helper to convert atom operators to string
  defp atom_to_op(:eq), do: "=="
  defp atom_to_op(:ne), do: "!="
  defp atom_to_op(:lt), do: "<"
  defp atom_to_op(:gt), do: ">"
  defp atom_to_op(:le), do: "<="
  defp atom_to_op(:ge), do: ">="
end
