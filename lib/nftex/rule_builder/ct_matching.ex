defmodule NFTablesEx.RuleBuilder.CTMatching do
  @moduledoc """
  Connection tracking (CT) matching functions for RuleBuilder.

  Provides functions for matching based on connection tracking state, status,
  direction, labels, zones, helpers, and other CT-related attributes.
  """

  alias NFTablesEx.{RuleBuilder, JsonExpr}

  @doc """
  Match connection tracking state.

  ## States

  - `:invalid` - Invalid connection
  - `:established` - Established connection
  - `:related` - Related to existing connection
  - `:new` - New connection
  - `:untracked` - Untracked connection

  ## Example

      builder |> match_ct_state([:established, :related])
  """
  @spec match_ct_state(RuleBuilder.t(), list(atom())) :: RuleBuilder.t()
  def match_ct_state(builder, states) when is_list(states) do
    state_list = Enum.map(states, &to_string/1)
    expr = JsonExpr.ct_match("state", state_list)
    RuleBuilder.add_expr(builder, expr)
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
      builder |> match_ct_status([:assured])

      # Match NATed connections
      builder |> match_ct_status([:snat])
  """
  @spec match_ct_status(RuleBuilder.t(), list(atom())) :: RuleBuilder.t()
  def match_ct_status(builder, statuses) when is_list(statuses) do
    status_list = Enum.map(statuses, &to_string/1)
    expr = JsonExpr.ct_match("status", status_list)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking direction.

  ## Example

      # Match original direction (outgoing)
      builder |> match_ct_direction(:original)

      # Match reply direction (incoming)
      builder |> match_ct_direction(:reply)
  """
  @spec match_ct_direction(RuleBuilder.t(), atom()) :: RuleBuilder.t()
  def match_ct_direction(builder, direction) when direction in [:original, :reply] do
    expr = JsonExpr.ct_match("direction", to_string(direction))
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match connection mark.

  Connection marks are persistent across packets in a connection.

  ## Example

      builder |> match_connmark(42)
  """
  @spec match_connmark(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_connmark(builder, mark) when is_integer(mark) and mark >= 0 do
    expr = JsonExpr.ct_match("mark", mark)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking label.

  CT labels are 128-bit bitmaps for complex stateful tracking.

  ## Example

      # Match connections labeled as suspicious
      builder |> match_ct_label("suspicious") |> drop()

      # Match numeric label bit
      builder |> match_ct_label(5) |> log("LABELED: ")
  """
  @spec match_ct_label(RuleBuilder.t(), String.t() | non_neg_integer()) :: RuleBuilder.t()
  def match_ct_label(builder, label) when is_binary(label) or is_integer(label) do
    expr = JsonExpr.ct_match("label", label)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking zone.

  CT zones provide isolation for multi-tenant or namespace scenarios.

  ## Example

      # Match zone 1
      builder |> match_ct_zone(1) |> accept()

      # Match zone for specific tenant
      builder |> match_ct_zone(100) |> jump("tenant_100")
  """
  @spec match_ct_zone(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_ct_zone(builder, zone) when is_integer(zone) and zone >= 0 do
    expr = JsonExpr.ct_match("zone", zone)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match connection tracking helper.

  Matches connections assigned to a specific CT helper (FTP, SIP, etc.).

  ## Example

      # Match FTP connections
      builder |> match_ct_helper("ftp") |> accept()

      # Match SIP connections
      builder |> match_ct_helper("sip") |> log("SIP: ")
  """
  @spec match_ct_helper(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def match_ct_helper(builder, helper) when is_binary(helper) do
    expr = JsonExpr.ct_match("helper", helper)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match connection byte count.

  ## Example

      # Block connections exceeding 1GB
      builder |> match_ct_bytes(:gt, 1_000_000_000) |> drop()

      # Match large downloads
      builder |> match_ct_bytes(:ge, 100_000_000) |> log("BIG-DL: ")
  """
  @spec match_ct_bytes(RuleBuilder.t(), atom(), non_neg_integer()) :: RuleBuilder.t()
  def match_ct_bytes(builder, op, bytes) when is_integer(bytes) and bytes >= 0 do
    op_str = atom_to_op(op)
    expr = JsonExpr.ct_match("bytes", bytes, op_str)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match connection packet count.

  ## Example

      # Match connections with many packets
      builder |> match_ct_packets(:gt, 10000) |> log("HIGH-PKT: ")

      # Block after packet limit
      builder |> match_ct_packets(:ge, 50000) |> drop()
  """
  @spec match_ct_packets(RuleBuilder.t(), atom(), non_neg_integer()) :: RuleBuilder.t()
  def match_ct_packets(builder, op, packets) when is_integer(packets) and packets >= 0 do
    op_str = atom_to_op(op)
    expr = JsonExpr.ct_match("packets", packets, op_str)
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match original (pre-NAT) source address.

  ## Example

      # Match original source before SNAT
      builder |> match_ct_original_saddr("192.168.1.100") |> accept()

      # Track pre-NAT source
      builder |> match_ct_original_saddr("10.0.0.0/8") |> log("INTERNAL: ")
  """
  @spec match_ct_original_saddr(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def match_ct_original_saddr(builder, addr) when is_binary(addr) do
    # CT original address requires special structure
    expr = %{
      "match" => %{
        "left" => %{"ct" => %{"key" => "ip saddr", "dir" => "original"}},
        "right" => addr,
        "op" => "=="
      }
    }
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Match original (pre-NAT) destination address.

  ## Example

      # Match original destination before DNAT
      builder |> match_ct_original_daddr("203.0.113.100") |> accept()
  """
  @spec match_ct_original_daddr(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def match_ct_original_daddr(builder, addr) when is_binary(addr) do
    # CT original address requires special structure
    expr = %{
      "match" => %{
        "left" => %{"ct" => %{"key" => "ip daddr", "dir" => "original"}},
        "right" => addr,
        "op" => "=="
      }
    }
    RuleBuilder.add_expr(builder, expr)
  end

  @doc """
  Limit number of connections per source IP.

  ## Example

      # Limit to 10 concurrent connections per IP
      builder
      |> match_dest_port(80)
      |> match_ct_state([:new])
      |> limit_connections(10)
      |> reject()

      # Limit SSH connections per IP
      builder
      |> match_dest_port(22)
      |> match_ct_state([:new])
      |> limit_connections(3)
      |> drop()
  """
  @spec limit_connections(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def limit_connections(builder, count) when is_integer(count) and count > 0 do
    expr = JsonExpr.ct_match("count", count)
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
