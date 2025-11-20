defmodule NFTables.Match.Actions do
  @moduledoc """
  Action and packet modification functions for Match.

  Provides functions for counter, logging, rate limiting, packet/connection marking,
  CT operations, and packet header modifications (DSCP, TTL, hop limit).
  """

  alias NFTables.{Match, Expr}

  # Basic actions

  @doc "Add counter expression"
  @spec counter(Match.t()) :: Match.t()
  def counter(builder) do
    expr = Expr.counter()
    Match.add_expr(builder, expr)
  end

  @doc """
  Add log expression.

  ## Options

  - `:level` - Syslog level (default: no level specified)
    - `:emerg` - Emergency
    - `:alert` - Alert
    - `:crit` - Critical
    - `:err` - Error
    - `:warning` or `:warn` - Warning
    - `:notice` - Notice
    - `:info` - Info
    - `:debug` - Debug

  ## Examples

      # Basic logging
      builder |> log("DROPPED: ")

      # With syslog level
      builder |> log("AUDIT: ", level: :warning)
      builder |> log("CRITICAL: ", level: :crit)
  """
  @spec log(Match.t(), String.t(), keyword()) :: Match.t()
  def log(builder, prefix, opts \\ []) do
    level = Keyword.get(opts, :level)

    json_opts = if level do
      level_str = case level do
        :emerg -> "emerg"
        :alert -> "alert"
        :crit -> "crit"
        :err -> "err"
        :warning -> "warn"
        :warn -> "warn"
        :notice -> "notice"
        :info -> "info"
        :debug -> "debug"
        other -> to_string(other)
      end
      [level: level_str]
    else
      []
    end

    expr = Expr.log(prefix, json_opts)
    Match.add_expr(builder, expr)
  end

  @doc """
  Add rate limiting.

  ## Example

      builder |> rate_limit(10, :minute)
      builder |> rate_limit(100, :second)
  """
  @spec rate_limit(Match.t(), non_neg_integer(), atom(), keyword()) :: Match.t()
  def rate_limit(builder, rate, unit, opts \\ []) do
    unit_str = case unit do
      :second -> "second"
      :minute -> "minute"
      :hour -> "hour"
      :day -> "day"
      :week -> "week"
      other -> to_string(other)
    end

    json_opts = if burst = Keyword.get(opts, :burst) do
      [burst: burst]
    else
      []
    end

    expr = Expr.limit(rate, unit_str, json_opts)
    Match.add_expr(builder, expr)
  end

  # Marking actions

  @doc """
  Set packet mark.

  Useful for policy routing and traffic shaping.

  ## Example

      builder |> set_mark(100)
  """
  @spec set_mark(Match.t(), non_neg_integer()) :: Match.t()
  def set_mark(builder, mark) when is_integer(mark) and mark >= 0 do
    expr = Expr.meta_set("mark", mark)
    Match.add_expr(builder, expr)
  end

  @doc """
  Set connection mark.

  Connection marks persist across all packets in a connection.

  ## Example

      builder |> set_connmark(42)
  """
  @spec set_connmark(Match.t(), non_neg_integer()) :: Match.t()
  def set_connmark(builder, mark) when is_integer(mark) and mark >= 0 do
    expr = Expr.ct_set("mark", mark)
    Match.add_expr(builder, expr)
  end

  @doc """
  Restore connection mark to packet mark.

  Copies the connection mark to the packet mark. This ensures all packets
  in a connection have the same mark, useful for policy routing and QoS.

  ## Example

      # Restore connmark for established connections
      builder
      |> ct_state([:established, :related])
      |> restore_mark()
      |> accept()

  ## Use Case

  In multi-WAN routing or QoS scenarios:
  1. First packet: classify and set connmark
  2. Subsequent packets: restore connmark to mark
  3. All packets in connection use same route/QoS tier
  """
  @spec restore_mark(Match.t()) :: Match.t()
  def restore_mark(builder) do
    # meta mark set ct mark
    expr = %{
      "mangle" => %{
        "key" => %{"meta" => %{"key" => "mark"}},
        "value" => %{"ct" => %{"key" => "mark"}}
      }
    }
    Match.add_expr(builder, expr)
  end

  @doc """
  Save packet mark to connection mark.

  Copies the packet mark to the connection mark. This persists the
  classification for the entire connection.

  ## Example

      # Classify new connection and save mark
      builder
      |> ct_state([:new])
      |> dscp(46)
      |> set_mark(1)
      |> save_mark()
      |> accept()

  ## Use Case

  In traffic classification:
  1. Match conditions and set packet mark
  2. Save mark to connmark for persistence
  3. Later packets restore connmark via restore_mark()
  """
  @spec save_mark(Match.t()) :: Match.t()
  def save_mark(builder) do
    # ct mark set meta mark
    expr = %{
      "mangle" => %{
        "key" => %{"ct" => %{"key" => "mark"}},
        "value" => %{"meta" => %{"key" => "mark"}}
      }
    }
    Match.add_expr(builder, expr)
  end

  # CT actions

  @doc """
  Set connection tracking label.

  Assigns a label to the connection for advanced stateful tracking.
  Labels are 128-bit bitmaps allowing complex classification.

  ## Example

      # Label suspicious connections
      builder
      |> source_ip("203.0.113.0/24")
      |> set_ct_label("suspicious")
      |> accept()

      # Set numeric label bit
      builder
      |> tcp()
      |> dport(22)
      |> set_ct_label(5)
      |> accept()

  ## Use Cases

  - Complex multi-stage stateful tracking
  - Connection classification across chains
  - Security event correlation
  """
  @spec set_ct_label(Match.t(), String.t() | non_neg_integer()) :: Match.t()
  def set_ct_label(builder, label) when is_binary(label) or is_integer(label) do
    expr = Expr.ct_set("label", label)
    Match.add_expr(builder, expr)
  end

  @doc """
  Assign connection tracking helper.

  Assigns a CT helper (FTP, SIP, etc.) to the connection for application
  layer gateway functionality.

  ## Example

      # Assign FTP helper
      builder
      |> tcp()
      |> dport(21)
      |> ct_state([:new])
      |> set_ct_helper("ftp")
      |> accept()

      # Assign SIP helper
      builder
      |> udp()
      |> dport(5060)
      |> set_ct_helper("sip")
      |> accept()

  ## Use Cases

  - FTP active mode support
  - SIP/VoIP NAT traversal
  - H.323 video conferencing
  - TFTP file transfers
  """
  @spec set_ct_helper(Match.t(), String.t()) :: Match.t()
  def set_ct_helper(builder, helper) when is_binary(helper) do
    expr = Expr.ct_set("helper", helper)
    Match.add_expr(builder, expr)
  end

  @doc """
  Assign connection to tracking zone.

  Places the connection in a specific CT zone for isolation.
  Useful for multi-tenant or namespace scenarios.

  ## Example

      # Assign to zone 1
      builder
      |> iif("tenant1")
      |> set_ct_zone(1)
      |> accept()

      # Assign to tenant-specific zone
      builder
      |> source_ip("192.168.100.0/24")
      |> set_ct_zone(100)
      |> accept()

  ## Use Cases

  - Multi-tenant isolation
  - Network namespace separation
  - Overlapping IP address spaces
  - Container network isolation
  """
  @spec set_ct_zone(Match.t(), non_neg_integer()) :: Match.t()
  def set_ct_zone(builder, zone) when is_integer(zone) and zone >= 0 do
    expr = Expr.ct_set("zone", zone)
    Match.add_expr(builder, expr)
  end

  # Packet modification

  @doc """
  Set DSCP (Differentiated Services Code Point) value.

  Modifies the DSCP field in the IP header for QoS remarking.

  ## DSCP Values

  - 46 (`:ef`) - Expedited Forwarding (VoIP voice)
  - 34 (`:af41`) - Assured Forwarding 4/1 (Video)
  - 26 (`:af31`) - Assured Forwarding 3/1 (Signaling)
  - 18 (`:af21`) - Assured Forwarding 2/1 (Streaming)
  - 10 (`:af11`) - Assured Forwarding 1/1 (Bulk)
  - 0 (`:cs0`) - Class Selector 0 (Best Effort)

  ## Example

      # Remark HTTP traffic as bulk
      builder
      |> tcp()
      |> dport(80)
      |> set_dscp(10)
      |> accept()

      # Mark VoIP as expedited forwarding
      builder
      |> udp()
      |> dport(5060)
      |> set_dscp(46)
      |> accept()

      # Use atom
      builder
      |> tcp()
      |> dport(22)
      |> set_dscp(:af31)
      |> accept()
  """
  @spec set_dscp(Match.t(), atom() | non_neg_integer()) :: Match.t()
  def set_dscp(builder, dscp) do
    dscp_val = case dscp do
      :ef -> 46
      :af41 -> 34
      :af31 -> 26
      :af21 -> 18
      :af11 -> 10
      :cs0 -> 0
      num when is_integer(num) and num >= 0 and num <= 63 -> num
      _ -> raise ArgumentError, "Invalid DSCP value: #{inspect(dscp)}"
    end

    expr = %{
      "mangle" => %{
        "key" => %{"payload" => %{"protocol" => "ip", "field" => "dscp"}},
        "value" => dscp_val
      }
    }
    Match.add_expr(builder, expr)
  end

  @doc """
  Set IP TTL (Time To Live) value.

  Modifies the TTL field in the IPv4 header.

  ## Example

      # Set TTL to 64
      builder |> set_ttl(64) |> accept()

      # Normalize TTL
      builder |> set_ttl(128) |> accept()

  ## Use Cases

  - TTL normalization (anti-fingerprinting)
  - Extending TTL for specific traffic
  - Router hop limit enforcement
  """
  @spec set_ttl(Match.t(), non_neg_integer()) :: Match.t()
  def set_ttl(builder, ttl) when is_integer(ttl) and ttl >= 0 and ttl <= 255 do
    expr = %{
      "mangle" => %{
        "key" => %{"payload" => %{"protocol" => "ip", "field" => "ttl"}},
        "value" => ttl
      }
    }
    Match.add_expr(builder, expr)
  end

  @doc """
  Set IPv6 hop limit value.

  IPv6 equivalent of TTL. Modifies the hop limit field in the IPv6 header.

  ## Example

      # Set hop limit to 64
      builder |> set_hoplimit(64) |> accept()

      # Normalize hop limit
      builder |> set_hoplimit(255) |> accept()
  """
  @spec set_hoplimit(Match.t(), non_neg_integer()) :: Match.t()
  def set_hoplimit(builder, hoplimit) when is_integer(hoplimit) and hoplimit >= 0 and hoplimit <= 255 do
    expr = %{
      "mangle" => %{
        "key" => %{"payload" => %{"protocol" => "ip6", "field" => "hoplimit"}},
        "value" => hoplimit
      }
    }
    Match.add_expr(builder, expr)
  end

  @doc """
  Increment IP TTL by 1.

  ## Example

      # Extend TTL by 1
      builder |> increment_ttl() |> accept()
  """
  @spec increment_ttl(Match.t()) :: Match.t()
  def increment_ttl(builder) do
    expr = %{
      "mangle" => %{
        "key" => %{"payload" => %{"protocol" => "ip", "field" => "ttl"}},
        "value" => %{
          "+" => [
            %{"payload" => %{"protocol" => "ip", "field" => "ttl"}},
            1
          ]
        }
      }
    }
    Match.add_expr(builder, expr)
  end

  @doc """
  Decrement IP TTL by 1.

  ## Example

      # Reduce TTL by 1
      builder |> decrement_ttl() |> accept()
  """
  @spec decrement_ttl(Match.t()) :: Match.t()
  def decrement_ttl(builder) do
    expr = %{
      "mangle" => %{
        "key" => %{"payload" => %{"protocol" => "ip", "field" => "ttl"}},
        "value" => %{
          "-" => [
            %{"payload" => %{"protocol" => "ip", "field" => "ttl"}},
            1
          ]
        }
      }
    }
    Match.add_expr(builder, expr)
  end

  @doc """
  Increment IPv6 hop limit by 1.

  ## Example

      # Extend hop limit by 1
      builder |> increment_hoplimit() |> accept()
  """
  @spec increment_hoplimit(Match.t()) :: Match.t()
  def increment_hoplimit(builder) do
    expr = %{
      "mangle" => %{
        "key" => %{"payload" => %{"protocol" => "ip6", "field" => "hoplimit"}},
        "value" => %{
          "+" => [
            %{"payload" => %{"protocol" => "ip6", "field" => "hoplimit"}},
            1
          ]
        }
      }
    }
    Match.add_expr(builder, expr)
  end

  @doc """
  Decrement IPv6 hop limit by 1.

  ## Example

      # Reduce hop limit by 1
      builder |> decrement_hoplimit() |> accept()
  """
  @spec decrement_hoplimit(Match.t()) :: Match.t()
  def decrement_hoplimit(builder) do
    expr = %{
      "mangle" => %{
        "key" => %{"payload" => %{"protocol" => "ip6", "field" => "hoplimit"}},
        "value" => %{
          "-" => [
            %{"payload" => %{"protocol" => "ip6", "field" => "hoplimit"}},
            1
          ]
        }
      }
    }
    Match.add_expr(builder, expr)
  end
end
