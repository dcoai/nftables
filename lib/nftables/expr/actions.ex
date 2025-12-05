defmodule NFTables.Expr.Actions do
  @moduledoc """
  Action and packet modification functions for Expr.

  Provides functions for counter, logging, rate limiting, packet/connection marking,
  CT operations, and packet header modifications (DSCP, TTL, hop limit).
  These actions modify packets or connection state rather than matching conditions.

  ## Import

      import NFTables.Expr.Actions

  ## Examples

      # Counter and logging
      tcp() |> dport(22) |> counter() |> log("SSH: ") |> accept()

      # Rate limiting
      tcp() |> dport(80) |> limit(100, :second, burst: 20) |> accept()

      # Packet marking for QoS
      udp() |> dport(5060) |> set_dscp(:ef) |> set_mark(1) |> accept()

      # Connection marking
      ct_state([:new]) |> set_mark(100) |> save_mark() |> accept()
      state([:established]) |> restore_mark() |> accept()

  For more information, see the [nftables statements wiki](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Statements).
  """

  alias NFTables.Expr

  # Basic actions

  @doc "Add counter expression"
  @spec counter(Expr.t()) :: Expr.t()
  def counter(builder \\ Expr.expr()) do
    expr = Expr.Structs.counter()
    Expr.add_expr(builder, expr)
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
  @spec log(Expr.t(), String.t(), keyword()) :: Expr.t()
  def log(builder \\ Expr.expr(), prefix, opts \\ []) do
    level = Keyword.get(opts, :level)
    level_map = %{
      emerg: "emerg", alert: "alert", crit: "crit", err: "err", warning: "warn",
      warn: "warn", notice: "notice", info: "info", debug: "debug"
    }

    json_opts =
      if level do
        [level: Map.get(level_map, level, to_string(level))]
      else
        []
      end

    expr = Expr.Structs.log(prefix, json_opts)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Add rate limiting.

  ## Example

      builder |> rate_limit(10, :minute)
      builder |> rate_limit(100, :second)
  """
  @spec rate_limit(Expr.t(), non_neg_integer(), atom(), keyword()) :: Expr.t()
  def rate_limit(builder \\ Expr.expr(), rate, unit, opts \\ []) do
    unit_str =
      case unit do
        :second -> "second"
        :minute -> "minute"
        :hour -> "hour"
        :day -> "day"
        :week -> "week"
        other -> to_string(other)
      end

    json_opts =
      if burst = Keyword.get(opts, :burst) do
        [burst: burst]
      else
        []
      end

    expr = Expr.Structs.limit(rate, unit_str, json_opts)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Convenience alias for rate_limit/4. Add rate limiting.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Examples

      # Basic rate limiting
      limit(10, :minute)

      # With burst
      tcp() |> dport(22) |> limit(10, :minute, burst: 5)

      # Continue existing expression
      builder |> limit(100, :second)
  """
  @spec limit(Expr.t(), non_neg_integer(), atom(), keyword()) :: Expr.t()
  def limit(builder \\ Expr.expr(), rate, unit, opts \\ []), do: rate_limit(builder, rate, unit, opts)

  # Marking actions

  @doc """
  Set packet mark.

  Useful for policy routing and traffic shaping.

  ## Example

      builder |> set_mark(100)
  """
  @spec set_mark(Expr.t(), non_neg_integer()) :: Expr.t()
  def set_mark(builder \\ Expr.expr(), mark) when is_integer(mark) and mark >= 0 do
    expr = Expr.Structs.meta_set("mark", mark)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Set connection mark.

  Connection marks persist across all packets in a connection.

  ## Example

      builder |> set_connmark(42)
  """
  @spec set_connmark(Expr.t(), non_neg_integer()) :: Expr.t()
  def set_connmark(builder \\ Expr.expr(), mark) when is_integer(mark) and mark >= 0 do
    expr = Expr.Structs.ct_set("mark", mark)
    Expr.add_expr(builder, expr)
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
  @spec restore_mark(Expr.t()) :: Expr.t()
  def restore_mark(builder \\ Expr.expr()) do
    # meta mark set ct mark
    expr = %{
      "mangle" => %{
        "key" => %{"meta" => %{"key" => "mark"}},
        "value" => %{"ct" => %{"key" => "mark"}}
      }
    }

    Expr.add_expr(builder, expr)
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
  @spec save_mark(Expr.t()) :: Expr.t()
  def save_mark(builder \\ Expr.expr()) do
    # ct mark set meta mark
    expr = %{
      "mangle" => %{
        "key" => %{"ct" => %{"key" => "mark"}},
        "value" => %{"meta" => %{"key" => "mark"}}
      }
    }

    Expr.add_expr(builder, expr)
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
  @spec set_ct_label(Expr.t(), String.t() | non_neg_integer()) :: Expr.t()
  def set_ct_label(builder \\ Expr.expr(), label) when is_binary(label) or is_integer(label) do
    expr = Expr.Structs.ct_set("label", label)
    Expr.add_expr(builder, expr)
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
  @spec set_ct_helper(Expr.t(), String.t()) :: Expr.t()
  def set_ct_helper(builder \\ Expr.expr(), helper) when is_binary(helper) do
    expr = Expr.Structs.ct_set("helper", helper)
    Expr.add_expr(builder, expr)
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
  @spec set_ct_zone(Expr.t(), non_neg_integer()) :: Expr.t()
  def set_ct_zone(builder \\ Expr.expr(), zone) when is_integer(zone) and zone >= 0 do
    expr = Expr.Structs.ct_set("zone", zone)
    Expr.add_expr(builder, expr)
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
  @spec set_dscp(Expr.t(), atom() | non_neg_integer()) :: Expr.t()
  def set_dscp(builder \\ Expr.expr(), dscp) do
    dscp_val =
      case dscp do
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

    Expr.add_expr(builder, expr)
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
  @spec set_ttl(Expr.t(), non_neg_integer()) :: Expr.t()
  def set_ttl(builder \\ Expr.expr(), ttl) when is_integer(ttl) and ttl >= 0 and ttl <= 255 do
    expr = %{
      "mangle" => %{
        "key" => %{"payload" => %{"protocol" => "ip", "field" => "ttl"}},
        "value" => ttl
      }
    }

    Expr.add_expr(builder, expr)
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
  @spec set_hoplimit(Expr.t(), non_neg_integer()) :: Expr.t()
  def set_hoplimit(builder \\ Expr.expr(), hoplimit)
      when is_integer(hoplimit) and hoplimit >= 0 and hoplimit <= 255 do
    expr = %{
      "mangle" => %{
        "key" => %{"payload" => %{"protocol" => "ip6", "field" => "hoplimit"}},
        "value" => hoplimit
      }
    }

    Expr.add_expr(builder, expr)
  end

  @doc """
  Increment IP TTL by 1.

  ## Example

      # Extend TTL by 1
      builder |> increment_ttl() |> accept()
  """
  @spec increment_ttl(Expr.t()) :: Expr.t()
  def increment_ttl(builder \\ Expr.expr()) do
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

    Expr.add_expr(builder, expr)
  end

  @doc """
  Decrement IP TTL by 1.

  ## Example

      # Reduce TTL by 1
      builder |> decrement_ttl() |> accept()
  """
  @spec decrement_ttl(Expr.t()) :: Expr.t()
  def decrement_ttl(builder \\ Expr.expr()) do
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

    Expr.add_expr(builder, expr)
  end

  @doc """
  Increment IPv6 hop limit by 1.

  ## Example

      # Extend hop limit by 1
      builder |> increment_hoplimit() |> accept()
  """
  @spec increment_hoplimit(Expr.t()) :: Expr.t()
  def increment_hoplimit(builder \\ Expr.expr()) do
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

    Expr.add_expr(builder, expr)
  end

  @doc """
  Decrement IPv6 hop limit by 1.

  ## Example

      # Reduce hop limit by 1
      builder |> decrement_hoplimit() |> accept()
  """
  @spec decrement_hoplimit(Expr.t()) :: Expr.t()
  def decrement_hoplimit(builder \\ Expr.expr()) do
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

    Expr.add_expr(builder, expr)
  end
end
