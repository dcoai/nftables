defmodule NFTex.RuleBuilder.Actions do
  @moduledoc """
  Action and packet modification functions for RuleBuilder.

  Provides functions for counter, logging, rate limiting, packet/connection marking,
  CT operations, and packet header modifications (DSCP, TTL, hop limit).
  """

  alias NFTex.RuleBuilder

  # Basic actions

  @doc "Add counter expression"
  @spec counter(RuleBuilder.t()) :: RuleBuilder.t()
  def counter(builder) do
    RuleBuilder.add_part(builder, "counter")
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
  @spec log(RuleBuilder.t(), String.t(), keyword()) :: RuleBuilder.t()
  def log(builder, prefix, opts \\ []) do
    level = Keyword.get(opts, :level)

    log_expr = if level do
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
      "log prefix #{inspect(prefix)} level #{level_str}"
    else
      "log prefix #{inspect(prefix)}"
    end

    RuleBuilder.add_part(builder, log_expr)
  end

  @doc """
  Add rate limiting.

  ## Example

      builder |> rate_limit(10, :minute)
      builder |> rate_limit(100, :second)
  """
  @spec rate_limit(RuleBuilder.t(), non_neg_integer(), atom(), keyword()) :: RuleBuilder.t()
  def rate_limit(builder, rate, unit, opts \\ []) do
    unit_str = case unit do
      :second -> "second"
      :minute -> "minute"
      :hour -> "hour"
      :day -> "day"
      :week -> "week"
      other -> to_string(other)
    end

    burst = Keyword.get(opts, :burst)
    limit_str = if burst do
      "limit rate #{rate}/#{unit_str} burst #{burst} packets"
    else
      "limit rate #{rate}/#{unit_str}"
    end

    RuleBuilder.add_part(builder, limit_str)
  end

  # Marking actions

  @doc """
  Set packet mark.

  Useful for policy routing and traffic shaping.

  ## Example

      builder |> set_mark(100)
  """
  @spec set_mark(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def set_mark(builder, mark) when is_integer(mark) and mark >= 0 do
    RuleBuilder.add_part(builder, "meta mark set #{mark}")
  end

  @doc """
  Set connection mark.

  Connection marks persist across all packets in a connection.

  ## Example

      builder |> set_connmark(42)
  """
  @spec set_connmark(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def set_connmark(builder, mark) when is_integer(mark) and mark >= 0 do
    RuleBuilder.add_part(builder, "ct mark set #{mark}")
  end

  @doc """
  Restore connection mark to packet mark.

  Copies the connection mark to the packet mark. This ensures all packets
  in a connection have the same mark, useful for policy routing and QoS.

  ## Example

      # Restore connmark for established connections
      builder
      |> match_ct_state([:established, :related])
      |> restore_mark()
      |> accept()

  ## Use Case

  In multi-WAN routing or QoS scenarios:
  1. First packet: classify and set connmark
  2. Subsequent packets: restore connmark to mark
  3. All packets in connection use same route/QoS tier
  """
  @spec restore_mark(RuleBuilder.t()) :: RuleBuilder.t()
  def restore_mark(builder) do
    RuleBuilder.add_part(builder, "meta mark set ct mark")
  end

  @doc """
  Save packet mark to connection mark.

  Copies the packet mark to the connection mark. This persists the
  classification for the entire connection.

  ## Example

      # Classify new connection and save mark
      builder
      |> match_ct_state([:new])
      |> match_dscp(46)
      |> set_mark(1)
      |> save_mark()
      |> accept()

  ## Use Case

  In traffic classification:
  1. Match conditions and set packet mark
  2. Save mark to connmark for persistence
  3. Later packets restore connmark via restore_mark()
  """
  @spec save_mark(RuleBuilder.t()) :: RuleBuilder.t()
  def save_mark(builder) do
    RuleBuilder.add_part(builder, "ct mark set meta mark")
  end

  # CT actions

  @doc """
  Set connection tracking label.

  Assigns a label to the connection for advanced stateful tracking.
  Labels are 128-bit bitmaps allowing complex classification.

  ## Example

      # Label suspicious connections
      builder
      |> match_source_ip("203.0.113.0/24")
      |> set_ct_label("suspicious")
      |> accept()

      # Set numeric label bit
      builder
      |> match_dest_port(22)
      |> set_ct_label(5)
      |> accept()

  ## Use Cases

  - Complex multi-stage stateful tracking
  - Connection classification across chains
  - Security event correlation
  """
  @spec set_ct_label(RuleBuilder.t(), String.t() | non_neg_integer()) :: RuleBuilder.t()
  def set_ct_label(builder, label) when is_binary(label) or is_integer(label) do
    label_str = if is_integer(label), do: to_string(label), else: inspect(label)
    RuleBuilder.add_part(builder, "ct label set #{label_str}")
  end

  @doc """
  Assign connection tracking helper.

  Assigns a CT helper (FTP, SIP, etc.) to the connection for application
  layer gateway functionality.

  ## Example

      # Assign FTP helper
      builder
      |> match_dest_port(21)
      |> match_ct_state([:new])
      |> set_ct_helper("ftp")
      |> accept()

      # Assign SIP helper
      builder
      |> match_udp_dport(5060)
      |> set_ct_helper("sip")
      |> accept()

  ## Use Cases

  - FTP active mode support
  - SIP/VoIP NAT traversal
  - H.323 video conferencing
  - TFTP file transfers
  """
  @spec set_ct_helper(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def set_ct_helper(builder, helper) when is_binary(helper) do
    RuleBuilder.add_part(builder, "ct helper set #{inspect(helper)}")
  end

  @doc """
  Assign connection to tracking zone.

  Places the connection in a specific CT zone for isolation.
  Useful for multi-tenant or namespace scenarios.

  ## Example

      # Assign to zone 1
      builder
      |> match_iif("tenant1")
      |> set_ct_zone(1)
      |> accept()

      # Assign to tenant-specific zone
      builder
      |> match_source_ip("192.168.100.0/24")
      |> set_ct_zone(100)
      |> accept()

  ## Use Cases

  - Multi-tenant isolation
  - Network namespace separation
  - Overlapping IP address spaces
  - Container network isolation
  """
  @spec set_ct_zone(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def set_ct_zone(builder, zone) when is_integer(zone) and zone >= 0 do
    RuleBuilder.add_part(builder, "ct zone set #{zone}")
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
      |> match_dest_port(80)
      |> set_dscp(10)
      |> accept()

      # Mark VoIP as expedited forwarding
      builder
      |> match_udp_dport(5060)
      |> set_dscp(46)
      |> accept()

      # Use atom
      builder
      |> match_dest_port(22)
      |> set_dscp(:af31)
      |> accept()
  """
  @spec set_dscp(RuleBuilder.t(), atom() | non_neg_integer()) :: RuleBuilder.t()
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
    RuleBuilder.add_part(builder, "ip dscp set #{dscp_val}")
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
  @spec set_ttl(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def set_ttl(builder, ttl) when is_integer(ttl) and ttl >= 0 and ttl <= 255 do
    RuleBuilder.add_part(builder, "ip ttl set #{ttl}")
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
  @spec set_hoplimit(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def set_hoplimit(builder, hoplimit) when is_integer(hoplimit) and hoplimit >= 0 and hoplimit <= 255 do
    RuleBuilder.add_part(builder, "ip6 hoplimit set #{hoplimit}")
  end

  @doc """
  Increment IP TTL by 1.

  ## Example

      # Extend TTL by 1
      builder |> increment_ttl() |> accept()
  """
  @spec increment_ttl(RuleBuilder.t()) :: RuleBuilder.t()
  def increment_ttl(builder) do
    RuleBuilder.add_part(builder, "ip ttl set ip ttl + 1")
  end

  @doc """
  Decrement IP TTL by 1.

  ## Example

      # Reduce TTL by 1
      builder |> decrement_ttl() |> accept()
  """
  @spec decrement_ttl(RuleBuilder.t()) :: RuleBuilder.t()
  def decrement_ttl(builder) do
    RuleBuilder.add_part(builder, "ip ttl set ip ttl - 1")
  end

  @doc """
  Increment IPv6 hop limit by 1.

  ## Example

      # Extend hop limit by 1
      builder |> increment_hoplimit() |> accept()
  """
  @spec increment_hoplimit(RuleBuilder.t()) :: RuleBuilder.t()
  def increment_hoplimit(builder) do
    RuleBuilder.add_part(builder, "ip6 hoplimit set ip6 hoplimit + 1")
  end

  @doc """
  Decrement IPv6 hop limit by 1.

  ## Example

      # Reduce hop limit by 1
      builder |> decrement_hoplimit() |> accept()
  """
  @spec decrement_hoplimit(RuleBuilder.t()) :: RuleBuilder.t()
  def decrement_hoplimit(builder) do
    RuleBuilder.add_part(builder, "ip6 hoplimit set ip6 hoplimit - 1")
  end
end
