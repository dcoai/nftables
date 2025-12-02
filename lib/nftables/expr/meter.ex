defmodule NFTables.Expr.Meter do
  @moduledoc """
  Per-key rate limiting using dynamic sets (meters).

  Meters provide stateful rate limiting on a per-key basis (e.g., per-IP address).
  They use dynamic sets to track keys and enforce rate limits independently for each key.

  This replaces iptables' hashlimit functionality with a more flexible approach.

  ## Overview

  A meter consists of:
  - A **dynamic set** to store keys
  - A **key expression** (what to track: IP, port, tuple, etc.)
  - A **limit statement** (rate limit per key)
  - Optional **timeout** (how long to keep inactive keys)

  ## Workflow

  1. Create a dynamic set with `Builder.add(set: ...)`
  2. Use meter expressions in rules to track and limit per-key
  3. nftables automatically manages set entries with timeouts

  ## Examples

      import NFTables.Match
      import NFTables.Match.Meter
      alias NFTables.Builder

      # Step 1: Create dynamic set
      Builder.new(family: :inet)
      |> Builder.add(table: "filter")
      |> Builder.add(
        set: "ssh_ratelimit",
        table: "filter",
        type: :ipv4_addr,
        flags: [:dynamic],
        timeout: 60,    # Expire after 60s inactivity
        size: 10000     # Max 10k tracked IPs
      )
      |> Builder.submit(pid: pid)

      # Step 2: Use meter in rule
      ssh_rule = rule()
        |> tcp()
        |> dport(22)
        |> ct_state([:new])
        |> meter_update(
          payload(:ip, :saddr),  # Track by source IP
          "ssh_ratelimit",        # Set name
          3,                      # 3 connections
          :minute,                # per minute
          burst: 5                # Allow burst of 5
        )
        |> accept()
       

      Builder.new()
      |> Builder.add(rule: ssh_rule, table: "filter", chain: "input", family: :inet)
      |> Builder.submit(pid: pid)

  ## Set Types for Keys

  - `:ipv4_addr` - Track by IPv4 address
  - `:ipv6_addr` - Track by IPv6 address
  - `:inet_proto` - Track by protocol number
  - `:inet_service` - Track by port number
  - Composite types: `{:concat, [:ipv4_addr, :inet_service]}` - Track by IP+port tuple

  ## Use Cases

  - **SSH brute-force protection**: Limit connections per IP
  - **HTTP flood protection**: Limit requests per source
  - **Port scan detection**: Limit new connections per IP
  - **Fair bandwidth sharing**: Limit throughput per user/IP
  - **SYN flood protection**: Limit SYN packets per source
  """

  alias NFTables.Expr

  @doc """
  Add meter with update operation.

  Uses "update" operation which updates existing entries or adds new ones.
  This is the most common meter operation.

  ## Parameters

  - `builder` - Match builder
  - `key_expr` - Expression for key (single or list for composite keys)
  - `set_name` - Name of the dynamic set
  - `rate` - Rate limit (number of events)
  - `per` - Time unit (:second, :minute, :hour, :day, :week)
  - `opts` - Options:
    - `:burst` - Burst size (default: 0)

  ## Examples

      # Per-IP SSH rate limiting
      builder
      |> meter_update(payload(:ip, :saddr), "ssh_limits", 3, :minute, burst: 5)

      # Composite key: per source-destination pair
      builder
      |> meter_update(
        [payload(:ip, :saddr), payload(:ip, :daddr)],
        "flow_limits",
        100,
        :second
      )

      # Per-port limiting
      builder
      |> meter_update(payload(:tcp, :dport), "port_limits", 50, :second)
  """
  @spec meter_update(Expr.t(), term(), String.t(), non_neg_integer(), atom(), keyword()) ::
          Expr.t()
  def meter_update(builder, key_expr, set_name, rate, per, opts \\ []) do
    limit_expr = build_limit_expr(rate, per, opts)
    set_expr = Expr.Structs.set_update(key_expr, set_name, [limit_expr])
    Expr.add_expr(builder, set_expr)
  end

  @doc """
  Add meter with add operation.

  Uses "add" operation which fails if the element already exists.
  Less common than update - use when you need to distinguish first-time vs repeat.

  ## Examples

      # Track first connection per IP
      builder
      |> meter_add(payload(:ip, :saddr), "new_ips", 1, :minute)
  """
  @spec meter_add(Expr.t(), term(), String.t(), non_neg_integer(), atom(), keyword()) ::
          Expr.t()
  def meter_add(builder, key_expr, set_name, rate, per, opts \\ []) do
    limit_expr = build_limit_expr(rate, per, opts)
    set_expr = Expr.Structs.set_add_operation(key_expr, set_name, [limit_expr])
    Expr.add_expr(builder, set_expr)
  end

  @doc """
  Convenience function: creates payload expression for common keys.

  ## Examples

      # Source IP (IPv4)
      payload(:ip, :saddr)
      #=> %{payload: %{protocol: "ip", field: "saddr"}}

      # Source IP (IPv6)
      payload(:ip6, :saddr)

      # Source port (TCP)
      payload(:tcp, :sport)

      # Destination port (UDP)
      payload(:udp, :dport)
  """
  @spec payload(atom(), atom()) :: map()
  def payload(protocol, field) do
    %{payload: %{protocol: to_string(protocol), field: to_string(field)}}
  end

  @doc """
  Build a composite key expression from multiple fields.

  ## Examples

      # Track by source IP + destination port
      composite_key([
        payload(:ip, :saddr),
        payload(:tcp, :dport)
      ])

      # Track by src IP + dst IP + protocol
      composite_key([
        payload(:ip, :saddr),
        payload(:ip, :daddr),
        payload(:ip, :protocol)
      ])
  """
  @spec composite_key(list(map())) :: list(map())
  def composite_key(expressions) when is_list(expressions) do
    expressions
  end

  ## Private Helpers

  # Build limit expression
  defp build_limit_expr(rate, per, opts) do
    unit_str = case per do
      :second -> "second"
      :minute -> "minute"
      :hour -> "hour"
      :day -> "day"
      :week -> "week"
      other -> to_string(other)
    end

    burst = Keyword.get(opts, :burst, 0)

    %{
      limit: %{
        rate: rate,
        per: unit_str,
        burst: burst
      }
    }
  end
end
