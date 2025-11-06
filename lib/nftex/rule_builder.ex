defmodule NFTex.RuleBuilder do
  @moduledoc """
  Fluent API for building nftables rules.

  This module provides an intuitive, chainable interface for building firewall rules
  using nft syntax strings internally.

  ## Quick Example

      alias NFTex.RuleBuilder

      # Drop packets from specific IP
      RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_source_ip("192.168.1.100")
      |> RuleBuilder.log("BLOCKED IP: ")
      |> RuleBuilder.drop()
      |> RuleBuilder.commit()

  ## Common Patterns

      # Accept established/related connections
      RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_ct_state([:established, :related])
      |> RuleBuilder.accept()
      |> RuleBuilder.commit()

      # Rate limit SSH connections
      RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_dest_port(22)
      |> RuleBuilder.rate_limit(10, :minute)
      |> RuleBuilder.accept()
      |> RuleBuilder.commit()

  ## See Also

  - `NFTex.Policy` - Pre-built common policies
  - `NFTex.Rule` - Low-level rule operations
  """

  alias NFTex.Rule

  defstruct [
    :pid,
    :table,
    :chain,
    :family,
    nft_parts: []
  ]

  @type t :: %__MODULE__{
          pid: pid(),
          table: String.t(),
          chain: String.t(),
          family: atom(),
          nft_parts: list(String.t())
        }

  @doc """
  Start building a new rule.

  ## Parameters

  - `pid` - NFTex process
  - `table` - Table name
  - `chain` - Chain name
  - `opts` - Options:
    - `:family` - Protocol family (default: `:inet`)

  ## Example

      builder = RuleBuilder.new(pid, "filter", "INPUT")
      builder = RuleBuilder.new(pid, "filter", "INPUT", family: :inet6)
  """
  @spec new(pid(), String.t(), String.t(), keyword()) :: t()
  def new(pid, table, chain, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)

    %__MODULE__{
      pid: pid,
      table: table,
      chain: chain,
      family: family,
      nft_parts: []
    }
  end

  ## Matching Functions

  @doc """
  Match source IP address.

  Accepts either a string IP ("192.168.1.100") or binary form (<<192, 168, 1, 100>>).
  """
  @spec match_source_ip(t(), String.t() | binary()) :: t()
  def match_source_ip(builder, ip) when is_binary(ip) do
    ip_str = format_ip(ip)

    # Determine IP version based on family or IP format
    prefix = case builder.family do
      :ip6 -> "ip6"
      :inet6 -> "ip6"
      _ -> if String.contains?(ip_str, ":"), do: "ip6", else: "ip"
    end

    add_part(builder, "#{prefix} saddr #{ip_str}")
  end

  @doc """
  Match destination IP address.

  Accepts either a string IP ("192.168.1.100") or binary form (<<192, 168, 1, 100>>).
  """
  @spec match_dest_ip(t(), String.t() | binary()) :: t()
  def match_dest_ip(builder, ip) when is_binary(ip) do
    ip_str = format_ip(ip)

    # Determine IP version based on family or IP format
    prefix = case builder.family do
      :ip6 -> "ip6"
      :inet6 -> "ip6"
      _ -> if String.contains?(ip_str, ":"), do: "ip6", else: "ip"
    end

    add_part(builder, "#{prefix} daddr #{ip_str}")
  end

  @doc "Match source port"
  @spec match_source_port(t(), non_neg_integer()) :: t()
  def match_source_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    add_part(builder, "tcp sport #{port}")
  end

  @doc "Match destination port (TCP)"
  @spec match_dest_port(t(), non_neg_integer()) :: t()
  def match_dest_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    add_part(builder, "tcp dport #{port}")
  end

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
  @spec match_ct_state(t(), list(atom())) :: t()
  def match_ct_state(builder, states) when is_list(states) do
    state_str = states
      |> Enum.map(&to_string/1)
      |> Enum.join(",")

    add_part(builder, "ct state #{state_str}")
  end

  @doc "Match input interface name"
  @spec match_iif(t(), String.t()) :: t()
  def match_iif(builder, ifname) when is_binary(ifname) do
    add_part(builder, "iifname #{inspect(ifname)}")
  end

  @doc "Match output interface name"
  @spec match_oif(t(), String.t()) :: t()
  def match_oif(builder, ifname) when is_binary(ifname) do
    add_part(builder, "oifname #{inspect(ifname)}")
  end

  @doc "Match protocol"
  @spec match_protocol(t(), atom() | String.t()) :: t()
  def match_protocol(builder, protocol) do
    add_part(builder, "ip protocol #{protocol}")
  end

  ## Action Functions

  @doc "Add counter expression"
  @spec counter(t()) :: t()
  def counter(builder) do
    add_part(builder, "counter")
  end

  @doc """
  Add log expression.

  ## Example

      builder |> log("DROPPED: ")
      builder |> log("AUDIT: ", level: :warning)
  """
  @spec log(t(), String.t(), keyword()) :: t()
  def log(builder, prefix, _opts \\ []) do
    # nft syntax: log prefix "text"
    add_part(builder, "log prefix #{inspect(prefix)}")
  end

  @doc """
  Add rate limiting.

  ## Example

      builder |> rate_limit(10, :minute)
      builder |> rate_limit(100, :second)
  """
  @spec rate_limit(t(), non_neg_integer(), atom(), keyword()) :: t()
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

    add_part(builder, limit_str)
  end

  ## Verdict Functions

  @doc "Accept packets"
  @spec accept(t()) :: t()
  def accept(builder) do
    add_part(builder, "accept")
  end

  @doc "Drop packets silently"
  @spec drop(t()) :: t()
  def drop(builder) do
    add_part(builder, "drop")
  end

  @doc """
  Reject packets with ICMP error.

  ## Example

      builder |> reject()
      builder |> reject(:tcp_reset)
  """
  @spec reject(t(), atom()) :: t()
  def reject(builder, type \\ :icmp_port_unreachable) do
    reject_str = case type do
      :tcp_reset -> "reject with tcp reset"
      :icmp_port_unreachable -> "reject"
      :icmpx_port_unreachable -> "reject with icmpx type port-unreachable"
      other -> "reject with #{other}"
    end

    add_part(builder, reject_str)
  end

  ## Build and Commit

  @doc """
  Commit the rule to the kernel.

  This builds the complete nft expression string from all parts
  and creates the rule using the JSON API.

  Returns `:ok` on success, `{:error, reason}` on failure.
  """
  @spec commit(t()) :: :ok | {:error, term()}
  def commit(%__MODULE__{} = builder) do
    # Build complete nft expression
    expr = Enum.join(builder.nft_parts, " ")

    # Use Rule.add to create the rule
    Rule.add(builder.pid, %{
      family: builder.family,
      table: builder.table,
      chain: builder.chain,
      expr: expr
    })
  end

  # Private helpers

  defp add_part(builder, part) when is_binary(part) do
    %{builder | nft_parts: builder.nft_parts ++ [part]}
  end

  # Format IP address - convert binary to string if needed
  defp format_ip(ip) when byte_size(ip) == 4 do
    # IPv4 binary format: <<192, 168, 1, 100>>
    <<a, b, c, d>> = ip
    "#{a}.#{b}.#{c}.#{d}"
  end

  defp format_ip(ip) when byte_size(ip) == 16 do
    # IPv6 binary format - convert to string
    # This is a simplified conversion; nftables will handle it
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = ip
    parts = [a, b, c, d, e, f, g, h]
      |> Enum.map(&Integer.to_string(&1, 16))
      |> Enum.map(&String.downcase/1)
    Enum.join(parts, ":")
  end

  defp format_ip(ip) when is_binary(ip) do
    # Already a string (e.g., "192.168.1.100" or "::1")
    # Check if it looks like an IP address
    if String.contains?(ip, ".") or String.contains?(ip, ":") do
      ip
    else
      # Might be a binary, try to parse as IPv4
      case :inet.parse_address(String.to_charlist(ip)) do
        {:ok, {a, b, c, d}} -> "#{a}.#{b}.#{c}.#{d}"
        {:ok, {a, b, c, d, e, f, g, h}} ->
          parts = [a, b, c, d, e, f, g, h]
            |> Enum.map(&Integer.to_string(&1, 16))
            |> Enum.map(&String.downcase/1)
          Enum.join(parts, ":")
        {:error, _} -> ip  # Return as-is if can't parse
      end
    end
  end
end
