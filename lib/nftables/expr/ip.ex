defmodule NFTables.Expr.IP do
  @moduledoc """
  IP address matching and IP-layer field functions for Expr.

  Provides functions to match source and destination IP addresses for both IPv4 and IPv6,
  as well as IP-layer fields like TTL (Time To Live) and hop limit.
  These are fundamental matching functions used in most firewall rules to identify
  traffic based on IP addresses and IP header fields.

  ## Import

      import NFTables.Expr.IP

  ## Examples

      # IP address matching
      source_ip("192.168.1.0/24") |> accept()
      dest_ip("10.0.0.1") |> drop()

      # TTL/hop limit matching
      ttl(:eq, 64) |> accept()
      hoplimit(:gt, 1) |> accept()

  For more information, see the [nftables payload expressions wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers).
  """

  alias NFTables.Expr

  @doc """
  Match source IP address.

  Accepts either a string IP ("192.168.1.100") or binary form (<<192, 168, 1, 100>>).
  Supports dual-arity: can start a new expression or continue an existing one.

  ## Examples

      # Start new expression
      source_ip("192.168.1.100") |> accept()

      # Continue existing expression
      source_ip("192.168.1.100")

      # IPv6
      source_ip("2001:db8::1")
  """
  @spec source_ip(Expr.t(), String.t() | binary()) :: Expr.t()
  def source_ip(builder \\ Expr.expr(), ip) when is_binary(ip) do
    ip_str = format_ip(ip)

    # Determine IP version based on family or IP format
    protocol =
      case builder.family do
        :ip6 -> "ip6"
        :inet6 -> "ip6"
        _ -> if String.contains?(ip_str, ":"), do: "ip6", else: "ip"
      end

    # Build JSON expression for IP source address match
    expr =
      if String.contains?(ip_str, "/") do
        # CIDR notation - use prefix match
        [addr, prefix_len] = String.split(ip_str, "/", parts: 2)
        Expr.Structs.payload_match_prefix(protocol, "saddr", addr, String.to_integer(prefix_len))
      else
        # Single IP - use regular match
        Expr.Structs.payload_match(protocol, "saddr", ip_str)
      end

    Expr.add_expr(builder, expr)
  end

  @doc """
  Match destination IP address.

  Accepts either a string IP ("192.168.1.100") or binary form (<<192, 168, 1, 100>>).
  Supports dual-arity: can start a new expression or continue an existing one.

  ## Examples

      # Start new expression
      dest_ip("192.168.1.100") |> accept()

      # Continue existing expression
      dest_ip("192.168.1.100")

      # IPv6
      dest_ip("2001:db8::1")
  """
  @spec dest_ip(Expr.t(), String.t() | binary()) :: Expr.t()
  def dest_ip(builder \\ Expr.expr(), ip) when is_binary(ip) do
    ip_str = format_ip(ip)

    # Determine IP version based on family or IP format
    protocol =
      case builder.family do
        :ip6 -> "ip6"
        :inet6 -> "ip6"
        _ -> if String.contains?(ip_str, ":"), do: "ip6", else: "ip"
      end

    # Build JSON expression for IP destination address match
    expr =
      if String.contains?(ip_str, "/") do
        # CIDR notation - use prefix match
        [addr, prefix_len] = String.split(ip_str, "/", parts: 2)
        Expr.Structs.payload_match_prefix(protocol, "daddr", addr, String.to_integer(prefix_len))
      else
        # Single IP - use regular match
        Expr.Structs.payload_match(protocol, "daddr", ip_str)
      end

    Expr.add_expr(builder, expr)
  end

  @doc """
  Match source IP address. Convenience alias for `source_ip/2`.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Example

      # Start new expression
      source("192.168.1.100")

      # Continue existing expression
      builder |> source("192.168.1.100")
  """
  @spec source(Expr.t(), String.t() | binary()) :: Expr.t()
  def source(builder \\ Expr.expr(), ip), do: source_ip(builder, ip)

  @doc """
  Match destination IP address. Convenience alias for `dest_ip/2`.

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Example

      # Start new expression
      dest("10.0.0.1")

      # Continue existing expression
      builder |> dest("10.0.0.1")
  """
  @spec dest(Expr.t(), String.t() | binary()) :: Expr.t()
  def dest(builder \\ Expr.expr(), ip), do: dest_ip(builder, ip)

  @doc """
  Match IP TTL (time to live).

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Example

      # Start a new expression
      ttl(:eq, 64)

      # Continue an existing expression and chain
      builder |> ttl(:eq, 1) |> drop()

      # Match packets with TTL > 64
      builder |> ttl(:gt, 64)
  """
  @spec ttl(Expr.t(), atom(), non_neg_integer()) :: Expr.t()
  def ttl(builder \\ Expr.expr(), op, ttl) when is_integer(ttl) and ttl >= 0 and ttl <= 255 do
    op_str = atom_to_op(op)
    expr = Expr.Structs.payload_match("ip", "ttl", ttl, op_str)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match IPv6 hop limit.

  IPv6 equivalent of TTL (Time To Live).

  Supports dual-arity: can start a new expression or continue an existing one.

  ## Example

      # Start a new expression
      hoplimit(:eq, 1)

      # Continue an existing expression and chain
      builder |> hoplimit(:eq, 1) |> drop()

      # Block low hop limit (potential spoofing)
      builder |> hoplimit(:lt, 10) |> drop()

  ## Use Cases

  - IPv6 traceroute blocking
  - Anti-spoofing (low hop limits)
  - TTL normalization checks
  """
  @spec hoplimit(Expr.t(), atom(), non_neg_integer()) :: Expr.t()
  def hoplimit(builder \\ Expr.expr(), op, hoplimit)
      when is_integer(hoplimit) and hoplimit >= 0 and hoplimit <= 255 do
    op_str = atom_to_op(op)
    expr = Expr.Structs.payload_match("ip6", "hoplimit", hoplimit, op_str)
    Expr.add_expr(builder, expr)
  end

  # Private helpers

  # Helper to convert atom operators to string
  defp atom_to_op(:eq), do: "=="
  defp atom_to_op(:ne), do: "!="
  defp atom_to_op(:lt), do: "<"
  defp atom_to_op(:gt), do: ">"
  defp atom_to_op(:le), do: "<="
  defp atom_to_op(:ge), do: ">="

  # Format IP address - convert binary to string if needed
  defp format_ip(ip) when byte_size(ip) == 4 do
    # IPv4 binary format: <<192, 168, 1, 100>>
    <<a, b, c, d>> = ip
    "#{a}.#{b}.#{c}.#{d}"
  end

  defp format_ip(ip) when byte_size(ip) == 16 do
    # IPv6 binary format - convert to string
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = ip

    parts =
      [a, b, c, d, e, f, g, h]
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
        {:ok, {a, b, c, d}} ->
          "#{a}.#{b}.#{c}.#{d}"

        {:ok, {a, b, c, d, e, f, g, h}} ->
          parts =
            [a, b, c, d, e, f, g, h]
            |> Enum.map(&Integer.to_string(&1, 16))
            |> Enum.map(&String.downcase/1)

          Enum.join(parts, ":")

        # Return as-is if can't parse
        {:error, _} ->
          ip
      end
    end
  end
end
