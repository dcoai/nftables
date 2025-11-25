defmodule NFTables.Match.IP do
  @moduledoc """
  IP address matching functions for Match.

  Provides functions to match source and destination IP addresses (IPv4 and IPv6).
  """

  alias NFTables.{Match, Expr}

  @doc """
  Match source IP address.

  Accepts either a string IP ("192.168.1.100") or binary form (<<192, 168, 1, 100>>).

  ## Examples

      builder
      |> IP.source_ip("192.168.1.100")

      builder
      |> IP.source_ip("2001:db8::1")
  """
  @spec source_ip(Match.t(), String.t() | binary()) :: Match.t()
  def source_ip(builder, ip) when is_binary(ip) do
    ip_str = format_ip(ip)

    # Determine IP version based on family or IP format
    protocol = case builder.family do
      :ip6 -> "ip6"
      :inet6 -> "ip6"
      _ -> if String.contains?(ip_str, ":"), do: "ip6", else: "ip"
    end

    # Build JSON expression for IP source address match
    expr = if String.contains?(ip_str, "/") do
      # CIDR notation - use prefix match
      [addr, prefix_len] = String.split(ip_str, "/", parts: 2)
      Expr.payload_match_prefix(protocol, "saddr", addr, String.to_integer(prefix_len))
    else
      # Single IP - use regular match
      Expr.payload_match(protocol, "saddr", ip_str)
    end
    Match.add_expr(builder, expr)
  end

  @doc """
  Match destination IP address.

  Accepts either a string IP ("192.168.1.100") or binary form (<<192, 168, 1, 100>>).

  ## Examples

      builder
      |> IP.dest_ip("192.168.1.100")

      builder
      |> IP.dest_ip("2001:db8::1")
  """
  @spec dest_ip(Match.t(), String.t() | binary()) :: Match.t()
  def dest_ip(builder, ip) when is_binary(ip) do
    ip_str = format_ip(ip)

    # Determine IP version based on family or IP format
    protocol = case builder.family do
      :ip6 -> "ip6"
      :inet6 -> "ip6"
      _ -> if String.contains?(ip_str, ":"), do: "ip6", else: "ip"
    end

    # Build JSON expression for IP destination address match
    expr = if String.contains?(ip_str, "/") do
      # CIDR notation - use prefix match
      [addr, prefix_len] = String.split(ip_str, "/", parts: 2)
      Expr.payload_match_prefix(protocol, "daddr", addr, String.to_integer(prefix_len))
    else
      # Single IP - use regular match
      Expr.payload_match(protocol, "daddr", ip_str)
    end
    Match.add_expr(builder, expr)
  end

  # Private helpers

  # Format IP address - convert binary to string if needed
  defp format_ip(ip) when byte_size(ip) == 4 do
    # IPv4 binary format: <<192, 168, 1, 100>>
    <<a, b, c, d>> = ip
    "#{a}.#{b}.#{c}.#{d}"
  end

  defp format_ip(ip) when byte_size(ip) == 16 do
    # IPv6 binary format - convert to string
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
