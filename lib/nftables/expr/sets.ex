defmodule NFTables.Expr.Sets do
  @moduledoc """
  Named set matching functions for firewall rules.

  This module provides functions to match packets against named sets. Sets are
  collections of IP addresses, ports, or other values that can be efficiently matched
  against. Sets must be created separately using the NFTables Builder API.

  ## Common Use Cases

  - IP blocklists and allowlists
  - Port whitelisting
  - Dynamic blacklisting
  - Efficient multi-value matching

  ## Import

      import NFTables.Expr.Sets

  For more information, see the [nftables sets wiki](https://wiki.nftables.org/wiki-nftables/index.php/Sets).
  """

  alias NFTables.Expr

  @doc """
  Match against a named set.

  The set must already exist in the table. Use NFTables.add/2 with `set:` option
  to create sets before using them in rules.

  ## Set Types

  - `:saddr` - Source IP address (supports IPv4 and IPv6 based on family)
  - `:daddr` - Destination IP address (supports IPv4 and IPv6 based on family)
  - `:sport` - Source port (requires protocol context: tcp/udp/sctp/dccp)
  - `:dport` - Destination port (requires protocol context: tcp/udp/sctp/dccp)

  ## Protocol Context

  Port matching (`:sport`, `:dport`) requires protocol context from `tcp()`, `udp()`,
  `sctp()`, or `dccp()`. IP matching (`:saddr`, `:daddr`) uses the rule's family
  to determine IPv4 ("ip") or IPv6 ("ip6") protocol.

  ## Examples

      # IPv4 blocklist
      set("@ipv4_blocklist", :saddr) |> drop()

      # IPv6 blocklist - automatically uses ip6 protocol
      expr(family: :inet6)
      |> set("@ipv6_blocklist", :saddr)
      |> drop()

      # TCP port set - requires tcp() for protocol context
      tcp()
      |> set("@allowed_ports", :dport)
      |> accept()

      # UDP port set
      udp()
      |> set("@dns_ports", :sport)
      |> accept()

      # Whitelist specific IPs for SSH
      tcp()
      |> dport(22)
      |> set("@ssh_allowed", :saddr)
      |> accept()

  ## Creating Sets

  Sets must be created before use:

      NFTables.add(table: "filter")
      |> NFTables.add(set: "ipv4_blocklist", type: :ipv4_addr)
      |> NFTables.add(element: ["1.2.3.4", "5.6.7.8"], set: "ipv4_blocklist")
      |> NFTables.submit(pid: pid)

  ## Error Handling

  This function will raise an `ArgumentError` if:
  - Port matching is used without protocol context
  - Invalid match type is specified
  """
  @spec set(Expr.t(), String.t(), atom()) :: Expr.t()
  def set(builder \\ Expr.expr(), set_name, match_type) when is_binary(set_name) do
    # Ensure set name starts with @
    set_ref = if String.starts_with?(set_name, "@"), do: set_name, else: "@#{set_name}"

    expr =
      case match_type do
        :saddr ->
          ip_proto = get_ip_protocol(builder)

          %{
            "match" => %{
              "left" => %{"payload" => %{"protocol" => ip_proto, "field" => "saddr"}},
              "right" => set_ref,
              "op" => "=="
            }
          }

        :daddr ->
          ip_proto = get_ip_protocol(builder)

          %{
            "match" => %{
              "left" => %{"payload" => %{"protocol" => ip_proto, "field" => "daddr"}},
              "right" => set_ref,
              "op" => "=="
            }
          }

        :sport ->
          port_proto = get_port_protocol!(builder, :sport)

          %{
            "match" => %{
              "left" => %{"payload" => %{"protocol" => port_proto, "field" => "sport"}},
              "right" => set_ref,
              "op" => "=="
            }
          }

        :dport ->
          port_proto = get_port_protocol!(builder, :dport)

          %{
            "match" => %{
              "left" => %{"payload" => %{"protocol" => port_proto, "field" => "dport"}},
              "right" => set_ref,
              "op" => "=="
            }
          }

        other ->
          raise ArgumentError, "Invalid set match type: #{inspect(other)}"
      end

    Expr.add_expr(builder, expr)
  end

  # Private: Get protocol from builder context for port matching
  defp get_port_protocol!(builder, field_name) do
    case builder.protocol do
      nil ->
        raise ArgumentError,
              "set/3 with :#{field_name} requires protocol context. " <>
                "Call tcp(), udp(), sctp(), or dccp() before using set/3 with :#{field_name}.\n\n" <>
                "Example: expr() |> tcp() |> set(\"@ports\", :#{field_name})"

      protocol when protocol in [:tcp, :udp, :sctp, :dccp] ->
        to_string(protocol)

      other ->
        raise ArgumentError,
              "set/3 with :#{field_name} requires a protocol with port fields (tcp, udp, sctp, dccp), got: #{inspect(other)}\n\n" <>
                "Use tcp(), udp(), sctp(), or dccp() before calling set/3 with :#{field_name}."
    end
  end

  # Private: Get IP protocol version from builder family
  defp get_ip_protocol(builder) do
    case builder.family do
      :ip6 -> "ip6"
      :inet6 -> "ip6"
      # Default to IPv4 (includes :inet, :ip, :arp, :bridge, etc.)
      _ -> "ip"
    end
  end
end
