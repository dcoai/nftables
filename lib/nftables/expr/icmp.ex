defmodule NFTables.Expr.ICMP do
  @moduledoc """
  ICMP and ICMPv6 matching functions for firewall rules.

  This module provides functions to match ICMP (Internet Control Message Protocol)
  packets for both IPv4 (ICMP) and IPv6 (ICMPv6). ICMP is used for diagnostic and
  control messages like ping, traceroute, and network error reporting.

  ## Common Use Cases

  - Allow ping (echo request/reply)
  - Block specific ICMP types for security
  - Allow ICMPv6 neighbor discovery (essential for IPv6)
  - Log ICMP unreachable messages

  ## Import

      import NFTables.Expr.ICMP

  For more information, see the [nftables ICMP wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_ICMP_traffic).
  """

  alias NFTables.Expr

  @doc """
  Match ICMP type (IPv4).

  ## Common ICMP Types

  - `0` or `:echo_reply` - Echo Reply (ping response)
  - `3` or `:dest_unreachable` - Destination Unreachable
  - `8` or `:echo_request` - Echo Request (ping)
  - `11` or `:time_exceeded` - Time Exceeded (traceroute)
  - `13` or `:timestamp_request` - Timestamp Request
  - `14` or `:timestamp_reply` - Timestamp Reply

  ## Example

      # Allow ping requests
      icmp_type(:echo_request) |> accept()

      # Block all ICMP except ping
      icmp_type(:echo_request) |> accept()
      protocol(:icmp) |> drop()
  """
  @spec icmp_type(Expr.t(), atom() | non_neg_integer()) :: Expr.t()
  def icmp_type(builder \\ Expr.expr(), type) do
    type_val =
      case type do
        :echo_reply -> "echo-reply"
        :dest_unreachable -> "destination-unreachable"
        :source_quench -> "source-quench"
        :redirect -> "redirect"
        :echo_request -> "echo-request"
        :router_advertisement -> "router-advertisement"
        :router_solicitation -> "router-solicitation"
        :time_exceeded -> "time-exceeded"
        :parameter_problem -> "parameter-problem"
        :timestamp_request -> "timestamp-request"
        :timestamp_reply -> "timestamp-reply"
        :info_request -> "info-request"
        :info_reply -> "info-reply"
        :address_mask_request -> "address-mask-request"
        :address_mask_reply -> "address-mask-reply"
        num when is_integer(num) -> num
        other -> to_string(other)
      end

    expr = Expr.Structs.payload_match("icmp", "type", type_val)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match ICMP code (IPv4).

  Must be used in conjunction with icmp_type.

  ## Example

      # Match destination unreachable, port unreachable
      icmp_type(:dest_unreachable)
      |> icmp_code(3)
      |> accept()
  """
  @spec icmp_code(Expr.t(), non_neg_integer()) :: Expr.t()
  def icmp_code(builder \\ Expr.expr(), code)
      when is_integer(code) and code >= 0 and code <= 255 do
    expr = Expr.Structs.payload_match("icmp", "code", code)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match ICMPv6 type (IPv6).

  ## Common ICMPv6 Types

  - `1` or `:dest_unreachable` - Destination Unreachable
  - `128` or `:echo_request` - Echo Request (ping)
  - `129` or `:echo_reply` - Echo Reply
  - `133` or `:router_solicit` - Router Solicitation
  - `134` or `:router_advert` - Router Advertisement
  - `135` or `:neighbour_solicit` - Neighbor Solicitation
  - `136` or `:neighbour_advert` - Neighbor Advertisement

  ## Example

      # Allow ICMPv6 ping
      icmpv6_type(:echo_request) |> accept()

      # Allow neighbor discovery (essential for IPv6)
      icmpv6_type(:neighbour_solicit) |> accept()
      icmpv6_type(:neighbour_advert) |> accept()
  """
  @spec icmpv6_type(Expr.t(), atom() | non_neg_integer()) :: Expr.t()
  def icmpv6_type(builder \\ Expr.expr(), type) do
    type_val =
      case type do
        :dest_unreachable -> "destination-unreachable"
        :packet_too_big -> "packet-too-big"
        :time_exceeded -> "time-exceeded"
        :param_problem -> "parameter-problem"
        :echo_request -> "echo-request"
        :echo_reply -> "echo-reply"
        :router_solicit -> "nd-router-solicit"
        :router_advert -> "nd-router-advert"
        :neighbour_solicit -> "nd-neighbor-solicit"
        :neighbour_advert -> "nd-neighbor-advert"
        :redirect -> "nd-redirect"
        num when is_integer(num) -> num
        other -> to_string(other)
      end

    expr = Expr.Structs.payload_match("icmpv6", "type", type_val)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match ICMPv6 code (IPv6).

  Must be used in conjunction with icmpv6_type.

  ## Example

      icmpv6_type(:dest_unreachable)
      |> icmpv6_code(4)
      |> drop()
  """
  @spec icmpv6_code(Expr.t(), non_neg_integer()) :: Expr.t()
  def icmpv6_code(builder \\ Expr.expr(), code)
      when is_integer(code) and code >= 0 and code <= 255 do
    expr = Expr.Structs.payload_match("icmpv6", "code", code)
    Expr.add_expr(builder, expr)
  end
end
