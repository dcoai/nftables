defmodule NFTables.Match.Layer2 do
  @moduledoc """
  Layer 2 (MAC, interface, VLAN) matching functions for Match.

  Provides functions for matching MAC addresses, network interfaces, and VLAN tags.
  """

  alias NFTables.{Match, Expr}

  @doc """
  Match source MAC address.

  ## Example

      builder |> source_mac("aa:bb:cc:dd:ee:ff")
  """
  @spec source_mac(Match.t(), String.t()) :: Match.t()
  def source_mac(builder, mac) when is_binary(mac) do
    expr = Expr.payload_match("ether", "saddr", mac)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match destination MAC address.

  ## Example

      builder |> dest_mac("aa:bb:cc:dd:ee:ff")
  """
  @spec dest_mac(Match.t(), String.t()) :: Match.t()
  def dest_mac(builder, mac) when is_binary(mac) do
    expr = Expr.payload_match("ether", "daddr", mac)
    Match.add_expr(builder, expr)
  end

  @doc "Match input interface name"
  @spec iif(Match.t(), String.t()) :: Match.t()
  def iif(builder, ifname) when is_binary(ifname) do
    expr = Expr.meta_match("iifname", ifname)
    Match.add_expr(builder, expr)
  end

  @doc "Match output interface name"
  @spec oif(Match.t(), String.t()) :: Match.t()
  def oif(builder, ifname) when is_binary(ifname) do
    expr = Expr.meta_match("oifname", ifname)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match VLAN ID.

  Used for VLAN-aware bridge filtering.

  ## Example

      # Match VLAN 100
      builder |> vlan_id(100) |> accept()

      # Match VLAN range (using multiple rules)
      builder |> vlan_id(50) |> jump("vlan_50")
  """
  @spec vlan_id(Match.t(), non_neg_integer()) :: Match.t()
  def vlan_id(builder, vlan_id) when is_integer(vlan_id) and vlan_id >= 0 and vlan_id <= 4095 do
    expr = Expr.payload_match("vlan", "id", vlan_id)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match VLAN priority (PCP).

  ## Example

      # Match high priority VLAN traffic
      builder |> vlan_pcp(7) |> accept()
  """
  @spec vlan_pcp(Match.t(), non_neg_integer()) :: Match.t()
  def vlan_pcp(builder, pcp) when is_integer(pcp) and pcp >= 0 and pcp <= 7 do
    expr = Expr.payload_match("vlan", "pcp", pcp)
    Match.add_expr(builder, expr)
  end
end
