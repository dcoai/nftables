defmodule NFTables.Expr.Layer2 do
  @moduledoc """
  Layer 2 (MAC, interface, VLAN) matching functions for Expr.

  Provides functions for matching MAC addresses, network interfaces, and VLAN tags.
  """

  alias NFTables.Expr

  @doc """
  Match source MAC address.

  ## Example

      builder |> source_mac("aa:bb:cc:dd:ee:ff")
  """
  @spec source_mac(Expr.t(), String.t()) :: Expr.t()
  def source_mac(builder \\ Expr.expr(), mac) when is_binary(mac) do
    expr = Expr.Structs.payload_match("ether", "saddr", mac)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match destination MAC address.

  ## Example

      builder |> dest_mac("aa:bb:cc:dd:ee:ff")
  """
  @spec dest_mac(Expr.t(), String.t()) :: Expr.t()
  def dest_mac(builder \\ Expr.expr(), mac) when is_binary(mac) do
    expr = Expr.Structs.payload_match("ether", "daddr", mac)
    Expr.add_expr(builder, expr)
  end

  @doc "Match input interface name"
  @spec iif(Expr.t(), String.t()) :: Expr.t()
  def iif(builder \\ Expr.expr(), ifname) when is_binary(ifname) do
    expr = Expr.Structs.meta_match("iifname", ifname)
    Expr.add_expr(builder, expr)
  end

  @doc "Match output interface name"
  @spec oif(Expr.t(), String.t()) :: Expr.t()
  def oif(builder \\ Expr.expr(), ifname) when is_binary(ifname) do
    expr = Expr.Structs.meta_match("oifname", ifname)
    Expr.add_expr(builder, expr)
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
  @spec vlan_id(Expr.t(), non_neg_integer()) :: Expr.t()
  def vlan_id(builder \\ Expr.expr(), vlan_id)
      when is_integer(vlan_id) and vlan_id >= 0 and vlan_id <= 4095 do
    expr = Expr.Structs.payload_match("vlan", "id", vlan_id)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match VLAN priority (PCP).

  ## Example

      # Match high priority VLAN traffic
      builder |> vlan_pcp(7) |> accept()
  """
  @spec vlan_pcp(Expr.t(), non_neg_integer()) :: Expr.t()
  def vlan_pcp(builder \\ Expr.expr(), pcp) when is_integer(pcp) and pcp >= 0 and pcp <= 7 do
    expr = Expr.Structs.payload_match("vlan", "pcp", pcp)
    Expr.add_expr(builder, expr)
  end
end
