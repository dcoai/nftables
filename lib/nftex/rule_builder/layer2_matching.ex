defmodule NFTex.RuleBuilder.Layer2Matching do
  @moduledoc """
  Layer 2 (MAC, interface, VLAN) matching functions for RuleBuilder.

  Provides functions for matching MAC addresses, network interfaces, and VLAN tags.
  """

  alias NFTex.RuleBuilder

  @doc """
  Match source MAC address.

  ## Example

      builder |> match_source_mac("aa:bb:cc:dd:ee:ff")
  """
  @spec match_source_mac(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def match_source_mac(builder, mac) when is_binary(mac) do
    RuleBuilder.add_part(builder, "ether saddr #{mac}")
  end

  @doc """
  Match destination MAC address.

  ## Example

      builder |> match_dest_mac("aa:bb:cc:dd:ee:ff")
  """
  @spec match_dest_mac(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def match_dest_mac(builder, mac) when is_binary(mac) do
    RuleBuilder.add_part(builder, "ether daddr #{mac}")
  end

  @doc "Match input interface name"
  @spec match_iif(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def match_iif(builder, ifname) when is_binary(ifname) do
    RuleBuilder.add_part(builder, "iifname #{inspect(ifname)}")
  end

  @doc "Match output interface name"
  @spec match_oif(RuleBuilder.t(), String.t()) :: RuleBuilder.t()
  def match_oif(builder, ifname) when is_binary(ifname) do
    RuleBuilder.add_part(builder, "oifname #{inspect(ifname)}")
  end

  @doc """
  Match VLAN ID.

  Used for VLAN-aware bridge filtering.

  ## Example

      # Match VLAN 100
      builder |> match_vlan_id(100) |> accept()

      # Match VLAN range (using multiple rules)
      builder |> match_vlan_id(50) |> jump("vlan_50")
  """
  @spec match_vlan_id(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_vlan_id(builder, vlan_id) when is_integer(vlan_id) and vlan_id >= 0 and vlan_id <= 4095 do
    RuleBuilder.add_part(builder, "vlan id #{vlan_id}")
  end

  @doc """
  Match VLAN priority (PCP).

  ## Example

      # Match high priority VLAN traffic
      builder |> match_vlan_pcp(7) |> accept()
  """
  @spec match_vlan_pcp(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_vlan_pcp(builder, pcp) when is_integer(pcp) and pcp >= 0 and pcp <= 7 do
    RuleBuilder.add_part(builder, "vlan pcp #{pcp}")
  end
end
