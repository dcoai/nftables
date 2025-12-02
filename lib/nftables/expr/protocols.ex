defmodule NFTables.Expr.Protocols do
  @moduledoc """
  Advanced protocol matching helpers for SCTP, DCCP, and GRE.

  Provides convenient functions for matching less common protocols that are
  not part of the standard TCP/UDP/ICMP set.

  ## Supported Protocols

  - **SCTP** (Stream Control Transmission Protocol) - Reliable, message-oriented transport
  - **DCCP** (Datagram Congestion Control Protocol) - Congestion-controlled unreliable datagrams
  - **GRE** (Generic Routing Encapsulation) - Tunneling protocol

  ## Usage

      import NFTables.Match
      import NFTables.Match.Protocols  # Or use via Match module

      # SCTP port matching (use generic dport/sport from Port module)
      rule()
      |> sctp()
      |> dport(9899)
      |> accept()

      # DCCP with ports (use generic dport/sport from Port module)
      rule()
      |> dccp()
      |> sport(5000)
      |> dport(6000)
      |> counter()

      # GRE tunnel
      rule()
      |> gre()
      |> gre_version(0)
      |> accept()
  """

  alias NFTables.Expr

  ## SCTP (Stream Control Transmission Protocol)

  @doc """
  Match SCTP protocol.

  SCTP is a reliable, message-oriented transport protocol that combines
  features of TCP and UDP. Common uses include telephony signaling (SS7),
  WebRTC data channels, and high-availability clustering.

  ## Examples

      # Match any SCTP traffic
      rule()
      |> sctp()
      |> accept()

      # Combine with other matchers
      rule()
      |> sctp()
      |> source_ip("192.168.1.0/24")
      |> counter()

  ## Protocol Number

  SCTP uses IP protocol number 132.
  """
  @spec sctp(Expr.t()) :: Expr.t()
  def sctp(builder) do
    expr = Expr.Structs.payload_match("ip", "protocol", "sctp")

    builder
    |> Expr.add_expr(expr)
    |> Expr.set_protocol(:sctp)
  end

  ## DCCP (Datagram Congestion Control Protocol)

  @doc """
  Match DCCP protocol.

  DCCP is a transport protocol that provides congestion control for unreliable
  datagrams. Useful for real-time applications that can tolerate packet loss
  but need congestion control (e.g., streaming media, online gaming).

  ## Examples

      # Match any DCCP traffic
      rule()
      |> dccp()
      |> counter()

      # DCCP with logging
      rule()
      |> dccp()
      |> log("DCCP packet: ")
      |> accept()

  ## Protocol Number

  DCCP uses IP protocol number 33.
  """
  @spec dccp(Expr.t()) :: Expr.t()
  def dccp(builder) do
    expr = Expr.Structs.payload_match("ip", "protocol", "dccp")

    builder
    |> Expr.add_expr(expr)
    |> Expr.set_protocol(:dccp)
  end

  ## GRE (Generic Routing Encapsulation)

  @doc """
  Match GRE protocol.

  GRE is a tunneling protocol used to encapsulate packets inside IP packets.
  Common uses include VPNs, PPTP, and network virtualization (e.g., NVGRE).

  ## Examples

      # Match any GRE traffic
      rule()
      |> gre()
      |> counter()

      # GRE tunnel from specific source
      rule()
      |> gre()
      |> source_ip("10.0.0.1")
      |> accept()

  ## Protocol Number

  GRE uses IP protocol number 47.
  """
  @spec gre(Expr.t()) :: Expr.t()
  def gre(builder) do
    expr = Expr.Structs.payload_match("ip", "protocol", "gre")

    builder
    |> Expr.add_expr(expr)
    |> Expr.set_protocol(:gre)
  end

  @doc """
  Match GRE version.

  GRE has two versions:
  - Version 0: Standard GRE (RFC 2784)
  - Version 1: Enhanced GRE used by PPTP (RFC 2637)

  ## Examples

      # Match standard GRE (version 0)
      rule()
      |> gre_version(0)
      |> accept()

      # Match PPTP GRE (version 1)
      rule()
      |> gre_version(1)
      |> log("PPTP tunnel: ")
      |> accept()
  """
  @spec gre_version(Expr.t(), non_neg_integer()) :: Expr.t()
  def gre_version(builder, version) when is_integer(version) and version >= 0 do
    builder
    |> ensure_gre()
    |> Expr.add_expr(Expr.Structs.payload_match("gre", "version", version))
  end

  @doc """
  Match GRE key.

  The GRE key field is used to identify traffic flows within GRE tunnels.
  Commonly used for:
  - Multi-tenant isolation
  - Traffic classification
  - GRE over IPsec

  ## Examples

      # Match specific GRE tunnel key
      rule()
      |> gre_key(12345)
      |> accept()

      # Route based on GRE key
      rule()
      |> gre_key(100)
      |> set_mark(1)
      |> accept()

  ## Notes

  The key field must be present in the GRE header (flags bit set).
  Not all GRE packets include a key field.
  """
  @spec gre_key(Expr.t(), non_neg_integer()) :: Expr.t()
  def gre_key(builder, key) when is_integer(key) and key >= 0 do
    builder
    |> ensure_gre()
    |> Expr.add_expr(Expr.Structs.payload_match("gre", "key", key))
  end

  @doc """
  Match GRE flags.

  GRE flags control optional features:
  - Checksum present
  - Routing present
  - Key present
  - Sequence number present
  - Strict source route

  ## Examples

      # Match GRE packets with key flag set
      rule()
      |> gre_flags(0x2000)  # Key bit
      |> accept()

  ## Flags Bitmask

  - 0x8000: Checksum present
  - 0x4000: Routing present
  - 0x2000: Key present
  - 0x1000: Sequence number present
  - 0x0800: Strict source route
  """
  @spec gre_flags(Expr.t(), non_neg_integer()) :: Expr.t()
  def gre_flags(builder, flags) when is_integer(flags) and flags >= 0 do
    builder
    |> ensure_gre()
    |> Expr.add_expr(Expr.Structs.payload_match("gre", "flags", flags))
  end

  ## Private Helpers

  # Ensure GRE protocol is set (auto-add if needed)
  defp ensure_gre(%Expr{protocol: :gre} = builder), do: builder
  defp ensure_gre(builder), do: gre(builder)
end
