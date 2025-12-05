defmodule NFTables.Expr.Payload do
  @moduledoc """
  Raw payload matching functions for deep packet inspection.

  This module provides functions to match arbitrary bytes at specific offsets within
  packet headers, bypassing protocol-specific parsing. This is essential for custom
  protocols, deep packet inspection (DPI), and advanced packet manipulation.

  ## Important: Bit-Level Operations

  **All offsets and lengths are specified in BITS, not bytes!**

  To convert: `byte_offset * 8 = bit_offset`

  Example: Byte offset 12 = Bit offset 96 (12 × 8)

  ## Base References

  - `:ll` - Link layer (Ethernet header start)
  - `:nh` - Network header (IP header start)
  - `:th` - Transport header (TCP/UDP header start)
  - `:ih` - Inner header (for tunneled packets)

  ## Common Use Cases

  - Custom protocol matching
  - Deep packet inspection
  - Protocol extension headers
  - Tunneled packet inspection
  - Advanced DPI rules

  ## Import

      import NFTables.Expr.Payload

  For more information, see the [nftables payload expressions wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers).
  """

  alias NFTables.Expr

  @doc """
  Match raw payload bytes at specific offset.

  Allows matching arbitrary bytes at specific offsets within packet headers.
  Remember: offsets and lengths are in **bits**, not bytes!

  ## Parameters

  - `builder` - Expression builder
  - `base` - Base reference point (`:ll`, `:nh`, `:th`, `:ih`)
  - `offset` - **Bit** offset from base (not bytes!)
  - `length` - Number of **bits** to match
  - `value` - Value to match against (integer, binary, or string)

  ## Examples

      # Match DNS port (53) using raw payload at transport header offset 16 bits
      udp()
      |> payload_raw(:th, 16, 16, 53)
      |> accept()

      # Match IPv4 source address 192.168.1.1 (network header, byte 12-15 = bits 96-127)
      payload_raw(:nh, 96, 32, <<192, 168, 1, 1>>)
      |> drop()

      # Match IPv6 next header field (routing header = 43)
      protocol(:ipv6)
      |> payload_raw(:nh, 48, 8, 43)
      |> drop()

      # Match first 4 bytes of HTTP GET request (inner header)
      tcp()
      |> dport(80)
      |> payload_raw(:ih, 0, 32, "GET ")
      |> log("HTTP GET")
      |> accept()

      # Match TCP SYN flag (transport header byte 13, bit 1)
      payload_raw(:th, 104, 8, 0x02)
      |> log("SYN packet")

  ## Offset Calculation Examples

  ### TCP Header

  - Source port: byte 0-1 = bits 0-15
  - Dest port: byte 2-3 = bits 16-31
  - Sequence: byte 4-7 = bits 32-63
  - Flags: byte 13 = bits 104-111

  ### IPv4 Header

  - Protocol: byte 9 = bits 72-79
  - Source IP: byte 12-15 = bits 96-127
  - Dest IP: byte 16-19 = bits 128-159

  ## Notes

  - Network byte order (big endian) is assumed
  - Values can be integers, binaries, or strings
  - For string values, they're converted to bytes
  """
  @spec payload_raw(Expr.t(), atom(), non_neg_integer(), pos_integer(), term()) :: Expr.t()
  def payload_raw(builder \\ Expr.expr(), base, offset, length, value) do
    expr = Expr.Structs.payload_raw_match(base, offset, length, value)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match raw payload with bitwise AND mask.

  Allows checking specific bits within a field using bitwise operations. Useful for
  flag checking, field masking, and partial field matching.

  ## How It Works

  1. Extract bits from packet: `field = packet[offset:offset+length]`
  2. Apply mask: `masked = field & mask`
  3. Compare: `masked == value`

  ## Parameters

  - `builder` - Expression builder
  - `base` - Base reference (`:ll`, `:nh`, `:th`, `:ih`)
  - `offset` - **Bit** offset from base
  - `length` - Number of **bits**
  - `mask` - Bitmask to apply (integer)
  - `value` - Value to match after masking

  ## Examples

      # Check TCP SYN flag (bit 1 in TCP flags byte at offset 104 bits)
      tcp()
      |> payload_raw_masked(:th, 104, 8, 0x02, 0x02)
      |> accept()

      # Check IP DF (Don't Fragment) flag (bit 14 in flags field)
      payload_raw_masked(:nh, 48, 16, 0x4000, 0x4000)
      |> drop()

      # Check if specific bit is set in custom protocol
      payload_raw_masked(:ih, 8, 8, 0x80, 0x80)
      |> counter()
      |> accept()

      # Match TCP flags: SYN+ACK (check bits 0 and 1)
      payload_raw_masked(:th, 104, 8, 0x12, 0x12)
      |> log("SYN-ACK")

  ## TCP Flags Reference

  TCP flags byte (offset 104 bits / byte 13):
  - `0x01` - FIN
  - `0x02` - SYN
  - `0x04` - RST
  - `0x08` - PSH
  - `0x10` - ACK
  - `0x20` - URG

  ## Use Cases

  - TCP flag checking (SYN, ACK, FIN, RST)
  - IP flag inspection (DF, MF)
  - Custom protocol bit flags
  - Selective field matching
  - Partial value extraction
  """
  @spec payload_raw_masked(
          Expr.t(),
          atom(),
          non_neg_integer(),
          pos_integer(),
          integer(),
          integer()
        ) :: Expr.t()
  def payload_raw_masked(builder \\ Expr.expr(), base, offset, length, mask, value) do
    payload_expr = Expr.Structs.payload_raw(base, offset, length)
    expr = Expr.Structs.bitwise_and_match(payload_expr, mask, value)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Extract raw payload value for use in other operations.

  Returns a payload expression that can be used as a key or value in set operations,
  packet mangling, or other advanced matching. This is a lower-level function that
  doesn't directly add to the builder.

  ## Parameters

  - `base` - Base reference (`:ll`, `:nh`, `:th`, `:ih`)
  - `offset` - **Bit** offset from base
  - `length` - Number of **bits** to extract

  ## Examples

      # Extract source IP as raw payload for set matching
      key = payload_raw_expr(:nh, 96, 32)

      # Use in advanced matching
      custom_match(key, "value")

  ## Use Cases

  - Set lookup keys
  - Dynamic value extraction
  - Packet mangling sources
  - Advanced rule compositions
  """
  @spec payload_raw_expr(atom(), non_neg_integer(), pos_integer()) :: map()
  def payload_raw_expr(base, offset, length) do
    Expr.Structs.payload_raw(base, offset, length)
  end
end
