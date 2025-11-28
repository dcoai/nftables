defmodule NFTables.Match.Advanced do
  @moduledoc """
  Advanced matching functions for Match.

  Provides functions for ICMP, packet metadata (marks, DSCP, fragmentation),
  packet type classification, cgroup matching, socket owner matching,
  IPsec SPI, ARP operations, and set matching.
  """

  alias NFTables.{Match, Expr}

  # Packet metadata matching

  @doc """
  Match packet mark.

  Useful for policy routing and traffic control.

  ## Example

      builder |> mark(100)
  """
  @spec mark(Match.t(), non_neg_integer()) :: Match.t()
  def mark(builder, mark) when is_integer(mark) and mark >= 0 do
    expr = Expr.meta_match("mark", mark)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match DSCP (Differentiated Services Code Point).

  ## Example

      # Match expedited forwarding
      builder |> dscp(46)

      # Match assured forwarding
      builder |> dscp(10)
  """
  @spec dscp(Match.t(), non_neg_integer()) :: Match.t()
  def dscp(builder, dscp) when is_integer(dscp) and dscp >= 0 and dscp <= 63 do
    expr = Expr.payload_match("ip", "dscp", dscp)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match fragmented packets.

  ## Example

      # Match fragmented packets
      builder |> fragmented(true)

      # Match non-fragmented packets
      builder |> fragmented(false)
  """
  @spec fragmented(Match.t(), boolean()) :: Match.t()
  def fragmented(builder, true) do
    # ip frag-off & 0x1fff != 0
    expr = %{
      "match" => %{
        "left" => %{
          "&" => [
            %{"payload" => %{"protocol" => "ip", "field" => "frag-off"}},
            0x1FFF
          ]
        },
        "right" => 0,
        "op" => "!="
      }
    }
    Match.add_expr(builder, expr)
  end
  def fragmented(builder, false) do
    # ip frag-off & 0x1fff == 0
    expr = %{
      "match" => %{
        "left" => %{
          "&" => [
            %{"payload" => %{"protocol" => "ip", "field" => "frag-off"}},
            0x1FFF
          ]
        },
        "right" => 0,
        "op" => "=="
      }
    }
    Match.add_expr(builder, expr)
  end

  # ICMP matching

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
      builder |> icmp_type(:echo_request) |> accept()

      # Block all ICMP except ping
      builder |> icmp_type(:echo_request) |> accept()
      builder |> protocol(:icmp) |> drop()
  """
  @spec icmp_type(Match.t(), atom() | non_neg_integer()) :: Match.t()
  def icmp_type(builder, type) do
    type_val = case type do
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
    expr = Expr.payload_match("icmp", "type", type_val)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match ICMP code (IPv4).

  Must be used in conjunction with icmp_type.

  ## Example

      # Match destination unreachable, port unreachable
      builder
      |> icmp_type(:dest_unreachable)
      |> icmp_code(3)
      |> accept()
  """
  @spec icmp_code(Match.t(), non_neg_integer()) :: Match.t()
  def icmp_code(builder, code) when is_integer(code) and code >= 0 and code <= 255 do
    expr = Expr.payload_match("icmp", "code", code)
    Match.add_expr(builder, expr)
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
      builder |> icmpv6_type(:echo_request) |> accept()

      # Allow neighbor discovery
      builder |> icmpv6_type(:neighbour_solicit) |> accept()
      builder |> icmpv6_type(:neighbour_advert) |> accept()
  """
  @spec icmpv6_type(Match.t(), atom() | non_neg_integer()) :: Match.t()
  def icmpv6_type(builder, type) do
    type_val = case type do
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
    expr = Expr.payload_match("icmpv6", "type", type_val)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match ICMPv6 code (IPv6).

  Must be used in conjunction with icmpv6_type.

  ## Example

      builder
      |> icmpv6_type(:dest_unreachable)
      |> icmpv6_code(4)
      |> drop()
  """
  @spec icmpv6_code(Match.t(), non_neg_integer()) :: Match.t()
  def icmpv6_code(builder, code) when is_integer(code) and code >= 0 and code <= 255 do
    expr = Expr.payload_match("icmpv6", "code", code)
    Match.add_expr(builder, expr)
  end

  # Packet type and metadata

  @doc """
  Match packet type (unicast, broadcast, multicast).

  ## Packet Types

  - `:unicast` - Unicast packet
  - `:broadcast` - Broadcast packet
  - `:multicast` - Multicast packet
  - `:other` - Other packet types

  ## Example

      # Drop broadcast packets
      builder |> pkttype(:broadcast) |> drop()

      # Rate limit multicast
      builder |> pkttype(:multicast) |> rate_limit(100, :second) |> accept()

      # Allow only unicast
      builder |> pkttype(:unicast) |> accept()
  """
  @spec pkttype(Match.t(), atom()) :: Match.t()
  def pkttype(builder, pkttype) when pkttype in [:unicast, :broadcast, :multicast, :other] do
    expr = Expr.meta_match("pkttype", to_string(pkttype))
    Match.add_expr(builder, expr)
  end

  @doc """
  Match packet priority (SO_PRIORITY).

  ## Example

      # Match high priority traffic
      builder |> priority(:gt, 5) |> accept()

      # Match specific priority
      builder |> priority(:eq, 7) |> log("PRIO-7: ")
  """
  @spec priority(Match.t(), atom(), non_neg_integer()) :: Match.t()
  def priority(builder, op, priority) when is_integer(priority) and priority >= 0 do
    op_str = case op do
      :eq -> "=="
      :ne -> "!="
      :lt -> "<"
      :gt -> ">"
      :le -> "<="
      :ge -> ">="
    end
    expr = Expr.meta_match("priority", priority, op_str)
    Match.add_expr(builder, expr)
  end

  # Cgroup and socket matching

  @doc """
  Match cgroup (control group) ID.

  Used for container-specific filtering.

  ## Example

      # Match specific cgroup
      builder |> cgroup(1001) |> jump("container_rules")

      # Block cgroup
      builder |> cgroup(2000) |> drop()
  """
  @spec cgroup(Match.t(), non_neg_integer()) :: Match.t()
  def cgroup(builder, cgroup_id) when is_integer(cgroup_id) and cgroup_id >= 0 do
    expr = Expr.meta_match("cgroup", cgroup_id)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match packets by socket owner user ID.

  Matches packets based on the UID of the process that created the socket.
  Only works for locally-generated traffic (OUTPUT chain).

  ## Example

      # Block specific user from internet access
      builder
      |> skuid(1001)
      |> oif("wan0")
      |> reject()

      # Allow only root to access specific service
      builder
      |> skuid(0)
      |> tcp()
      |> dport(9000)
      |> accept()
  """
  @spec skuid(Match.t(), non_neg_integer()) :: Match.t()
  def skuid(builder, uid) when is_integer(uid) and uid >= 0 do
    expr = Expr.meta_match("skuid", uid)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match packets by socket owner group ID.

  Matches packets based on the GID of the process that created the socket.
  Only works for locally-generated traffic (OUTPUT chain).

  ## Example

      # Block specific group from internet access
      builder
      |> skgid(1002)
      |> oif("wan0")
      |> reject()

      # Allow specific group to access admin port
      builder
      |> skgid(100)
      |> tcp()
      |> dport(8443)
      |> accept()
  """
  @spec skgid(Match.t(), non_neg_integer()) :: Match.t()
  def skgid(builder, gid) when is_integer(gid) and gid >= 0 do
    expr = Expr.meta_match("skgid", gid)
    Match.add_expr(builder, expr)
  end

  # IPsec matching

  @doc """
  Match IPsec AH (Authentication Header) SPI.

  ## Example

      # Match specific AH SPI
      builder |> ah_spi(12345) |> accept()

      # Log IPsec AH traffic
      builder |> ah_spi(:any) |> log("IPSEC-AH: ")
  """
  @spec ah_spi(Match.t(), non_neg_integer() | :any) :: Match.t()
  def ah_spi(builder, :any) do
    # Match any AH SPI (just check if AH header exists)
    expr = %{"match" => %{
      "left" => %{"payload" => %{"protocol" => "ah", "field" => "spi"}},
      "right" => 0,
      "op" => ">="
    }}
    Match.add_expr(builder, expr)
  end
  def ah_spi(builder, spi) when is_integer(spi) and spi >= 0 do
    expr = Expr.payload_match("ah", "spi", spi)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match IPsec ESP (Encapsulating Security Payload) SPI.

  ## Example

      # Match specific ESP SPI
      builder |> esp_spi(54321) |> accept()

      # Match any ESP traffic
      builder |> esp_spi(:any) |> log("IPSEC-ESP: ")
  """
  @spec esp_spi(Match.t(), non_neg_integer() | :any) :: Match.t()
  def esp_spi(builder, :any) do
    # Match any ESP SPI (just check if ESP header exists)
    expr = %{"match" => %{
      "left" => %{"payload" => %{"protocol" => "esp", "field" => "spi"}},
      "right" => 0,
      "op" => ">="
    }}
    Match.add_expr(builder, expr)
  end
  def esp_spi(builder, spi) when is_integer(spi) and spi >= 0 do
    expr = Expr.payload_match("esp", "spi", spi)
    Match.add_expr(builder, expr)
  end

  # ARP matching

  @doc """
  Match ARP operation.

  ## Operations

  - `:request` (1) - ARP request
  - `:reply` (2) - ARP reply
  - Or numeric value

  ## Example

      # Match ARP requests
      builder |> arp_operation(:request) |> log("ARP-REQ: ")

      # Match ARP replies
      builder |> arp_operation(:reply) |> accept()
  """
  @spec arp_operation(Match.t(), atom() | non_neg_integer()) :: Match.t()
  def arp_operation(builder, operation) do
    op_val = case operation do
      :request -> 1
      :reply -> 2
      num when is_integer(num) -> num
      _ -> raise ArgumentError, "Invalid ARP operation: #{inspect(operation)}"
    end
    expr = Expr.payload_match("arp", "operation", op_val)
    Match.add_expr(builder, expr)
  end

  # Set matching

  @doc """
  Match against a named set.

  The set must already exist in the table. Use Builder to create sets.

  ## Examples

      # IPv4 blocklist
      rule()
      |> set("@ipv4_blocklist", :saddr)
      |> drop()

      # IPv6 blocklist - automatically uses ip6 protocol
      rule(family: :inet6)
      |> set("@ipv6_blocklist", :saddr)
      |> drop()

      # TCP port set - requires tcp() for protocol context
      rule()
      |> tcp()
      |> set("@allowed_ports", :dport)
      |> accept()

      # UDP port set - works with any protocol (tcp, udp, sctp, dccp)
      rule()
      |> udp()
      |> set("@dns_ports", :sport)
      |> accept()

  ## Set Types

  - `:saddr` - Source IP address (supports IPv4 and IPv6 based on family)
  - `:daddr` - Destination IP address (supports IPv4 and IPv6 based on family)
  - `:sport` - Source port (requires protocol context: tcp/udp/sctp/dccp)
  - `:dport` - Destination port (requires protocol context: tcp/udp/sctp/dccp)

  ## Protocol Context

  Port matching (`:sport`, `:dport`) requires protocol context from tcp(), udp(),
  sctp(), or dccp(). IP matching (`:saddr`, `:daddr`) uses the rule's family
  to determine IPv4 ("ip") or IPv6 ("ip6") protocol.
  """
  @spec set(Match.t(), String.t(), atom()) :: Match.t()
  def set(builder, set_name, match_type) when is_binary(set_name) do
    # Ensure set name starts with @
    set_ref = if String.starts_with?(set_name, "@"), do: set_name, else: "@#{set_name}"

    expr = case match_type do
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
      other -> raise ArgumentError, "Invalid set match type: #{inspect(other)}"
    end

    Match.add_expr(builder, expr)
  end

  ## Raw Payload Matching

  @doc """
  Match raw payload bytes at specific offset.

  Allows matching arbitrary bytes at specific offsets within packet headers,
  bypassing protocol-specific parsing. Essential for custom protocols or DPI.

  ## Parameters

  - `builder` - Match builder
  - `base` - Base reference point:
    - `:ll` - Link layer (Ethernet header start)
    - `:nh` - Network header (IP header start)
    - `:th` - Transport header (TCP/UDP header start)
    - `:ih` - Inner header (for tunneled packets)
  - `offset` - **Bit** offset from base (not byte!)
  - `length` - Number of **bits** to match
  - `value` - Value to match against

  ## Examples

      # Match DNS port (53) using raw payload at transport header offset 16
      rule()
      |> udp()
      |> payload_raw(:th, 16, 16, 53)
      |> accept()

      # Match IPv4 source address using raw payload
      rule()
      |> payload_raw(:nh, 96, 32, <<192, 168, 1, 1>>)
      |> drop()

      # Match IPv6 next header (routing header = 43)
      rule()
      |> protocol(:ipv6)
      |> payload_raw(:nh, 48, 8, 43)
      |> drop()

      # Match first 4 bytes of HTTP GET request
      rule()
      |> tcp()
      |> dport(80)
      |> payload_raw(:ih, 0, 32, "GET ")
      |> log("HTTP GET: ")
      |> accept()

  ## Use Cases

  - Custom protocol matching
  - Deep packet inspection
  - Protocol field extraction
  - Tunneled packet inspection
  - Extension header checking

  ## Notes

  - **Offsets and lengths are in BITS, not bytes!**
  - To convert: byte_offset * 8 = bit_offset
  - Example: Byte 12 = Bit 96 (12 * 8)
  - Network byte order (big endian) is assumed
  """
  @spec payload_raw(Match.t(), atom(), non_neg_integer(), pos_integer(), term()) :: Match.t()
  def payload_raw(builder, base, offset, length, value) do
    expr = Expr.payload_raw_match(base, offset, length, value)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match raw payload with bitwise AND mask.

  Allows checking specific bits within a field using bitwise operations.
  Useful for flag checking, field masking, etc.

  ## Parameters

  - `builder` - Match builder
  - `base` - Base reference (:ll, :nh, :th, :ih)
  - `offset` - Bit offset from base
  - `length` - Number of bits
  - `mask` - Bitmask to apply
  - `value` - Value to match after masking

  ## Examples

      # Check TCP SYN flag (bit 1 in TCP flags byte)
      rule()
      |> tcp()
      |> payload_raw_masked(:th, 104, 8, 0x02, 0x02)
      |> accept()

      # Check IP DF (Don't Fragment) flag
      rule()
      |> payload_raw_masked(:nh, 48, 16, 0x4000, 0x4000)
      |> drop()

      # Check if specific bit is set in custom protocol
      rule()
      |> payload_raw_masked(:ih, 8, 8, 0x80, 0x80)
      |> counter()
      |> accept()

  ## How It Works

  1. Extract bits from packet: `field = packet[offset:offset+length]`
  2. Apply mask: `masked = field & mask`
  3. Compare: `masked == value`

  ## Use Cases

  - TCP flag checking
  - IP flag inspection
  - Custom protocol bit flags
  - Selective field matching
  """
  @spec payload_raw_masked(
          Match.t(),
          atom(),
          non_neg_integer(),
          pos_integer(),
          integer(),
          integer()
        ) :: Match.t()
  def payload_raw_masked(builder, base, offset, length, mask, value) do
    payload_expr = Expr.payload_raw(base, offset, length)
    expr = Expr.bitwise_and_match(payload_expr, mask, value)
    Match.add_expr(builder, expr)
  end

  @doc """
  Extract raw payload value (for use in set operations, mangling, etc.).

  Returns a payload expression that can be used as a key or value in other operations.

  ## Examples

      # Use raw payload as set lookup key
      key = payload_raw_expr(:nh, 96, 32)  # Source IP as raw payload

      # Use in set matching
      rule()
      |> set_match(key, "blacklist")
      |> drop()
  """
  @spec payload_raw_expr(atom(), non_neg_integer(), pos_integer()) :: map()
  def payload_raw_expr(base, offset, length) do
    Expr.payload_raw(base, offset, length)
  end

  ## Socket Matching

  @doc """
  Match packets with transparent socket.

  Used in transparent proxy setups to identify packets that belong to
  an existing transparent socket. This prevents loops where proxied
  packets are re-proxied.

  ## Examples

      # Mark packets with existing transparent socket
      rule()
      |> socket_transparent()
      |> set_mark(1)
      |> accept()

      # Skip TPROXY for packets already handled
      rule()
      |> tcp()
      |> socket_transparent()
      |> accept()  # Don't redirect again

  ## Use Cases

  - Transparent proxy setups
  - Avoiding TPROXY loops
  - Identifying proxy-handled traffic

  ## Typical TPROXY Setup

      # Chain 1: Mark existing transparent connections
      mark_existing = rule()
        |> socket_transparent()
        |> set_mark(1)
        |> accept()

      # Chain 2: TPROXY unmarked traffic
      tproxy_new = rule()
        |> tcp()
        |> dport(80)
        |> mark(0)  # Not marked
        |> tproxy(to: 8080)

      # Chain 3: Accept marked traffic
      accept_marked = rule()
        |> mark(1)
        |> accept()
  """
  @spec socket_transparent(Match.t()) :: Match.t()
  def socket_transparent(builder) do
    expr = Expr.socket_match_value("transparent", 1)
    Match.add_expr(builder, expr)
  end

  ## OSF (OS Fingerprinting)

  @doc """
  Match operating system by passive fingerprinting (OSF).

  OSF performs passive OS detection by analyzing TCP SYN packet characteristics
  such as window size, TTL, TCP options, and other fingerprints. This requires
  the pf.os database to be loaded.

  ## Parameters

  - `builder` - Match builder
  - `os_name` - OS name to match (e.g., "Linux", "Windows", "MacOS")
  - `opts` - Options:
    - `:ttl` - TTL matching mode: `:loose` (default), `:skip`, `:strict`

  ## Examples

      # Match Linux systems
      rule()
      |> osf_name("Linux")
      |> log("Linux detected: ")
      |> accept()

      # Match Windows with strict TTL checking
      rule()
      |> osf_name("Windows", ttl: :strict)
      |> set_mark(2)
      |> accept()

      # Block unknown OS
      rule()
      |> osf_name("unknown")
      |> drop()

  ## Requirements

  Before using OSF, load the pf.os database:
  ```bash
  nfnl_osf -f /usr/share/pf.os
  ```

  ## Common OS Names

  - "Linux" - Linux kernel
  - "Windows" - Microsoft Windows
  - "MacOS" - Apple macOS
  - "FreeBSD" - FreeBSD
  - "OpenBSD" - OpenBSD
  - "unknown" - Unknown/unmatched OS

  ## Use Cases

  1. **OS-based Rate Limiting**
     ```elixir
     rule()
     |> osf_name("Windows")
     |> limit(10, :second)
     |> accept()
     ```

  2. **OS-based Marking**
     ```elixir
     rule() |> osf_name("Linux") |> set_mark(1)
     rule() |> osf_name("Windows") |> set_mark(2)
     rule() |> osf_name("MacOS") |> set_mark(3)
     ```

  3. **Security Policies**
     ```elixir
     # Allow only Linux connections to SSH
     rule()
     |> tcp()
     |> dport(22)
     |> osf_name("Linux")
     |> accept()
     ```

  ## Notes

  - OSF only works on TCP SYN packets
  - Requires connection tracking to be enabled
  - May not detect all systems accurately
  - Can be evaded by OS fingerprint spoofing tools
  """
  @spec osf_name(Match.t(), String.t(), keyword()) :: Match.t()
  def osf_name(builder, os_name, opts \\ []) when is_binary(os_name) do
    ttl = opts |> Keyword.get(:ttl, :loose) |> ttl_to_string()
    expr = Expr.osf_match_value("name", os_name, ttl)
    Match.add_expr(builder, expr)
  end

  @doc """
  Match operating system version by passive fingerprinting.

  Similar to `osf_name/3` but matches the OS version instead of the OS name.

  ## Parameters

  - `builder` - Match builder
  - `version` - OS version to match (e.g., "3.x", "10", "11")
  - `opts` - Options:
    - `:ttl` - TTL matching mode: `:loose` (default), `:skip`, `:strict`

  ## Examples

      # Match Linux 3.x kernels
      rule()
      |> osf_version("3.x")
      |> counter()

      # Match Windows 10
      rule()
      |> osf_name("Windows")
      |> osf_version("10")
      |> log("Windows 10: ")
      |> accept()

  ## Use Cases

  1. **Version-specific Policies**
     ```elixir
     # Block old OS versions
     rule()
     |> osf_name("Windows")
     |> osf_version("XP")
     |> reject()
     ```

  2. **Version-based QoS**
     ```elixir
     rule()
     |> osf_version("3.x")
     |> set_priority(1)
     ```
  """
  @spec osf_version(Match.t(), String.t(), keyword()) :: Match.t()
  def osf_version(builder, version, opts \\ []) when is_binary(version) do
    ttl = opts |> Keyword.get(:ttl, :loose) |> ttl_to_string()
    expr = Expr.osf_match_value("version", version, ttl)
    Match.add_expr(builder, expr)
  end

  # Private: Convert TTL atom to string
  defp ttl_to_string(:loose), do: "loose"
  defp ttl_to_string(:skip), do: "skip"
  defp ttl_to_string(:strict), do: "strict"
  defp ttl_to_string(other) when is_binary(other), do: other

  # Private: Get protocol from builder context for port matching
  defp get_port_protocol!(builder, field_name) do
    case builder.protocol do
      nil ->
        raise ArgumentError,
              "set/3 with :#{field_name} requires protocol context. " <>
              "Call tcp(), udp(), sctp(), or dccp() before using set/3 with :#{field_name}.\n\n" <>
              "Example: rule() |> tcp() |> set(\"@ports\", :#{field_name})"

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
      _ -> "ip"  # Default to IPv4 (includes :inet, :ip, :arp, :bridge, etc.)
    end
  end
end
