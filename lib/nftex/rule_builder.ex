defmodule NFTex.RuleBuilder do
  @moduledoc """
  Fluent API for building nftables rules.

  This module provides an intuitive, chainable interface for building firewall rules
  using nft syntax strings internally.

  ## Quick Example

      alias NFTex.RuleBuilder

      # Drop packets from specific IP
      RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_source_ip("192.168.1.100")
      |> RuleBuilder.log("BLOCKED IP: ")
      |> RuleBuilder.drop()
      |> RuleBuilder.commit()

  ## Common Patterns

      # Accept established/related connections
      RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_ct_state([:established, :related])
      |> RuleBuilder.accept()
      |> RuleBuilder.commit()

      # Rate limit SSH connections
      RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_dest_port(22)
      |> RuleBuilder.rate_limit(10, :minute)
      |> RuleBuilder.accept()
      |> RuleBuilder.commit()

  ## See Also

  - `NFTex.Policy` - Pre-built common policies
  - `NFTex.Rule` - Low-level rule operations
  """

  alias NFTex.Rule

  defstruct [
    :pid,
    :table,
    :chain,
    :family,
    nft_parts: []
  ]

  @type t :: %__MODULE__{
          pid: pid(),
          table: String.t(),
          chain: String.t(),
          family: atom(),
          nft_parts: list(String.t())
        }

  @doc """
  Start building a new rule.

  ## Parameters

  - `pid` - NFTex process
  - `table` - Table name
  - `chain` - Chain name
  - `opts` - Options:
    - `:family` - Protocol family (default: `:inet`)

  ## Example

      builder = RuleBuilder.new(pid, "filter", "INPUT")
      builder = RuleBuilder.new(pid, "filter", "INPUT", family: :inet6)
  """
  @spec new(pid(), String.t(), String.t(), keyword()) :: t()
  def new(pid, table, chain, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)

    %__MODULE__{
      pid: pid,
      table: table,
      chain: chain,
      family: family,
      nft_parts: []
    }
  end

  ## Matching Functions

  @doc """
  Match source IP address.

  Accepts either a string IP ("192.168.1.100") or binary form (<<192, 168, 1, 100>>).
  """
  @spec match_source_ip(t(), String.t() | binary()) :: t()
  def match_source_ip(builder, ip) when is_binary(ip) do
    ip_str = format_ip(ip)

    # Determine IP version based on family or IP format
    prefix = case builder.family do
      :ip6 -> "ip6"
      :inet6 -> "ip6"
      _ -> if String.contains?(ip_str, ":"), do: "ip6", else: "ip"
    end

    add_part(builder, "#{prefix} saddr #{ip_str}")
  end

  @doc """
  Match destination IP address.

  Accepts either a string IP ("192.168.1.100") or binary form (<<192, 168, 1, 100>>).
  """
  @spec match_dest_ip(t(), String.t() | binary()) :: t()
  def match_dest_ip(builder, ip) when is_binary(ip) do
    ip_str = format_ip(ip)

    # Determine IP version based on family or IP format
    prefix = case builder.family do
      :ip6 -> "ip6"
      :inet6 -> "ip6"
      _ -> if String.contains?(ip_str, ":"), do: "ip6", else: "ip"
    end

    add_part(builder, "#{prefix} daddr #{ip_str}")
  end

  @doc "Match source port"
  @spec match_source_port(t(), non_neg_integer()) :: t()
  def match_source_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    add_part(builder, "tcp sport #{port}")
  end

  @doc "Match destination port (TCP)"
  @spec match_dest_port(t(), non_neg_integer()) :: t()
  def match_dest_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    add_part(builder, "tcp dport #{port}")
  end

  @doc "Match UDP source port"
  @spec match_udp_sport(t(), non_neg_integer()) :: t()
  def match_udp_sport(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    add_part(builder, "udp sport #{port}")
  end

  @doc "Match UDP destination port"
  @spec match_udp_dport(t(), non_neg_integer()) :: t()
  def match_udp_dport(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    add_part(builder, "udp dport #{port}")
  end

  @doc """
  Match TCP port range.

  ## Example

      # Match high ports (1024-65535)
      builder |> match_port_range(1024, 65535)

      # Match specific range
      builder |> match_port_range(8000, 9000)
  """
  @spec match_port_range(t(), non_neg_integer(), non_neg_integer()) :: t()
  def match_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    add_part(builder, "tcp dport #{min_port}-#{max_port}")
  end

  @doc """
  Match TCP source port range.

  ## Example

      builder |> match_source_port_range(1024, 65535)
  """
  @spec match_source_port_range(t(), non_neg_integer(), non_neg_integer()) :: t()
  def match_source_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    add_part(builder, "tcp sport #{min_port}-#{max_port}")
  end

  @doc """
  Match UDP port range.

  ## Example

      # Match RTP media range
      builder |> match_udp_port_range(10000, 20000)
  """
  @spec match_udp_port_range(t(), non_neg_integer(), non_neg_integer()) :: t()
  def match_udp_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    add_part(builder, "udp dport #{min_port}-#{max_port}")
  end

  @doc """
  Match UDP source port range.

  ## Example

      builder |> match_udp_source_port_range(1024, 65535)
  """
  @spec match_udp_source_port_range(t(), non_neg_integer(), non_neg_integer()) :: t()
  def match_udp_source_port_range(builder, min_port, max_port)
      when is_integer(min_port) and is_integer(max_port) and
             min_port >= 0 and min_port <= 65535 and
             max_port >= 0 and max_port <= 65535 and
             min_port <= max_port do
    add_part(builder, "udp sport #{min_port}-#{max_port}")
  end

  @doc """
  Match TCP flags.

  ## Flags
  - `:syn` - Synchronize
  - `:ack` - Acknowledgment
  - `:fin` - Finish
  - `:rst` - Reset
  - `:psh` - Push
  - `:urg` - Urgent

  ## Example

      # Match SYN packets (new connections)
      builder |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])

      # Match SYN-ACK
      builder |> match_tcp_flags([:syn, :ack], [:syn, :ack, :rst, :fin])
  """
  @spec match_tcp_flags(t(), list(atom()), list(atom())) :: t()
  def match_tcp_flags(builder, flags, mask) when is_list(flags) and is_list(mask) do
    flags_str = flags |> Enum.map(&to_string/1) |> Enum.join(",")
    mask_str = mask |> Enum.map(&to_string/1) |> Enum.join(",")
    add_part(builder, "tcp flags #{mask_str} == #{flags_str}")
  end

  @doc """
  Match packet length.

  ## Example

      # Match packets larger than 1000 bytes
      builder |> match_length(:gt, 1000)

      # Match packets exactly 64 bytes
      builder |> match_length(:eq, 64)
  """
  @spec match_length(t(), atom(), non_neg_integer()) :: t()
  def match_length(builder, op, length) when is_integer(length) and length >= 0 do
    op_str = case op do
      :eq -> "=="
      :ne -> "!="
      :lt -> "<"
      :gt -> ">"
      :le -> "<="
      :ge -> ">="
    end
    add_part(builder, "meta length #{op_str} #{length}")
  end

  @doc """
  Match IP TTL (time to live).

  ## Example

      # Drop packets with TTL = 1 (traceroute)
      builder |> match_ttl(:eq, 1) |> drop()

      # Match packets with TTL > 64
      builder |> match_ttl(:gt, 64)
  """
  @spec match_ttl(t(), atom(), non_neg_integer()) :: t()
  def match_ttl(builder, op, ttl) when is_integer(ttl) and ttl >= 0 and ttl <= 255 do
    op_str = case op do
      :eq -> "=="
      :ne -> "!="
      :lt -> "<"
      :gt -> ">"
      :le -> "<="
      :ge -> ">="
    end
    add_part(builder, "ip ttl #{op_str} #{ttl}")
  end

  @doc """
  Match IPv6 hop limit.

  IPv6 equivalent of TTL (Time To Live).

  ## Example

      # Drop packets with hop limit = 1 (traceroute)
      builder |> match_hoplimit(:eq, 1) |> drop()

      # Block low hop limit (potential spoofing)
      builder |> match_hoplimit(:lt, 10) |> drop()

  ## Use Cases

  - IPv6 traceroute blocking
  - Anti-spoofing (low hop limits)
  - TTL normalization checks
  """
  @spec match_hoplimit(t(), atom(), non_neg_integer()) :: t()
  def match_hoplimit(builder, op, hoplimit) when is_integer(hoplimit) and hoplimit >= 0 and hoplimit <= 255 do
    op_str = case op do
      :eq -> "=="
      :ne -> "!="
      :lt -> "<"
      :gt -> ">"
      :le -> "<="
      :ge -> ">="
    end
    add_part(builder, "ip6 hoplimit #{op_str} #{hoplimit}")
  end

  @doc """
  Match source MAC address.

  ## Example

      builder |> match_source_mac("aa:bb:cc:dd:ee:ff")
  """
  @spec match_source_mac(t(), String.t()) :: t()
  def match_source_mac(builder, mac) when is_binary(mac) do
    add_part(builder, "ether saddr #{mac}")
  end

  @doc """
  Match destination MAC address.

  ## Example

      builder |> match_dest_mac("aa:bb:cc:dd:ee:ff")
  """
  @spec match_dest_mac(t(), String.t()) :: t()
  def match_dest_mac(builder, mac) when is_binary(mac) do
    add_part(builder, "ether daddr #{mac}")
  end

  @doc """
  Match packet mark.

  Packet marks are used for policy routing and advanced traffic control.

  ## Example

      builder |> match_mark(100)
  """
  @spec match_mark(t(), non_neg_integer()) :: t()
  def match_mark(builder, mark) when is_integer(mark) and mark >= 0 do
    add_part(builder, "meta mark #{mark}")
  end

  @doc """
  Match connection mark.

  Connection marks are persistent across packets in a connection.

  ## Example

      builder |> match_connmark(42)
  """
  @spec match_connmark(t(), non_neg_integer()) :: t()
  def match_connmark(builder, mark) when is_integer(mark) and mark >= 0 do
    add_part(builder, "ct mark #{mark}")
  end

  @doc """
  Match DSCP (Differentiated Services Code Point).

  ## Example

      # Match expedited forwarding
      builder |> match_dscp(46)

      # Match assured forwarding
      builder |> match_dscp(10)
  """
  @spec match_dscp(t(), non_neg_integer()) :: t()
  def match_dscp(builder, dscp) when is_integer(dscp) and dscp >= 0 and dscp <= 63 do
    add_part(builder, "ip dscp #{dscp}")
  end

  @doc """
  Match fragmented packets.

  ## Example

      # Match fragmented packets
      builder |> match_fragmented(true)

      # Match non-fragmented packets
      builder |> match_fragmented(false)
  """
  @spec match_fragmented(t(), boolean()) :: t()
  def match_fragmented(builder, true) do
    add_part(builder, "ip frag-off & 0x1fff != 0")
  end
  def match_fragmented(builder, false) do
    add_part(builder, "ip frag-off & 0x1fff == 0")
  end

  @doc """
  Match connection tracking direction.

  ## Example

      # Match original direction (outgoing)
      builder |> match_ct_direction(:original)

      # Match reply direction (incoming)
      builder |> match_ct_direction(:reply)
  """
  @spec match_ct_direction(t(), atom()) :: t()
  def match_ct_direction(builder, direction) when direction in [:original, :reply] do
    add_part(builder, "ct direction #{direction}")
  end

  @doc """
  Match connection tracking status.

  ## Statuses
  - `:expected` - Connection is expected
  - `:seen_reply` - Packets seen in both directions
  - `:assured` - Connection is assured (will not be deleted on timeout)
  - `:confirmed` - Connection is confirmed
  - `:snat` - Source NAT applied
  - `:dnat` - Destination NAT applied
  - `:dying` - Connection is dying

  ## Example

      # Match assured connections
      builder |> match_ct_status([:assured])

      # Match NATed connections
      builder |> match_ct_status([:snat])
  """
  @spec match_ct_status(t(), list(atom())) :: t()
  def match_ct_status(builder, statuses) when is_list(statuses) do
    status_str = statuses
      |> Enum.map(&to_string/1)
      |> Enum.join(",")
    add_part(builder, "ct status #{status_str}")
  end

  @doc """
  Match connection tracking state.

  ## States

  - `:invalid` - Invalid connection
  - `:established` - Established connection
  - `:related` - Related to existing connection
  - `:new` - New connection
  - `:untracked` - Untracked connection

  ## Example

      builder |> match_ct_state([:established, :related])
  """
  @spec match_ct_state(t(), list(atom())) :: t()
  def match_ct_state(builder, states) when is_list(states) do
    state_str = states
      |> Enum.map(&to_string/1)
      |> Enum.join(",")

    add_part(builder, "ct state #{state_str}")
  end

  @doc """
  Match connection tracking label.

  CT labels are 128-bit bitmaps for complex stateful tracking.

  ## Example

      # Match connections labeled as suspicious
      builder |> match_ct_label("suspicious") |> drop()

      # Match numeric label bit
      builder |> match_ct_label(5) |> log("LABELED: ")
  """
  @spec match_ct_label(t(), String.t() | non_neg_integer()) :: t()
  def match_ct_label(builder, label) when is_binary(label) or is_integer(label) do
    label_str = if is_integer(label), do: to_string(label), else: inspect(label)
    add_part(builder, "ct label #{label_str}")
  end

  @doc """
  Match connection tracking zone.

  CT zones provide isolation for multi-tenant or namespace scenarios.

  ## Example

      # Match zone 1
      builder |> match_ct_zone(1) |> accept()

      # Match zone for specific tenant
      builder |> match_ct_zone(100) |> jump("tenant_100")
  """
  @spec match_ct_zone(t(), non_neg_integer()) :: t()
  def match_ct_zone(builder, zone) when is_integer(zone) and zone >= 0 do
    add_part(builder, "ct zone #{zone}")
  end

  @doc """
  Match connection tracking helper.

  Matches connections assigned to a specific CT helper (FTP, SIP, etc.).

  ## Example

      # Match FTP connections
      builder |> match_ct_helper("ftp") |> accept()

      # Match SIP connections
      builder |> match_ct_helper("sip") |> log("SIP: ")
  """
  @spec match_ct_helper(t(), String.t()) :: t()
  def match_ct_helper(builder, helper) when is_binary(helper) do
    add_part(builder, "ct helper #{inspect(helper)}")
  end

  @doc """
  Match connection byte count.

  ## Example

      # Block connections exceeding 1GB
      builder |> match_ct_bytes(:gt, 1_000_000_000) |> drop()

      # Match large downloads
      builder |> match_ct_bytes(:ge, 100_000_000) |> log("BIG-DL: ")
  """
  @spec match_ct_bytes(t(), atom(), non_neg_integer()) :: t()
  def match_ct_bytes(builder, op, bytes) when is_integer(bytes) and bytes >= 0 do
    op_str = case op do
      :eq -> "=="
      :ne -> "!="
      :lt -> "<"
      :gt -> ">"
      :le -> "<="
      :ge -> ">="
    end
    add_part(builder, "ct bytes #{op_str} #{bytes}")
  end

  @doc """
  Match connection packet count.

  ## Example

      # Match connections with many packets
      builder |> match_ct_packets(:gt, 10000) |> log("HIGH-PKT: ")

      # Block after packet limit
      builder |> match_ct_packets(:ge, 50000) |> drop()
  """
  @spec match_ct_packets(t(), atom(), non_neg_integer()) :: t()
  def match_ct_packets(builder, op, packets) when is_integer(packets) and packets >= 0 do
    op_str = case op do
      :eq -> "=="
      :ne -> "!="
      :lt -> "<"
      :gt -> ">"
      :le -> "<="
      :ge -> ">="
    end
    add_part(builder, "ct packets #{op_str} #{packets}")
  end

  @doc """
  Match original (pre-NAT) source address.

  ## Example

      # Match original source before SNAT
      builder |> match_ct_original_saddr("192.168.1.100") |> accept()

      # Track pre-NAT source
      builder |> match_ct_original_saddr("10.0.0.0/8") |> log("INTERNAL: ")
  """
  @spec match_ct_original_saddr(t(), String.t()) :: t()
  def match_ct_original_saddr(builder, addr) when is_binary(addr) do
    add_part(builder, "ct original ip saddr #{addr}")
  end

  @doc """
  Match original (pre-NAT) destination address.

  ## Example

      # Match original destination before DNAT
      builder |> match_ct_original_daddr("203.0.113.100") |> accept()
  """
  @spec match_ct_original_daddr(t(), String.t()) :: t()
  def match_ct_original_daddr(builder, addr) when is_binary(addr) do
    add_part(builder, "ct original ip daddr #{addr}")
  end

  @doc "Match input interface name"
  @spec match_iif(t(), String.t()) :: t()
  def match_iif(builder, ifname) when is_binary(ifname) do
    add_part(builder, "iifname #{inspect(ifname)}")
  end

  @doc "Match output interface name"
  @spec match_oif(t(), String.t()) :: t()
  def match_oif(builder, ifname) when is_binary(ifname) do
    add_part(builder, "oifname #{inspect(ifname)}")
  end

  @doc "Match protocol"
  @spec match_protocol(t(), atom() | String.t()) :: t()
  def match_protocol(builder, protocol) do
    add_part(builder, "ip protocol #{protocol}")
  end

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
      builder |> match_icmp_type(:echo_request) |> accept()

      # Block all ICMP except ping
      builder |> match_icmp_type(:echo_request) |> accept()
      builder |> match_protocol(:icmp) |> drop()
  """
  @spec match_icmp_type(t(), atom() | non_neg_integer()) :: t()
  def match_icmp_type(builder, type) do
    type_str = case type do
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
      num when is_integer(num) -> to_string(num)
      other -> to_string(other)
    end
    add_part(builder, "icmp type #{type_str}")
  end

  @doc """
  Match ICMP code (IPv4).

  Must be used in conjunction with match_icmp_type.

  ## Example

      # Match destination unreachable, port unreachable
      builder
      |> match_icmp_type(:dest_unreachable)
      |> match_icmp_code(3)
      |> accept()
  """
  @spec match_icmp_code(t(), non_neg_integer()) :: t()
  def match_icmp_code(builder, code) when is_integer(code) and code >= 0 and code <= 255 do
    add_part(builder, "icmp code #{code}")
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
      builder |> match_icmpv6_type(:echo_request) |> accept()

      # Allow neighbor discovery
      builder |> match_icmpv6_type(:neighbour_solicit) |> accept()
      builder |> match_icmpv6_type(:neighbour_advert) |> accept()
  """
  @spec match_icmpv6_type(t(), atom() | non_neg_integer()) :: t()
  def match_icmpv6_type(builder, type) do
    type_str = case type do
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
      num when is_integer(num) -> to_string(num)
      other -> to_string(other)
    end
    add_part(builder, "icmpv6 type #{type_str}")
  end

  @doc """
  Match ICMPv6 code (IPv6).

  Must be used in conjunction with match_icmpv6_type.

  ## Example

      builder
      |> match_icmpv6_type(:dest_unreachable)
      |> match_icmpv6_code(4)
      |> drop()
  """
  @spec match_icmpv6_code(t(), non_neg_integer()) :: t()
  def match_icmpv6_code(builder, code) when is_integer(code) and code >= 0 and code <= 255 do
    add_part(builder, "icmpv6 code #{code}")
  end

  @doc """
  Match packet type (unicast, broadcast, multicast).

  ## Packet Types

  - `:unicast` - Unicast packet
  - `:broadcast` - Broadcast packet
  - `:multicast` - Multicast packet
  - `:other` - Other packet types

  ## Example

      # Drop broadcast packets
      builder |> match_pkttype(:broadcast) |> drop()

      # Rate limit multicast
      builder |> match_pkttype(:multicast) |> rate_limit(100, :second) |> accept()

      # Allow only unicast
      builder |> match_pkttype(:unicast) |> accept()
  """
  @spec match_pkttype(t(), atom()) :: t()
  def match_pkttype(builder, pkttype) when pkttype in [:unicast, :broadcast, :multicast, :other] do
    add_part(builder, "meta pkttype #{pkttype}")
  end

  @doc """
  Match packet priority (SO_PRIORITY).

  ## Example

      # Match high priority traffic
      builder |> match_priority(:gt, 5) |> accept()

      # Match specific priority
      builder |> match_priority(:eq, 7) |> log("PRIO-7: ")
  """
  @spec match_priority(t(), atom(), non_neg_integer()) :: t()
  def match_priority(builder, op, priority) when is_integer(priority) and priority >= 0 do
    op_str = case op do
      :eq -> "=="
      :ne -> "!="
      :lt -> "<"
      :gt -> ">"
      :le -> "<="
      :ge -> ">="
    end
    add_part(builder, "meta priority #{op_str} #{priority}")
  end

  @doc """
  Match cgroup (control group) ID.

  Used for container-specific filtering.

  ## Example

      # Match specific cgroup
      builder |> match_cgroup(1001) |> jump("container_rules")

      # Block cgroup
      builder |> match_cgroup(2000) |> drop()
  """
  @spec match_cgroup(t(), non_neg_integer()) :: t()
  def match_cgroup(builder, cgroup_id) when is_integer(cgroup_id) and cgroup_id >= 0 do
    add_part(builder, "meta cgroup #{cgroup_id}")
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
  @spec match_vlan_id(t(), non_neg_integer()) :: t()
  def match_vlan_id(builder, vlan_id) when is_integer(vlan_id) and vlan_id >= 0 and vlan_id <= 4095 do
    add_part(builder, "vlan id #{vlan_id}")
  end

  @doc """
  Match VLAN priority (PCP).

  ## Example

      # Match high priority VLAN traffic
      builder |> match_vlan_pcp(7) |> accept()
  """
  @spec match_vlan_pcp(t(), non_neg_integer()) :: t()
  def match_vlan_pcp(builder, pcp) when is_integer(pcp) and pcp >= 0 and pcp <= 7 do
    add_part(builder, "vlan pcp #{pcp}")
  end

  @doc """
  Match ARP operation.

  ## Operations

  - `:request` (1) - ARP request
  - `:reply` (2) - ARP reply
  - Or numeric value

  ## Example

      # Match ARP requests
      builder |> match_arp_operation(:request) |> log("ARP-REQ: ")

      # Match ARP replies
      builder |> match_arp_operation(:reply) |> accept()
  """
  @spec match_arp_operation(t(), atom() | non_neg_integer()) :: t()
  def match_arp_operation(builder, operation) do
    op_val = case operation do
      :request -> 1
      :reply -> 2
      num when is_integer(num) -> num
      _ -> raise ArgumentError, "Invalid ARP operation: #{inspect(operation)}"
    end
    add_part(builder, "arp operation #{op_val}")
  end

  @doc """
  Match IPsec AH (Authentication Header) SPI.

  ## Example

      # Match specific AH SPI
      builder |> match_ah_spi(12345) |> accept()

      # Log IPsec AH traffic
      builder |> match_ah_spi(:any) |> log("IPSEC-AH: ")
  """
  @spec match_ah_spi(t(), non_neg_integer() | :any) :: t()
  def match_ah_spi(builder, :any) do
    add_part(builder, "ah spi")
  end
  def match_ah_spi(builder, spi) when is_integer(spi) and spi >= 0 do
    add_part(builder, "ah spi #{spi}")
  end

  @doc """
  Match IPsec ESP (Encapsulating Security Payload) SPI.

  ## Example

      # Match specific ESP SPI
      builder |> match_esp_spi(54321) |> accept()

      # Match any ESP traffic
      builder |> match_esp_spi(:any) |> log("IPSEC-ESP: ")
  """
  @spec match_esp_spi(t(), non_neg_integer() | :any) :: t()
  def match_esp_spi(builder, :any) do
    add_part(builder, "esp spi")
  end
  def match_esp_spi(builder, spi) when is_integer(spi) and spi >= 0 do
    add_part(builder, "esp spi #{spi}")
  end

  @doc """
  Limit number of connections per source IP.

  ## Example

      # Limit to 10 concurrent connections per IP
      builder
      |> match_dest_port(80)
      |> match_ct_state([:new])
      |> limit_connections(10)
      |> reject()

      # Limit SSH connections per IP
      builder
      |> match_dest_port(22)
      |> match_ct_state([:new])
      |> limit_connections(3)
      |> drop()
  """
  @spec limit_connections(t(), non_neg_integer()) :: t()
  def limit_connections(builder, count) when is_integer(count) and count > 0 do
    add_part(builder, "ct count #{count}")
  end

  @doc """
  Match packets by socket owner user ID.

  Matches packets based on the UID of the process that created the socket.
  Only works for locally-generated traffic (OUTPUT chain).

  ## Example

      # Block specific user from internet access
      builder
      |> match_skuid(1001)
      |> match_oif("wan0")
      |> reject()

      # Allow only root to access specific service
      builder
      |> match_skuid(0)
      |> match_dest_port(9000)
      |> accept()
  """
  @spec match_skuid(t(), non_neg_integer()) :: t()
  def match_skuid(builder, uid) when is_integer(uid) and uid >= 0 do
    add_part(builder, "meta skuid #{uid}")
  end

  @doc """
  Match packets by socket owner group ID.

  Matches packets based on the GID of the process that created the socket.
  Only works for locally-generated traffic (OUTPUT chain).

  ## Example

      # Block specific group from internet access
      builder
      |> match_skgid(1002)
      |> match_oif("wan0")
      |> reject()

      # Allow specific group to access admin port
      builder
      |> match_skgid(100)
      |> match_dest_port(8443)
      |> accept()
  """
  @spec match_skgid(t(), non_neg_integer()) :: t()
  def match_skgid(builder, gid) when is_integer(gid) and gid >= 0 do
    add_part(builder, "meta skgid #{gid}")
  end

  @doc """
  Match against a named set.

  The set must already exist in the table. Use NFTex.Set to manage sets.

  ## Example

      # Create set first
      :ok = NFTex.Set.create(pid, %{
        name: "blocklist",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr
      })

      # Match against set
      builder
      |> match_set("@blocklist", :saddr)
      |> drop()

      # Match destination port against port set
      builder
      |> match_set("@allowed_ports", :dport)
      |> accept()

  ## Set Types

  - `:saddr` - Source IP address
  - `:daddr` - Destination IP address
  - `:sport` - Source port
  - `:dport` - Destination port
  """
  @spec match_set(t(), String.t(), atom()) :: t()
  def match_set(builder, set_name, match_type) when is_binary(set_name) do
    # Ensure set name starts with @
    set_ref = if String.starts_with?(set_name, "@"), do: set_name, else: "@#{set_name}"

    match_expr = case match_type do
      :saddr -> "ip saddr #{set_ref}"
      :daddr -> "ip daddr #{set_ref}"
      :sport -> "tcp sport #{set_ref}"
      :dport -> "tcp dport #{set_ref}"
      other -> raise ArgumentError, "Invalid set match type: #{inspect(other)}"
    end

    add_part(builder, match_expr)
  end

  ## Action Functions

  @doc "Add counter expression"
  @spec counter(t()) :: t()
  def counter(builder) do
    add_part(builder, "counter")
  end

  @doc """
  Add log expression.

  ## Options

  - `:level` - Syslog level (default: no level specified)
    - `:emerg` - Emergency
    - `:alert` - Alert
    - `:crit` - Critical
    - `:err` - Error
    - `:warning` or `:warn` - Warning
    - `:notice` - Notice
    - `:info` - Info
    - `:debug` - Debug

  ## Examples

      # Basic logging
      builder |> log("DROPPED: ")

      # With syslog level
      builder |> log("AUDIT: ", level: :warning)
      builder |> log("CRITICAL: ", level: :crit)
  """
  @spec log(t(), String.t(), keyword()) :: t()
  def log(builder, prefix, opts \\ []) do
    level = Keyword.get(opts, :level)

    log_expr = if level do
      level_str = case level do
        :emerg -> "emerg"
        :alert -> "alert"
        :crit -> "crit"
        :err -> "err"
        :warning -> "warn"
        :warn -> "warn"
        :notice -> "notice"
        :info -> "info"
        :debug -> "debug"
        other -> to_string(other)
      end
      "log prefix #{inspect(prefix)} level #{level_str}"
    else
      "log prefix #{inspect(prefix)}"
    end

    add_part(builder, log_expr)
  end

  @doc """
  Add rate limiting.

  ## Example

      builder |> rate_limit(10, :minute)
      builder |> rate_limit(100, :second)
  """
  @spec rate_limit(t(), non_neg_integer(), atom(), keyword()) :: t()
  def rate_limit(builder, rate, unit, opts \\ []) do
    unit_str = case unit do
      :second -> "second"
      :minute -> "minute"
      :hour -> "hour"
      :day -> "day"
      :week -> "week"
      other -> to_string(other)
    end

    burst = Keyword.get(opts, :burst)
    limit_str = if burst do
      "limit rate #{rate}/#{unit_str} burst #{burst} packets"
    else
      "limit rate #{rate}/#{unit_str}"
    end

    add_part(builder, limit_str)
  end

  @doc """
  Set packet mark.

  Useful for policy routing and traffic shaping.

  ## Example

      builder |> set_mark(100)
  """
  @spec set_mark(t(), non_neg_integer()) :: t()
  def set_mark(builder, mark) when is_integer(mark) and mark >= 0 do
    add_part(builder, "meta mark set #{mark}")
  end

  @doc """
  Set connection mark.

  Connection marks persist across all packets in a connection.

  ## Example

      builder |> set_connmark(42)
  """
  @spec set_connmark(t(), non_neg_integer()) :: t()
  def set_connmark(builder, mark) when is_integer(mark) and mark >= 0 do
    add_part(builder, "ct mark set #{mark}")
  end

  @doc """
  Restore connection mark to packet mark.

  Copies the connection mark to the packet mark. This ensures all packets
  in a connection have the same mark, useful for policy routing and QoS.

  ## Example

      # Restore connmark for established connections
      builder
      |> match_ct_state([:established, :related])
      |> restore_mark()
      |> accept()

  ## Use Case

  In multi-WAN routing or QoS scenarios:
  1. First packet: classify and set connmark
  2. Subsequent packets: restore connmark to mark
  3. All packets in connection use same route/QoS tier
  """
  @spec restore_mark(t()) :: t()
  def restore_mark(builder) do
    add_part(builder, "meta mark set ct mark")
  end

  @doc """
  Save packet mark to connection mark.

  Copies the packet mark to the connection mark. This persists the
  classification for the entire connection.

  ## Example

      # Classify new connection and save mark
      builder
      |> match_ct_state([:new])
      |> match_dscp(46)
      |> set_mark(1)
      |> save_mark()
      |> accept()

  ## Use Case

  In traffic classification:
  1. Match conditions and set packet mark
  2. Save mark to connmark for persistence
  3. Later packets restore connmark via restore_mark()
  """
  @spec save_mark(t()) :: t()
  def save_mark(builder) do
    add_part(builder, "ct mark set meta mark")
  end

  @doc """
  Set connection tracking label.

  Assigns a label to the connection for advanced stateful tracking.
  Labels are 128-bit bitmaps allowing complex classification.

  ## Example

      # Label suspicious connections
      builder
      |> match_source_ip("203.0.113.0/24")
      |> set_ct_label("suspicious")
      |> accept()

      # Set numeric label bit
      builder
      |> match_dest_port(22)
      |> set_ct_label(5)
      |> accept()

  ## Use Cases

  - Complex multi-stage stateful tracking
  - Connection classification across chains
  - Security event correlation
  """
  @spec set_ct_label(t(), String.t() | non_neg_integer()) :: t()
  def set_ct_label(builder, label) when is_binary(label) or is_integer(label) do
    label_str = if is_integer(label), do: to_string(label), else: inspect(label)
    add_part(builder, "ct label set #{label_str}")
  end

  @doc """
  Assign connection tracking helper.

  Assigns a CT helper (FTP, SIP, etc.) to the connection for application
  layer gateway functionality.

  ## Example

      # Assign FTP helper
      builder
      |> match_dest_port(21)
      |> match_ct_state([:new])
      |> set_ct_helper("ftp")
      |> accept()

      # Assign SIP helper
      builder
      |> match_udp_dport(5060)
      |> set_ct_helper("sip")
      |> accept()

  ## Use Cases

  - FTP active mode support
  - SIP/VoIP NAT traversal
  - H.323 video conferencing
  - TFTP file transfers
  """
  @spec set_ct_helper(t(), String.t()) :: t()
  def set_ct_helper(builder, helper) when is_binary(helper) do
    add_part(builder, "ct helper set #{inspect(helper)}")
  end

  @doc """
  Assign connection to tracking zone.

  Places the connection in a specific CT zone for isolation.
  Useful for multi-tenant or namespace scenarios.

  ## Example

      # Assign to zone 1
      builder
      |> match_iif("tenant1")
      |> set_ct_zone(1)
      |> accept()

      # Assign to tenant-specific zone
      builder
      |> match_source_ip("192.168.100.0/24")
      |> set_ct_zone(100)
      |> accept()

  ## Use Cases

  - Multi-tenant isolation
  - Network namespace separation
  - Overlapping IP address spaces
  - Container network isolation
  """
  @spec set_ct_zone(t(), non_neg_integer()) :: t()
  def set_ct_zone(builder, zone) when is_integer(zone) and zone >= 0 do
    add_part(builder, "ct zone set #{zone}")
  end

  @doc """
  Set DSCP (Differentiated Services Code Point) value.

  Modifies the DSCP field in the IP header for QoS remarking.

  ## DSCP Values

  - 46 (`:ef`) - Expedited Forwarding (VoIP voice)
  - 34 (`:af41`) - Assured Forwarding 4/1 (Video)
  - 26 (`:af31`) - Assured Forwarding 3/1 (Signaling)
  - 18 (`:af21`) - Assured Forwarding 2/1 (Streaming)
  - 10 (`:af11`) - Assured Forwarding 1/1 (Bulk)
  - 0 (`:cs0`) - Class Selector 0 (Best Effort)

  ## Example

      # Remark HTTP traffic as bulk
      builder
      |> match_dest_port(80)
      |> set_dscp(10)
      |> accept()

      # Mark VoIP as expedited forwarding
      builder
      |> match_udp_dport(5060)
      |> set_dscp(46)
      |> accept()

      # Use atom
      builder
      |> match_dest_port(22)
      |> set_dscp(:af31)
      |> accept()
  """
  @spec set_dscp(t(), atom() | non_neg_integer()) :: t()
  def set_dscp(builder, dscp) do
    dscp_val = case dscp do
      :ef -> 46
      :af41 -> 34
      :af31 -> 26
      :af21 -> 18
      :af11 -> 10
      :cs0 -> 0
      num when is_integer(num) and num >= 0 and num <= 63 -> num
      _ -> raise ArgumentError, "Invalid DSCP value: #{inspect(dscp)}"
    end
    add_part(builder, "ip dscp set #{dscp_val}")
  end

  @doc """
  Set IP TTL (Time To Live) value.

  Modifies the TTL field in the IPv4 header.

  ## Example

      # Set TTL to 64
      builder |> set_ttl(64) |> accept()

      # Normalize TTL
      builder |> set_ttl(128) |> accept()

  ## Use Cases

  - TTL normalization (anti-fingerprinting)
  - Extending TTL for specific traffic
  - Router hop limit enforcement
  """
  @spec set_ttl(t(), non_neg_integer()) :: t()
  def set_ttl(builder, ttl) when is_integer(ttl) and ttl >= 0 and ttl <= 255 do
    add_part(builder, "ip ttl set #{ttl}")
  end

  @doc """
  Set IPv6 hop limit value.

  IPv6 equivalent of TTL. Modifies the hop limit field in the IPv6 header.

  ## Example

      # Set hop limit to 64
      builder |> set_hoplimit(64) |> accept()

      # Normalize hop limit
      builder |> set_hoplimit(255) |> accept()
  """
  @spec set_hoplimit(t(), non_neg_integer()) :: t()
  def set_hoplimit(builder, hoplimit) when is_integer(hoplimit) and hoplimit >= 0 and hoplimit <= 255 do
    add_part(builder, "ip6 hoplimit set #{hoplimit}")
  end

  @doc """
  Increment IP TTL by 1.

  ## Example

      # Extend TTL by 1
      builder |> increment_ttl() |> accept()
  """
  @spec increment_ttl(t()) :: t()
  def increment_ttl(builder) do
    add_part(builder, "ip ttl set ip ttl + 1")
  end

  @doc """
  Decrement IP TTL by 1.

  ## Example

      # Reduce TTL by 1
      builder |> decrement_ttl() |> accept()
  """
  @spec decrement_ttl(t()) :: t()
  def decrement_ttl(builder) do
    add_part(builder, "ip ttl set ip ttl - 1")
  end

  @doc """
  Increment IPv6 hop limit by 1.

  ## Example

      # Extend hop limit by 1
      builder |> increment_hoplimit() |> accept()
  """
  @spec increment_hoplimit(t()) :: t()
  def increment_hoplimit(builder) do
    add_part(builder, "ip6 hoplimit set ip6 hoplimit + 1")
  end

  @doc """
  Decrement IPv6 hop limit by 1.

  ## Example

      # Reduce hop limit by 1
      builder |> decrement_hoplimit() |> accept()
  """
  @spec decrement_hoplimit(t()) :: t()
  def decrement_hoplimit(builder) do
    add_part(builder, "ip6 hoplimit set ip6 hoplimit - 1")
  end

  ## NAT Actions

  @doc """
  Apply source NAT (SNAT) to an IP address.

  ## Example

      # SNAT to single IP
      builder |> snat_to("203.0.113.1")

      # SNAT to IP:port
      builder |> snat_to("203.0.113.1", port: 1024)
  """
  @spec snat_to(t(), String.t(), keyword()) :: t()
  def snat_to(builder, ip, opts \\ []) when is_binary(ip) do
    port = Keyword.get(opts, :port)

    # Add family prefix for inet tables
    nat_type = case builder.family do
      :ip6 -> "snat ip6"
      :inet6 -> "snat ip6"
      _ -> "snat ip"
    end

    snat_str = if port do
      "#{nat_type} to #{ip}:#{port}"
    else
      "#{nat_type} to #{ip}"
    end
    add_part(builder, snat_str)
  end

  @doc """
  Apply destination NAT (DNAT) to an IP address.

  ## Example

      # DNAT to single IP
      builder |> dnat_to("192.168.1.100")

      # DNAT to IP:port (port forwarding)
      builder |> dnat_to("192.168.1.100", port: 8080)
  """
  @spec dnat_to(t(), String.t(), keyword()) :: t()
  def dnat_to(builder, ip, opts \\ []) when is_binary(ip) do
    port = Keyword.get(opts, :port)

    # Add family prefix for inet tables
    nat_type = case builder.family do
      :ip6 -> "dnat ip6"
      :inet6 -> "dnat ip6"
      _ -> "dnat ip"
    end

    dnat_str = if port do
      "#{nat_type} to #{ip}:#{port}"
    else
      "#{nat_type} to #{ip}"
    end
    add_part(builder, dnat_str)
  end

  @doc """
  Apply masquerading (dynamic SNAT).

  Automatically uses the outgoing interface's IP address.

  ## Example

      # Basic masquerade
      builder |> masquerade()

      # Masquerade with port range
      builder |> masquerade(port_range: "1024-65535")
  """
  @spec masquerade(t(), keyword()) :: t()
  def masquerade(builder, opts \\ []) do
    port_range = Keyword.get(opts, :port_range)
    masq_str = if port_range do
      "masquerade to :#{port_range}"
    else
      "masquerade"
    end
    add_part(builder, masq_str)
  end

  @doc """
  Redirect to local port.

  Used for transparent proxying.

  ## Example

      # Redirect HTTP to local proxy
      builder |> match_dest_port(80) |> redirect_to(3128)
  """
  @spec redirect_to(t(), non_neg_integer()) :: t()
  def redirect_to(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    add_part(builder, "redirect to :#{port}")
  end

  ## Verdict Functions

  @doc "Accept packets"
  @spec accept(t()) :: t()
  def accept(builder) do
    add_part(builder, "accept")
  end

  @doc "Drop packets silently"
  @spec drop(t()) :: t()
  def drop(builder) do
    add_part(builder, "drop")
  end

  @doc """
  Reject packets with ICMP error.

  ## Example

      builder |> reject()
      builder |> reject(:tcp_reset)
  """
  @spec reject(t(), atom()) :: t()
  def reject(builder, type \\ :icmp_port_unreachable) do
    reject_str = case type do
      :tcp_reset -> "reject with tcp reset"
      :icmp_port_unreachable -> "reject"
      :icmpx_port_unreachable -> "reject with icmpx type port-unreachable"
      other -> "reject with #{other}"
    end

    add_part(builder, reject_str)
  end

  @doc """
  Continue to next rule.

  Unlike accept/drop/reject, this verdict continues rule evaluation.
  Useful for complex rule flows where you want to apply actions but
  continue processing.

  ## Example

      # Log and continue (don't stop processing)
      builder
      |> match_dest_port(22)
      |> log("SSH: ")
      |> continue()

      # Apply action and continue
      builder
      |> match_source_ip("192.168.1.0/24")
      |> set_mark(100)
      |> continue()

  ## Use Cases

  - Logging without terminal verdict
  - Multi-stage packet processing
  - Complex action chains
  - Audit trails with continued filtering
  """
  @spec continue(t()) :: t()
  def continue(builder) do
    add_part(builder, "continue")
  end

  @doc """
  Disable connection tracking for packets.

  Marks packets as untracked, bypassing the connection tracking system.
  This improves performance but disables stateful features.

  ## Example

      # Disable tracking for high-volume traffic
      builder
      |> match_dest_port(443)
      |> notrack()

      # Skip tracking for local traffic
      builder
      |> match_source_ip("127.0.0.0/8")
      |> notrack()

  ## Use Cases

  - High-throughput servers (performance optimization)
  - Stateless firewalls
  - Reducing conntrack table load
  - Local/loopback traffic optimization

  ## WARNING

  Disabling connection tracking means:
  - No stateful filtering (NEW/ESTABLISHED states)
  - No NAT for these packets
  - No connection limits
  """
  @spec notrack(t()) :: t()
  def notrack(builder) do
    add_part(builder, "notrack")
  end

  @doc """
  Queue packets to userspace for inspection.

  Sends packets to a userspace program (IDS/IPS) via NFQUEUE.
  The userspace program decides the final verdict.

  ## Options

  - `:bypass` - If queue is full, accept the packet (default: drop)
  - `:fanout` - Distribute packets across multiple queues

  ## Example

      # Queue to IDS on queue 0
      builder
      |> match_dest_port(80)
      |> queue_to_userspace(0)

      # Queue with bypass (don't drop on queue full)
      builder
      |> match_dest_port(443)
      |> queue_to_userspace(1, bypass: true)

      # Queue with fanout
      builder
      |> match_protocol(:tcp)
      |> queue_to_userspace(0, fanout: true)

  ## Use Cases

  - IDS/IPS integration (Suricata, Snort)
  - Custom packet inspection
  - Deep packet inspection
  - Application-level filtering
  """
  @spec queue_to_userspace(t(), non_neg_integer(), keyword()) :: t()
  def queue_to_userspace(builder, queue_num, opts \\ []) when is_integer(queue_num) and queue_num >= 0 do
    bypass = Keyword.get(opts, :bypass, false)
    fanout = Keyword.get(opts, :fanout, false)

    flags = []
    flags = if bypass, do: ["bypass" | flags], else: flags
    flags = if fanout, do: ["fanout" | flags], else: flags

    queue_str = if Enum.empty?(flags) do
      "queue num #{queue_num}"
    else
      flag_str = Enum.join(flags, ",")
      "queue num #{queue_num} flags #{flag_str}"
    end

    add_part(builder, queue_str)
  end

  @doc """
  Enable SYN proxy for DDoS protection.

  Implements SYN cookie-based protection against SYN flood attacks.
  The firewall handles the TCP handshake, protecting backend servers.

  ## Options

  - `:mss` - Maximum segment size (default: auto)
  - `:wscale` - Window scaling (default: auto)
  - `:sack_perm` - SACK permitted (default: auto)
  - `:timestamp` - TCP timestamp (default: auto)

  ## Example

      # Basic synproxy
      builder
      |> match_dest_port(80)
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> synproxy()

      # With custom MSS
      builder
      |> match_dest_port(443)
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> synproxy(mss: 1460)

      # Full options
      builder
      |> match_dest_port(22)
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> synproxy(mss: 1460, wscale: 7, sack_perm: true, timestamp: true)

  ## Use Cases

  - SYN flood DDoS protection
  - High-volume web servers
  - Public-facing services
  - Attack mitigation

  ## WARNING

  - Only use on SYN packets (match_tcp_flags required)
  - May break some TCP options
  - Backend servers see firewall as client
  """
  @spec synproxy(t(), keyword()) :: t()
  def synproxy(builder, opts \\ []) do
    mss = Keyword.get(opts, :mss)
    wscale = Keyword.get(opts, :wscale)
    sack_perm = Keyword.get(opts, :sack_perm)
    timestamp = Keyword.get(opts, :timestamp)

    params = []
    params = if mss, do: ["mss #{mss}" | params], else: params
    params = if wscale, do: ["wscale #{wscale}" | params], else: params
    params = if sack_perm, do: ["sack-perm" | params], else: params
    params = if timestamp, do: ["timestamp" | params], else: params

    synproxy_str = if Enum.empty?(params) do
      "synproxy"
    else
      param_str = Enum.join(Enum.reverse(params), " ")
      "synproxy #{param_str}"
    end

    add_part(builder, synproxy_str)
  end

  @doc """
  Set TCP Maximum Segment Size (MSS).

  Modifies or clamps the TCP MSS option. Useful for fixing PMTU issues
  with PPPoE or VPN connections.

  ## Example

      # Clamp MSS to 1400 (for PPPoE)
      builder
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> set_tcp_mss(1400)
      |> accept()

      # Clamp to PMTU
      builder
      |> match_oif("pppoe0")
      |> match_tcp_flags([:syn], [:syn, :ack, :rst, :fin])
      |> set_tcp_mss(:pmtu)
      |> accept()

  ## Use Cases

  - PPPoE connections (typically 1492 MTU → 1452 MSS)
  - VPN tunnels with reduced MTU
  - Fixing PMTU black holes
  - WAN interface MSS clamping
  """
  @spec set_tcp_mss(t(), non_neg_integer() | :pmtu) :: t()
  def set_tcp_mss(builder, :pmtu) do
    add_part(builder, "tcp option maxseg size set rt mtu")
  end
  def set_tcp_mss(builder, mss) when is_integer(mss) and mss > 0 and mss <= 65535 do
    add_part(builder, "tcp option maxseg size set #{mss}")
  end

  @doc """
  Duplicate packet to another interface.

  Sends a copy of the packet to a different interface while the original
  continues normal processing. Used for traffic mirroring and monitoring.

  ## Example

      # Mirror to monitoring interface
      builder
      |> match_dest_port(443)
      |> duplicate_to("monitor0")
      |> accept()

      # Mirror suspicious traffic to IDS
      builder
      |> match_source_ip("203.0.113.0/24")
      |> duplicate_to("ids0")
      |> continue()

  ## Use Cases

  - Network traffic monitoring
  - IDS/IPS analysis
  - Traffic analysis and debugging
  - Compliance and auditing
  """
  @spec duplicate_to(t(), String.t()) :: t()
  def duplicate_to(builder, interface) when is_binary(interface) do
    add_part(builder, "dup to device #{inspect(interface)}")
  end

  @doc """
  Enable flow offloading to hardware.

  Offloads established connections to hardware for fast-path processing.
  Dramatically improves throughput for forwarded traffic on supported hardware.

  ## Options

  - `:table` - Flowtable name (required if using named flowtable)

  ## Example

      # Basic flow offload
      builder
      |> match_ct_state([:established])
      |> flow_offload()

      # Named flowtable
      builder
      |> match_ct_state([:established])
      |> flow_offload(table: "fastpath")

  ## Use Cases

  - Router throughput optimization
  - Hardware acceleration (if supported)
  - Multi-gigabit routing
  - Reducing CPU load on forwarding

  ## Requirements

  - Hardware support (not all NICs support offloading)
  - Flowtable must be created first
  - Only works for ESTABLISHED connections
  """
  @spec flow_offload(t(), keyword()) :: t()
  def flow_offload(builder, opts \\ []) do
    table = Keyword.get(opts, :table)

    offload_str = if table do
      "flow add @#{table}"
    else
      "flow offload"
    end

    add_part(builder, offload_str)
  end

  @doc """
  Jump to another chain.

  Transfers control to the specified chain. If the chain accepts the packet,
  processing continues in the current chain after the jump. If the chain
  drops/rejects the packet, it terminates immediately.

  ## Example

      # Jump to custom logging chain
      builder
      |> match_dest_port(22)
      |> jump("ssh_logging")
      |> accept()

      # Complex rule organization
      builder
      |> match_source_ip("192.168.1.0/24")
      |> jump("internal_rules")

  ## Use Cases

  - Organize complex rulesets into logical chains
  - Reusable rule groups
  - Conditional rule application
  """
  @spec jump(t(), String.t()) :: t()
  def jump(builder, chain_name) when is_binary(chain_name) do
    add_part(builder, "jump #{chain_name}")
  end

  @doc """
  Go to another chain (non-returning jump).

  Transfers control to the specified chain permanently. Unlike jump,
  control never returns to the current chain.

  ## Example

      # Permanent transfer to specialized chain
      builder
      |> match_dest_port(443)
      |> goto("https_chain")

  ## Difference from jump/1

  - `jump/1`: Returns after chain processing (like a function call)
  - `goto/1`: Never returns (like a goto statement)
  """
  @spec goto(t(), String.t()) :: t()
  def goto(builder, chain_name) when is_binary(chain_name) do
    add_part(builder, "goto #{chain_name}")
  end

  @doc """
  Return from chain.

  Returns control to the calling chain. Only valid in chains that
  were entered via jump (not base chains).

  ## Example

      # In a custom chain, return early
      builder
      |> match_source_ip("192.168.1.100")
      |> return_from_chain()

      # Continue processing in calling chain
  """
  @spec return_from_chain(t()) :: t()
  def return_from_chain(builder) do
    add_part(builder, "return")
  end

  ## Build and Commit

  @doc """
  Commit the rule to the kernel.

  This builds the complete nft expression string from all parts
  and creates the rule using the JSON API.

  Returns `:ok` on success, `{:error, reason}` on failure.
  """
  @spec commit(t()) :: :ok | {:error, term()}
  def commit(%__MODULE__{} = builder) do
    # Build complete nft expression
    expr = Enum.join(builder.nft_parts, " ")

    # Use Rule.add to create the rule
    Rule.add(builder.pid, %{
      family: builder.family,
      table: builder.table,
      chain: builder.chain,
      expr: expr
    })
  end

  # Private helpers

  defp add_part(builder, part) when is_binary(part) do
    %{builder | nft_parts: builder.nft_parts ++ [part]}
  end

  # Format IP address - convert binary to string if needed
  defp format_ip(ip) when byte_size(ip) == 4 do
    # IPv4 binary format: <<192, 168, 1, 100>>
    <<a, b, c, d>> = ip
    "#{a}.#{b}.#{c}.#{d}"
  end

  defp format_ip(ip) when byte_size(ip) == 16 do
    # IPv6 binary format - convert to string
    # This is a simplified conversion; nftables will handle it
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
