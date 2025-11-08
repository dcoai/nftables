defmodule NFTex.RuleBuilder.AdvancedMatching do
  @moduledoc """
  Advanced matching functions for RuleBuilder.

  Provides functions for ICMP, packet metadata (marks, DSCP, fragmentation),
  packet type classification, cgroup matching, socket owner matching,
  IPsec SPI, ARP operations, and set matching.
  """

  alias NFTex.RuleBuilder

  # Packet metadata matching

  @doc """
  Match packet mark.

  Useful for policy routing and traffic control.

  ## Example

      builder |> match_mark(100)
  """
  @spec match_mark(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_mark(builder, mark) when is_integer(mark) and mark >= 0 do
    RuleBuilder.add_part(builder, "meta mark #{mark}")
  end

  @doc """
  Match DSCP (Differentiated Services Code Point).

  ## Example

      # Match expedited forwarding
      builder |> match_dscp(46)

      # Match assured forwarding
      builder |> match_dscp(10)
  """
  @spec match_dscp(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_dscp(builder, dscp) when is_integer(dscp) and dscp >= 0 and dscp <= 63 do
    RuleBuilder.add_part(builder, "ip dscp #{dscp}")
  end

  @doc """
  Match fragmented packets.

  ## Example

      # Match fragmented packets
      builder |> match_fragmented(true)

      # Match non-fragmented packets
      builder |> match_fragmented(false)
  """
  @spec match_fragmented(RuleBuilder.t(), boolean()) :: RuleBuilder.t()
  def match_fragmented(builder, true) do
    RuleBuilder.add_part(builder, "ip frag-off & 0x1fff != 0")
  end
  def match_fragmented(builder, false) do
    RuleBuilder.add_part(builder, "ip frag-off & 0x1fff == 0")
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
      builder |> match_icmp_type(:echo_request) |> accept()

      # Block all ICMP except ping
      builder |> match_icmp_type(:echo_request) |> accept()
      builder |> match_protocol(:icmp) |> drop()
  """
  @spec match_icmp_type(RuleBuilder.t(), atom() | non_neg_integer()) :: RuleBuilder.t()
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
    RuleBuilder.add_part(builder, "icmp type #{type_str}")
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
  @spec match_icmp_code(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_icmp_code(builder, code) when is_integer(code) and code >= 0 and code <= 255 do
    RuleBuilder.add_part(builder, "icmp code #{code}")
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
  @spec match_icmpv6_type(RuleBuilder.t(), atom() | non_neg_integer()) :: RuleBuilder.t()
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
    RuleBuilder.add_part(builder, "icmpv6 type #{type_str}")
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
  @spec match_icmpv6_code(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_icmpv6_code(builder, code) when is_integer(code) and code >= 0 and code <= 255 do
    RuleBuilder.add_part(builder, "icmpv6 code #{code}")
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
      builder |> match_pkttype(:broadcast) |> drop()

      # Rate limit multicast
      builder |> match_pkttype(:multicast) |> rate_limit(100, :second) |> accept()

      # Allow only unicast
      builder |> match_pkttype(:unicast) |> accept()
  """
  @spec match_pkttype(RuleBuilder.t(), atom()) :: RuleBuilder.t()
  def match_pkttype(builder, pkttype) when pkttype in [:unicast, :broadcast, :multicast, :other] do
    RuleBuilder.add_part(builder, "meta pkttype #{pkttype}")
  end

  @doc """
  Match packet priority (SO_PRIORITY).

  ## Example

      # Match high priority traffic
      builder |> match_priority(:gt, 5) |> accept()

      # Match specific priority
      builder |> match_priority(:eq, 7) |> log("PRIO-7: ")
  """
  @spec match_priority(RuleBuilder.t(), atom(), non_neg_integer()) :: RuleBuilder.t()
  def match_priority(builder, op, priority) when is_integer(priority) and priority >= 0 do
    op_str = case op do
      :eq -> "=="
      :ne -> "!="
      :lt -> "<"
      :gt -> ">"
      :le -> "<="
      :ge -> ">="
    end
    RuleBuilder.add_part(builder, "meta priority #{op_str} #{priority}")
  end

  # Cgroup and socket matching

  @doc """
  Match cgroup (control group) ID.

  Used for container-specific filtering.

  ## Example

      # Match specific cgroup
      builder |> match_cgroup(1001) |> jump("container_rules")

      # Block cgroup
      builder |> match_cgroup(2000) |> drop()
  """
  @spec match_cgroup(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_cgroup(builder, cgroup_id) when is_integer(cgroup_id) and cgroup_id >= 0 do
    RuleBuilder.add_part(builder, "meta cgroup #{cgroup_id}")
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
  @spec match_skuid(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_skuid(builder, uid) when is_integer(uid) and uid >= 0 do
    RuleBuilder.add_part(builder, "meta skuid #{uid}")
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
  @spec match_skgid(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def match_skgid(builder, gid) when is_integer(gid) and gid >= 0 do
    RuleBuilder.add_part(builder, "meta skgid #{gid}")
  end

  # IPsec matching

  @doc """
  Match IPsec AH (Authentication Header) SPI.

  ## Example

      # Match specific AH SPI
      builder |> match_ah_spi(12345) |> accept()

      # Log IPsec AH traffic
      builder |> match_ah_spi(:any) |> log("IPSEC-AH: ")
  """
  @spec match_ah_spi(RuleBuilder.t(), non_neg_integer() | :any) :: RuleBuilder.t()
  def match_ah_spi(builder, :any) do
    RuleBuilder.add_part(builder, "ah spi")
  end
  def match_ah_spi(builder, spi) when is_integer(spi) and spi >= 0 do
    RuleBuilder.add_part(builder, "ah spi #{spi}")
  end

  @doc """
  Match IPsec ESP (Encapsulating Security Payload) SPI.

  ## Example

      # Match specific ESP SPI
      builder |> match_esp_spi(54321) |> accept()

      # Match any ESP traffic
      builder |> match_esp_spi(:any) |> log("IPSEC-ESP: ")
  """
  @spec match_esp_spi(RuleBuilder.t(), non_neg_integer() | :any) :: RuleBuilder.t()
  def match_esp_spi(builder, :any) do
    RuleBuilder.add_part(builder, "esp spi")
  end
  def match_esp_spi(builder, spi) when is_integer(spi) and spi >= 0 do
    RuleBuilder.add_part(builder, "esp spi #{spi}")
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
      builder |> match_arp_operation(:request) |> log("ARP-REQ: ")

      # Match ARP replies
      builder |> match_arp_operation(:reply) |> accept()
  """
  @spec match_arp_operation(RuleBuilder.t(), atom() | non_neg_integer()) :: RuleBuilder.t()
  def match_arp_operation(builder, operation) do
    op_val = case operation do
      :request -> 1
      :reply -> 2
      num when is_integer(num) -> num
      _ -> raise ArgumentError, "Invalid ARP operation: #{inspect(operation)}"
    end
    RuleBuilder.add_part(builder, "arp operation #{op_val}")
  end

  # Set matching

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
  @spec match_set(RuleBuilder.t(), String.t(), atom()) :: RuleBuilder.t()
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

    RuleBuilder.add_part(builder, match_expr)
  end
end
