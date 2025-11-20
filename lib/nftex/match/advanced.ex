defmodule NFTablesEx.Match.Advanced do
  @moduledoc """
  Advanced matching functions for Match.

  Provides functions for ICMP, packet metadata (marks, DSCP, fragmentation),
  packet type classification, cgroup matching, socket owner matching,
  IPsec SPI, ARP operations, and set matching.
  """

  alias NFTablesEx.{Match, Expr}

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

  ## Example

      # Create set first using Builder
      alias NFTablesEx.Builder

      Builder.new()
      |> Builder.add(
        set: "blocklist",
        table: "filter",
        family: :inet,
        type: :ipv4_addr
      )
      |> Builder.execute(pid)

      # Match against set
      builder
      |> set("@blocklist", :saddr)
      |> drop()

      # Match destination port against port set
      builder
      |> set("@allowed_ports", :dport)
      |> accept()

  ## Set Types

  - `:saddr` - Source IP address
  - `:daddr` - Destination IP address
  - `:sport` - Source port
  - `:dport` - Destination port
  """
  @spec set(Match.t(), String.t(), atom()) :: Match.t()
  def set(builder, set_name, match_type) when is_binary(set_name) do
    # Ensure set name starts with @
    set_ref = if String.starts_with?(set_name, "@"), do: set_name, else: "@#{set_name}"

    expr = case match_type do
      :saddr ->
        %{
          "match" => %{
            "left" => %{"payload" => %{"protocol" => "ip", "field" => "saddr"}},
            "right" => set_ref,
            "op" => "=="
          }
        }
      :daddr ->
        %{
          "match" => %{
            "left" => %{"payload" => %{"protocol" => "ip", "field" => "daddr"}},
            "right" => set_ref,
            "op" => "=="
          }
        }
      :sport ->
        %{
          "match" => %{
            "left" => %{"payload" => %{"protocol" => "tcp", "field" => "sport"}},
            "right" => set_ref,
            "op" => "=="
          }
        }
      :dport ->
        %{
          "match" => %{
            "left" => %{"payload" => %{"protocol" => "tcp", "field" => "dport"}},
            "right" => set_ref,
            "op" => "=="
          }
        }
      other -> raise ArgumentError, "Invalid set match type: #{inspect(other)}"
    end

    Match.add_expr(builder, expr)
  end
end
