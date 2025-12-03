defmodule NFTables.NAT do
  @moduledoc """
  High-level Network Address Translation (NAT) operations.

  This module provides convenient functions for common NAT scenarios like
  internet sharing (masquerade), port forwarding (DNAT), and source NAT.

  All functions follow a builder-first pattern, taking a Builder as the first
  parameter and returning a modified Builder. This allows composing multiple
  NAT rules before submitting them in a single transaction.

  ## Quick Examples

      {:ok, pid} = NFTables.start_link()

      # Single rule
      Builder.new()
      |> NFTables.NAT.setup_masquerade("wan0")
      |> NFTables.submit(pid: pid)

      # Compose multiple NAT rules
      Builder.new()
      |> NFTables.NAT.setup_masquerade("wan0", table: "nat")
      |> NFTables.NAT.port_forward(80, "192.168.1.100", 8080, table: "nat")
      |> NFTables.NAT.static_nat("203.0.113.1", "192.168.1.100", table: "nat")
      |> NFTables.submit(pid: pid)

  ## Prerequisites

  NAT operations require a NAT table and appropriate chains:

      # Create NAT table and chains using Builder
      Builder.new()
      |> NFTables.add(table: "nat", family: :inet)
      |> NFTables.add(
        table: "nat",
        chain: "prerouting",
        family: :inet,
        type: :nat,
        hook: :prerouting,
        priority: -100,
        policy: :accept
      )
      |> NFTables.add(
        table: "nat",
        chain: "postrouting",
        family: :inet,
        type: :nat,
        hook: :postrouting,
        priority: 100,
        policy: :accept
      )
      |> NFTables.submit(pid: pid)

  """

  import NFTables.Expr
  alias NFTables.Builder

  @type family :: :inet | :ip | :ip6

  @doc """
  Set up internet sharing (masquerade) on an interface.

  This enables NAT for all outgoing traffic on the specified interface,
  allowing internal hosts to share a single public IP address.

  ## Parameters

  - `builder` - Builder to add the rule to (defaults to new builder)
  - `interface` - Outgoing interface name (e.g., "eth0", "wan0")
  - `opts` - Options:
    - `:table` - NAT table name (default: "nat")
    - `:chain` - Chain name (default: "postrouting")
    - `:family` - Protocol family (default: :inet)

  ## Examples

      # Share internet connection via eth0
      Builder.new()
      |> NFTables.NAT.setup_masquerade("eth0")
      |> NFTables.submit(pid: pid)

      # Compose with other rules
      Builder.new()
      |> NFTables.NAT.setup_masquerade("wan0", table: "nat")
      |> NFTables.NAT.source_nat("10.0.0.0/24", "203.0.113.1", table: "nat")
      |> NFTables.submit(pid: pid)
  """
  @spec setup_masquerade(Builder.t(), String.t(), keyword()) :: Builder.t()
  def setup_masquerade(builder \\ Builder.new(), interface, opts \\ []) when is_binary(interface) do
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "postrouting")
    family = Keyword.get(opts, :family, :inet)

    expr_list =
      expr(family: family)
      |> oif(interface)
      |> masquerade()

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Forward a port to an internal host (DNAT).

  This redirects incoming traffic on a specific port to an internal
  host and optionally a different port.

  ## Parameters

  - `builder` - Builder to add the rule to (defaults to new builder)
  - `external_port` - Port to listen on
  - `internal_ip` - Destination IP address
  - `internal_port` - Destination port (defaults to external_port)
  - `opts` - Options:
    - `:protocol` - :tcp or :udp (default: :tcp)
    - `:table` - NAT table name (default: "nat")
    - `:chain` - Chain name (default: "prerouting")
    - `:family` - Protocol family (default: :inet)
    - `:interface` - Limit to specific interface (optional)

  ## Examples

      # Forward external port 80 to internal web server
      Builder.new()
      |> NFTables.NAT.port_forward(80, "192.168.1.100", 8080)
      |> NFTables.submit(pid: pid)

      # Forward SSH to internal host
      Builder.new()
      |> NFTables.NAT.port_forward(2222, "192.168.1.10", 22)
      |> NFTables.submit(pid: pid)

      # Forward UDP DNS
      Builder.new()
      |> NFTables.NAT.port_forward(53, "192.168.1.1", 53, protocol: :udp)
      |> NFTables.submit(pid: pid)

      # Compose multiple port forwards
      Builder.new()
      |> NFTables.NAT.port_forward(80, "192.168.1.100", 8080, table: "nat")
      |> NFTables.NAT.port_forward(443, "192.168.1.100", 8443, table: "nat")
      |> NFTables.submit(pid: pid)
  """
  @spec port_forward(Builder.t(), non_neg_integer(), String.t(), non_neg_integer(), keyword()) ::
          Builder.t()
  def port_forward(builder \\ Builder.new(), external_port, internal_ip, internal_port, opts \\ [])
      when is_integer(external_port) and is_binary(internal_ip) and
             is_integer(internal_port) do
    protocol = Keyword.get(opts, :protocol, :tcp)
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "prerouting")
    family = Keyword.get(opts, :family, :inet)
    interface = Keyword.get(opts, :interface)

    expr_builder = expr(family: family)

    expr_builder = if interface do
      iif(expr_builder, interface)
    else
      expr_builder
    end

    expr_list =
      expr_builder
      |> (case protocol do
        :tcp -> &tcp/1
        :udp -> &udp/1
      end).()
      |> dport(external_port)
      |> dnat_to(internal_ip, port: internal_port)

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Set up static (1:1) NAT between two IP addresses.

  Maps all traffic for a public IP to a private IP and vice versa.
  This function adds both DNAT (prerouting) and SNAT (postrouting) rules.

  ## Parameters

  - `builder` - Builder to add the rules to (defaults to new builder)
  - `public_ip` - External IP address
  - `private_ip` - Internal IP address
  - `opts` - Options:
    - `:table` - NAT table name (default: "nat")
    - `:family` - Protocol family (default: :inet)

  ## Examples

      # Map public IP to DMZ host
      Builder.new()
      |> NFTables.NAT.static_nat("203.0.113.100", "192.168.1.100")
      |> NFTables.submit(pid: pid)

      # Multiple static NAT mappings
      Builder.new()
      |> NFTables.NAT.static_nat("203.0.113.100", "192.168.1.100", table: "nat")
      |> NFTables.NAT.static_nat("203.0.113.101", "192.168.1.101", table: "nat")
      |> NFTables.submit(pid: pid)
  """
  @spec static_nat(Builder.t(), String.t(), String.t(), keyword()) :: Builder.t()
  def static_nat(builder \\ Builder.new(), public_ip, private_ip, opts \\ [])
      when is_binary(public_ip) and is_binary(private_ip) do
    table = Keyword.get(opts, :table, "nat")
    family = Keyword.get(opts, :family, :inet)

    # Build DNAT rule (incoming: public -> private)
    dnat_expr =
      expr(family: family)
      |> dest_ip(public_ip)
      |> dnat_to(private_ip)

    # Build SNAT rule (outgoing: private -> public)
    snat_expr =
      expr(family: family)
      |> source_ip(private_ip)
      |> snat_to(public_ip)

    builder
    |> NFTables.add(rule: dnat_expr, table: table, chain: "prerouting", family: family)
    |> NFTables.add(rule: snat_expr, table: table, chain: "postrouting", family: family)
  end

  @doc """
  Set up source NAT for a specific source IP or subnet.

  ## Parameters

  - `builder` - Builder to add the rule to (defaults to new builder)
  - `source` - Source IP or CIDR (e.g., "192.168.1.0/24")
  - `nat_ip` - IP to NAT to
  - `opts` - Options:
    - `:table` - NAT table name (default: "nat")
    - `:chain` - Chain name (default: "postrouting")
    - `:family` - Protocol family (default: :inet)
    - `:interface` - Limit to specific interface (optional)

  ## Examples

      # NAT internal subnet to public IP
      Builder.new()
      |> NFTables.NAT.source_nat("192.168.1.0/24", "203.0.113.1")
      |> NFTables.submit(pid: pid)

      # NAT specific host
      Builder.new()
      |> NFTables.NAT.source_nat("192.168.1.100", "203.0.113.1")
      |> NFTables.submit(pid: pid)

      # With interface restriction
      Builder.new()
      |> NFTables.NAT.source_nat("10.0.0.0/24", "203.0.113.1", interface: "wan0")
      |> NFTables.submit(pid: pid)
  """
  @spec source_nat(Builder.t(), String.t(), String.t(), keyword()) :: Builder.t()
  def source_nat(builder \\ Builder.new(), source, nat_ip, opts \\ [])
      when is_binary(source) and is_binary(nat_ip) do
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "postrouting")
    family = Keyword.get(opts, :family, :inet)
    interface = Keyword.get(opts, :interface)

    expr_builder =
      expr(family: family)
      |> source_ip(source)

    expr_builder = if interface do
      oif(expr_builder, interface)
    else
      expr_builder
    end

    expr_list =
      expr_builder
      |> snat_to(nat_ip)

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Set up destination NAT for incoming traffic.

  ## Parameters

  - `builder` - Builder to add the rule to (defaults to new builder)
  - `dest` - Destination IP to match
  - `nat_ip` - IP to NAT to
  - `opts` - Options:
    - `:table` - NAT table name (default: "nat")
    - `:chain` - Chain name (default: "prerouting")
    - `:family` - Protocol family (default: :inet)
    - `:interface` - Limit to specific interface (optional)

  ## Examples

      # Redirect traffic to virtual IP to actual server
      Builder.new()
      |> NFTables.NAT.destination_nat("203.0.113.100", "192.168.1.100")
      |> NFTables.submit(pid: pid)

      # With interface restriction
      Builder.new()
      |> NFTables.NAT.destination_nat("203.0.113.100", "192.168.1.100", interface: "wan0")
      |> NFTables.submit(pid: pid)
  """
  @spec destination_nat(Builder.t(), String.t(), String.t(), keyword()) :: Builder.t()
  def destination_nat(builder \\ Builder.new(), dest, nat_ip, opts \\ [])
      when is_binary(dest) and is_binary(nat_ip) do
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "prerouting")
    family = Keyword.get(opts, :family, :inet)
    interface = Keyword.get(opts, :interface)

    expr_builder = expr(family: family)

    expr_builder = if interface do
      iif(expr_builder, interface)
    else
      expr_builder
    end

    expr_list =
      expr_builder
      |> dest_ip(dest)
      |> dnat_to(nat_ip)

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
  end

  @doc """
  Redirect a port to a different port on the same host (local port redirect).

  Useful for transparent proxying.

  ## Parameters

  - `builder` - Builder to add the rule to (defaults to new builder)
  - `from_port` - Port to redirect from
  - `to_port` - Port to redirect to
  - `opts` - Options:
    - `:protocol` - :tcp or :udp (default: :tcp)
    - `:table` - NAT table name (default: "nat")
    - `:chain` - Chain name (default: "prerouting")
    - `:family` - Protocol family (default: :inet)

  ## Examples

      # Redirect HTTP to local proxy
      Builder.new()
      |> NFTables.NAT.redirect_port(80, 3128)
      |> NFTables.submit(pid: pid)

      # Redirect HTTPS to local proxy
      Builder.new()
      |> NFTables.NAT.redirect_port(443, 8443)
      |> NFTables.submit(pid: pid)

      # Multiple redirects
      Builder.new()
      |> NFTables.NAT.redirect_port(80, 3128, table: "nat")
      |> NFTables.NAT.redirect_port(443, 8443, table: "nat")
      |> NFTables.submit(pid: pid)
  """
  @spec redirect_port(Builder.t(), non_neg_integer(), non_neg_integer(), keyword()) ::
          Builder.t()
  def redirect_port(builder \\ Builder.new(), from_port, to_port, opts \\ [])
      when is_integer(from_port) and is_integer(to_port) do
    protocol = Keyword.get(opts, :protocol, :tcp)
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "prerouting")
    family = Keyword.get(opts, :family, :inet)

    expr_list =
      expr(family: family)
      |> (case protocol do
        :tcp -> &tcp/1
        :udp -> &udp/1
      end).()
      |> dport(from_port)
      |> redirect_to(to_port)

    builder
    |> NFTables.add(rule: expr_list, table: table, chain: chain, family: family)
  end
end
