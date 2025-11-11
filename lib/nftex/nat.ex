defmodule NFTablesEx.NAT do
  @moduledoc """
  High-level Network Address Translation (NAT) operations.

  This module provides convenient functions for common NAT scenarios like
  internet sharing (masquerade), port forwarding (DNAT), and source NAT.

  ## Quick Examples

      {:ok, pid} = NFTablesEx.start_link()

      # Internet sharing (masquerade)
      :ok = NFTablesEx.NAT.setup_masquerade(pid, "wan0")

      # Port forwarding
      :ok = NFTablesEx.NAT.port_forward(pid, 80, "192.168.1.100", 8080)

      # 1:1 NAT
      :ok = NFTablesEx.NAT.static_nat(pid, "203.0.113.1", "192.168.1.100")

  ## Prerequisites

  NAT operations require a NAT table and appropriate chains:

      # Create NAT table
      :ok = NFTablesEx.Table.add(pid, %{name: "nat", family: :inet})

      # Create PREROUTING chain (for DNAT)
      :ok = NFTablesEx.Chain.add(pid, %{
        table: "nat",
        name: "prerouting",
        family: :inet,
        type: :nat,
        hook: :prerouting,
        priority: -100,
        policy: :accept
      })

      # Create POSTROUTING chain (for SNAT/masquerade)
      :ok = NFTablesEx.Chain.add(pid, %{
        table: "nat",
        name: "postrouting",
        family: :inet,
        type: :nat,
        hook: :postrouting,
        priority: 100,
        policy: :accept
      })

  """

  alias NFTablesEx.RuleBuilder

  @type family :: :inet | :ip | :ip6

  @doc """
  Set up internet sharing (masquerade) on an interface.

  This enables NAT for all outgoing traffic on the specified interface,
  allowing internal hosts to share a single public IP address.

  ## Parameters

  - `pid` - NFTex process
  - `interface` - Outgoing interface name (e.g., "eth0", "wan0")
  - `opts` - Options:
    - `:table` - NAT table name (default: "nat")
    - `:chain` - Chain name (default: "postrouting")
    - `:family` - Protocol family (default: :inet)

  ## Example

      # Share internet connection via eth0
      :ok = NFTablesEx.NAT.setup_masquerade(pid, "eth0")

      # Now internal hosts (192.168.1.0/24) can access internet
  """
  @spec setup_masquerade(pid(), String.t(), keyword()) :: :ok | {:error, term()}
  def setup_masquerade(pid, interface, opts \\ []) when is_binary(interface) do
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "postrouting")
    family = Keyword.get(opts, :family, :inet)

    RuleBuilder.new(pid, table, chain, family: family)
    |> RuleBuilder.match_oif(interface)
    |> RuleBuilder.masquerade()
    |> RuleBuilder.commit()
  end

  @doc """
  Forward a port to an internal host (DNAT).

  This redirects incoming traffic on a specific port to an internal
  host and optionally a different port.

  ## Parameters

  - `pid` - NFTex process
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
      :ok = NFTablesEx.NAT.port_forward(pid, 80, "192.168.1.100", 8080)

      # Forward SSH to internal host
      :ok = NFTablesEx.NAT.port_forward(pid, 2222, "192.168.1.10", 22)

      # Forward UDP DNS
      :ok = NFTablesEx.NAT.port_forward(pid, 53, "192.168.1.1", 53, protocol: :udp)
  """
  @spec port_forward(pid(), non_neg_integer(), String.t(), non_neg_integer(), keyword()) ::
          :ok | {:error, term()}
  def port_forward(pid, external_port, internal_ip, internal_port, opts \\ [])
      when is_integer(external_port) and is_binary(internal_ip) and
             is_integer(internal_port) do
    protocol = Keyword.get(opts, :protocol, :tcp)
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "prerouting")
    family = Keyword.get(opts, :family, :inet)
    interface = Keyword.get(opts, :interface)

    builder = RuleBuilder.new(pid, table, chain, family: family)

    builder = if interface do
      RuleBuilder.match_iif(builder, interface)
    else
      builder
    end

    builder = case protocol do
      :tcp -> RuleBuilder.match_dest_port(builder, external_port)
      :udp -> RuleBuilder.match_udp_dport(builder, external_port)
    end

    builder
    |> RuleBuilder.dnat_to(internal_ip, port: internal_port)
    |> RuleBuilder.commit()
  end

  @doc """
  Set up static (1:1) NAT between two IP addresses.

  Maps all traffic for a public IP to a private IP and vice versa.

  ## Parameters

  - `pid` - NFTex process
  - `public_ip` - External IP address
  - `private_ip` - Internal IP address
  - `opts` - Options:
    - `:table` - NAT table name (default: "nat")
    - `:family` - Protocol family (default: :inet)

  ## Example

      # Map public IP to DMZ host
      :ok = NFTablesEx.NAT.static_nat(pid, "203.0.113.100", "192.168.1.100")
  """
  @spec static_nat(pid(), String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def static_nat(pid, public_ip, private_ip, opts \\ [])
      when is_binary(public_ip) and is_binary(private_ip) do
    table = Keyword.get(opts, :table, "nat")
    family = Keyword.get(opts, :family, :inet)

    # DNAT: public -> private (incoming)
    with :ok <- dnat_rule(pid, table, "prerouting", family, public_ip, private_ip),
         # SNAT: private -> public (outgoing)
         :ok <- snat_rule(pid, table, "postrouting", family, private_ip, public_ip) do
      :ok
    end
  end

  @doc """
  Set up source NAT for a specific source IP or subnet.

  ## Parameters

  - `pid` - NFTex process
  - `source` - Source IP or CIDR (e.g., "192.168.1.0/24")
  - `nat_ip` - IP to NAT to
  - `opts` - Options:
    - `:table` - NAT table name (default: "nat")
    - `:chain` - Chain name (default: "postrouting")
    - `:family` - Protocol family (default: :inet)
    - `:interface` - Limit to specific interface (optional)

  ## Example

      # NAT internal subnet to public IP
      :ok = NFTablesEx.NAT.source_nat(pid, "192.168.1.0/24", "203.0.113.1")

      # NAT specific host
      :ok = NFTablesEx.NAT.source_nat(pid, "192.168.1.100", "203.0.113.1")
  """
  @spec source_nat(pid(), String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def source_nat(pid, source, nat_ip, opts \\ [])
      when is_binary(source) and is_binary(nat_ip) do
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "postrouting")
    family = Keyword.get(opts, :family, :inet)
    interface = Keyword.get(opts, :interface)

    builder = RuleBuilder.new(pid, table, chain, family: family)
    |> RuleBuilder.match_source_ip(source)

    builder = if interface do
      RuleBuilder.match_oif(builder, interface)
    else
      builder
    end

    builder
    |> RuleBuilder.snat_to(nat_ip)
    |> RuleBuilder.commit()
  end

  @doc """
  Set up destination NAT for incoming traffic.

  ## Parameters

  - `pid` - NFTex process
  - `dest` - Destination IP to match
  - `nat_ip` - IP to NAT to
  - `opts` - Options:
    - `:table` - NAT table name (default: "nat")
    - `:chain` - Chain name (default: "prerouting")
    - `:family` - Protocol family (default: :inet)
    - `:interface` - Limit to specific interface (optional)

  ## Example

      # Redirect traffic to virtual IP to actual server
      :ok = NFTablesEx.NAT.destination_nat(pid, "203.0.113.100", "192.168.1.100")
  """
  @spec destination_nat(pid(), String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def destination_nat(pid, dest, nat_ip, opts \\ [])
      when is_binary(dest) and is_binary(nat_ip) do
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "prerouting")
    family = Keyword.get(opts, :family, :inet)
    interface = Keyword.get(opts, :interface)

    builder = RuleBuilder.new(pid, table, chain, family: family)

    builder = if interface do
      RuleBuilder.match_iif(builder, interface)
    else
      builder
    end

    builder
    |> RuleBuilder.match_dest_ip(dest)
    |> RuleBuilder.dnat_to(nat_ip)
    |> RuleBuilder.commit()
  end

  @doc """
  Redirect a port to a different port on the same host (local port redirect).

  Useful for transparent proxying.

  ## Example

      # Redirect HTTP to local proxy
      :ok = NFTablesEx.NAT.redirect_port(pid, 80, 3128)
  """
  @spec redirect_port(pid(), non_neg_integer(), non_neg_integer(), keyword()) ::
          :ok | {:error, term()}
  def redirect_port(pid, from_port, to_port, opts \\ [])
      when is_integer(from_port) and is_integer(to_port) do
    protocol = Keyword.get(opts, :protocol, :tcp)
    table = Keyword.get(opts, :table, "nat")
    chain = Keyword.get(opts, :chain, "prerouting")
    family = Keyword.get(opts, :family, :inet)

    builder = RuleBuilder.new(pid, table, chain, family: family)

    builder = case protocol do
      :tcp -> RuleBuilder.match_dest_port(builder, from_port)
      :udp -> RuleBuilder.match_udp_dport(builder, from_port)
    end

    builder
    |> RuleBuilder.redirect_to(to_port)
    |> RuleBuilder.commit()
  end

  # Private helpers

  defp dnat_rule(pid, table, chain, family, dest_ip, nat_ip) do
    RuleBuilder.new(pid, table, chain, family: family)
    |> RuleBuilder.match_dest_ip(dest_ip)
    |> RuleBuilder.dnat_to(nat_ip)
    |> RuleBuilder.commit()
  end

  defp snat_rule(pid, table, chain, family, source_ip, nat_ip) do
    RuleBuilder.new(pid, table, chain, family: family)
    |> RuleBuilder.match_source_ip(source_ip)
    |> RuleBuilder.snat_to(nat_ip)
    |> RuleBuilder.commit()
  end
end
