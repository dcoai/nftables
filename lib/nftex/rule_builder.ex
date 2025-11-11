defmodule NFTablesEx.RuleBuilder do
  @moduledoc """
  Fluent API for building nftables rules.

  This module provides an intuitive, chainable interface for building firewall rules
  using nft syntax strings internally.

  ## Quick Example

      alias NFTablesEx.RuleBuilder

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

  - `NFTablesEx.Policy` - Pre-built common policies
  - `NFTablesEx.Rule` - Low-level rule operations
  """

  alias NFTablesEx.Formatter
  alias NFTablesEx.RuleBuilder.{
    IPMatching,
    PortMatching,
    TCPMatching,
    Layer2Matching,
    CTMatching,
    AdvancedMatching,
    Actions,
    NAT,
    Verdicts
  }

  defstruct [
    :pid,
    :table,
    :chain,
    :family,
    expr_list: []      # JSON expression maps
  ]

  @type t :: %__MODULE__{
          pid: pid(),
          table: String.t(),
          chain: String.t(),
          family: atom(),
          expr_list: list(map())
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

      # Create builder with default IPv4/IPv6 family
      builder = RuleBuilder.new(pid, "filter", "INPUT")

      # Create builder for IPv6
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
      expr_list: []
    }
  end

  ## IP Matching (delegated to IPMatching)

  defdelegate match_source_ip(builder, ip), to: IPMatching
  defdelegate match_dest_ip(builder, ip), to: IPMatching

  ## Port Matching (delegated to PortMatching)

  defdelegate match_source_port(builder, port), to: PortMatching
  defdelegate match_dest_port(builder, port), to: PortMatching
  defdelegate match_udp_sport(builder, port), to: PortMatching
  defdelegate match_udp_dport(builder, port), to: PortMatching
  defdelegate match_port_range(builder, min_port, max_port), to: PortMatching
  defdelegate match_source_port_range(builder, min_port, max_port), to: PortMatching
  defdelegate match_udp_port_range(builder, min_port, max_port), to: PortMatching
  defdelegate match_udp_source_port_range(builder, min_port, max_port), to: PortMatching

  ## TCP/Protocol Matching (delegated to TCPMatching)

  defdelegate match_tcp_flags(builder, flags, mask), to: TCPMatching
  defdelegate match_length(builder, op, length), to: TCPMatching
  defdelegate match_ttl(builder, op, ttl), to: TCPMatching
  defdelegate match_hoplimit(builder, op, hoplimit), to: TCPMatching
  defdelegate match_protocol(builder, protocol), to: TCPMatching

  ## Layer 2 Matching (delegated to Layer2Matching)

  defdelegate match_source_mac(builder, mac), to: Layer2Matching
  defdelegate match_dest_mac(builder, mac), to: Layer2Matching
  defdelegate match_iif(builder, ifname), to: Layer2Matching
  defdelegate match_oif(builder, ifname), to: Layer2Matching
  defdelegate match_vlan_id(builder, vlan_id), to: Layer2Matching
  defdelegate match_vlan_pcp(builder, pcp), to: Layer2Matching

  ## Connection Tracking Matching (delegated to CTMatching)

  defdelegate match_ct_state(builder, states), to: CTMatching
  defdelegate match_ct_status(builder, statuses), to: CTMatching
  defdelegate match_ct_direction(builder, direction), to: CTMatching
  defdelegate match_connmark(builder, mark), to: CTMatching
  defdelegate match_ct_label(builder, label), to: CTMatching
  defdelegate match_ct_zone(builder, zone), to: CTMatching
  defdelegate match_ct_helper(builder, helper), to: CTMatching
  defdelegate match_ct_bytes(builder, op, bytes), to: CTMatching
  defdelegate match_ct_packets(builder, op, packets), to: CTMatching
  defdelegate match_ct_original_saddr(builder, addr), to: CTMatching
  defdelegate match_ct_original_daddr(builder, addr), to: CTMatching
  defdelegate limit_connections(builder, count), to: CTMatching

  ## Advanced Matching (delegated to AdvancedMatching)

  defdelegate match_mark(builder, mark), to: AdvancedMatching
  defdelegate match_dscp(builder, dscp), to: AdvancedMatching
  defdelegate match_fragmented(builder, is_fragmented), to: AdvancedMatching
  defdelegate match_icmp_type(builder, type), to: AdvancedMatching
  defdelegate match_icmp_code(builder, code), to: AdvancedMatching
  defdelegate match_icmpv6_type(builder, type), to: AdvancedMatching
  defdelegate match_icmpv6_code(builder, code), to: AdvancedMatching
  defdelegate match_pkttype(builder, pkttype), to: AdvancedMatching
  defdelegate match_priority(builder, op, priority), to: AdvancedMatching
  defdelegate match_cgroup(builder, cgroup_id), to: AdvancedMatching
  defdelegate match_skuid(builder, uid), to: AdvancedMatching
  defdelegate match_skgid(builder, gid), to: AdvancedMatching
  defdelegate match_ah_spi(builder, spi), to: AdvancedMatching
  defdelegate match_esp_spi(builder, spi), to: AdvancedMatching
  defdelegate match_arp_operation(builder, operation), to: AdvancedMatching
  defdelegate match_set(builder, set_name, match_type), to: AdvancedMatching

  ## Actions (delegated to Actions)

  defdelegate counter(builder), to: Actions
  defdelegate log(builder, prefix), to: Actions
  defdelegate log(builder, prefix, opts), to: Actions
  defdelegate rate_limit(builder, rate, unit), to: Actions
  defdelegate rate_limit(builder, rate, unit, opts), to: Actions
  defdelegate set_mark(builder, mark), to: Actions
  defdelegate set_connmark(builder, mark), to: Actions
  defdelegate restore_mark(builder), to: Actions
  defdelegate save_mark(builder), to: Actions
  defdelegate set_ct_label(builder, label), to: Actions
  defdelegate set_ct_helper(builder, helper), to: Actions
  defdelegate set_ct_zone(builder, zone), to: Actions
  defdelegate set_dscp(builder, dscp), to: Actions
  defdelegate set_ttl(builder, ttl), to: Actions
  defdelegate set_hoplimit(builder, hoplimit), to: Actions
  defdelegate increment_ttl(builder), to: Actions
  defdelegate decrement_ttl(builder), to: Actions
  defdelegate increment_hoplimit(builder), to: Actions
  defdelegate decrement_hoplimit(builder), to: Actions

  ## NAT Actions (delegated to NAT)

  defdelegate snat_to(builder, ip), to: NAT
  defdelegate snat_to(builder, ip, opts), to: NAT
  defdelegate dnat_to(builder, ip), to: NAT
  defdelegate dnat_to(builder, ip, opts), to: NAT
  defdelegate masquerade(builder), to: NAT
  defdelegate masquerade(builder, opts), to: NAT
  defdelegate redirect_to(builder, port), to: NAT

  ## Verdicts (delegated to Verdicts)

  defdelegate accept(builder), to: Verdicts
  defdelegate drop(builder), to: Verdicts
  defdelegate reject(builder), to: Verdicts
  defdelegate reject(builder, type), to: Verdicts
  defdelegate continue(builder), to: Verdicts
  defdelegate notrack(builder), to: Verdicts
  defdelegate queue_to_userspace(builder, queue_num), to: Verdicts
  defdelegate queue_to_userspace(builder, queue_num, opts), to: Verdicts
  defdelegate synproxy(builder), to: Verdicts
  defdelegate synproxy(builder, opts), to: Verdicts
  defdelegate set_tcp_mss(builder, mss), to: Verdicts
  defdelegate duplicate_to(builder, interface), to: Verdicts
  defdelegate flow_offload(builder), to: Verdicts
  defdelegate flow_offload(builder, opts), to: Verdicts
  defdelegate jump(builder, chain_name), to: Verdicts
  defdelegate goto(builder, chain_name), to: Verdicts
  defdelegate return_from_chain(builder), to: Verdicts

  ## Build and Commit

  @doc """
  Build the nft command string without executing.

  Converts the JSON expression list to human-readable nft syntax.
  Returns the nft command string that would be sent to add this rule.
  Useful for batching, remote execution, or inspection.

  ## Returns

  nft command string

  ## Examples

      # Build command
      cmd = RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_source_ip("192.168.1.100")
      |> RuleBuilder.drop()
      |> RuleBuilder.to_nft_command()
      #=> "add rule inet filter INPUT ip saddr 192.168.1.100 drop"

      # Use in batch
      cmd1 = RuleBuilder.new(pid, "filter", "INPUT")
             |> match_source_ip("1.2.3.4")
             |> drop()
             |> to_nft_command()

      cmd2 = RuleBuilder.new(pid, "filter", "INPUT")
             |> match_source_ip("5.6.7.8")
             |> drop()
             |> to_nft_command()

      batch = Batch.new()
      |> Batch.add(cmd1)
      |> Batch.add(cmd2)
      |> Batch.execute()

      # Send to remote node
      cmd = RuleBuilder.new(pid, "filter", "INPUT")
            |> match_dest_port(22)
            |> rate_limit(10, :minute)
            |> accept()
            |> to_nft_command()

      MyTransport.send_to_node("firewall-1", cmd)
  """
  @spec to_nft_command(t()) :: binary()
  def to_nft_command(%__MODULE__{} = builder) do
    # Format expr_list to nft syntax
    expr = Formatter.format_expr_list(builder.expr_list)
    "add rule #{builder.family} #{builder.table} #{builder.chain} #{expr}"
  end

  @doc """
  Commit the rule to the kernel.

  Sends the structured JSON expression list directly to the kernel via
  the libnftables JSON API.

  Returns `:ok` on success, `{:error, reason}` on failure.

  ## Examples

      # Build and commit a rule
      RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_source_ip("192.168.1.100")
      |> RuleBuilder.drop()
      |> RuleBuilder.commit()
  """
  @spec commit(t()) :: :ok | {:error, term()}
  def commit(%__MODULE__{} = builder) do
    # Convert expr_list to nftables JSON format
    nftables_json = %{
      nftables: [
        %{
          add: %{
            rule: %{
              family: builder.family,
              table: builder.table,
              chain: builder.chain,
              expr: builder.expr_list
            }
          }
        }
      ]
    }

    # Encode to JSON using Elixir's JSON module (returns binary)
    json_string = JSON.encode!(nftables_json)

    # Execute via Executor
    case NFTablesEx.Executor.execute(json_string, pid: builder.pid) do
      {:ok, _response} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  # Private helpers

  @doc false
  def add_expr(builder, expr) when is_map(expr) do
    # Add JSON expression map to expr_list
    %{builder | expr_list: builder.expr_list ++ [expr]}
  end
end
