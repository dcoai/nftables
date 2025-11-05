defmodule NFTex.RuleBuilder do
  @moduledoc """
  Fluent API for building nftables rules.

  This module provides an intuitive, chainable interface for building firewall rules
  without dealing with low-level expression management.

  ## Quick Example

      alias NFTex.RuleBuilder

      # Drop packets from specific IP
      RuleBuilder.new(pid, "filter", "INPUT")
      |> RuleBuilder.match_source_ip(<<192, 168, 1, 100>>)
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

  alias NFTex.ExpressionBuilder, as: Expr
  alias NFTex.Port

  @nft_reg_1 1
  @nft_reg_2 2

  defstruct [
    :pid,
    :table,
    :chain,
    :rule_id,
    :family,
    expressions: []
  ]

  @type t :: %__MODULE__{
          pid: pid(),
          table: String.t(),
          chain: String.t(),
          rule_id: non_neg_integer() | nil,
          family: atom(),
          expressions: list()
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
      expressions: []
    }
  end

  ## Matching Functions

  @doc "Match source IP address"
  @spec match_source_ip(t(), binary()) :: t()
  def match_source_ip(builder, ip) when is_binary(ip) do
    add_match(builder, fn pid ->
      with {:ok, payload_id} <- Expr.payload_ipv4_saddr(pid, @nft_reg_1),
           {:ok, cmp_id} <- Expr.cmp_eq(pid, @nft_reg_1, ip) do
        {:ok, [payload_id, cmp_id]}
      end
    end)
  end

  @doc "Match destination IP address"
  @spec match_dest_ip(t(), binary()) :: t()
  def match_dest_ip(builder, ip) when is_binary(ip) do
    add_match(builder, fn pid ->
      with {:ok, payload_id} <- Expr.payload_ipv4_daddr(pid, @nft_reg_1),
           {:ok, cmp_id} <- Expr.cmp_eq(pid, @nft_reg_1, ip) do
        {:ok, [payload_id, cmp_id]}
      end
    end)
  end

  @doc "Match source port"
  @spec match_source_port(t(), non_neg_integer()) :: t()
  def match_source_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    port_bin = <<port::16-big>>
    add_match(builder, fn pid ->
      with {:ok, payload_id} <- Expr.payload_sport(pid, @nft_reg_1),
           {:ok, cmp_id} <- Expr.cmp_eq(pid, @nft_reg_1, port_bin) do
        {:ok, [payload_id, cmp_id]}
      end
    end)
  end

  @doc "Match destination port"
  @spec match_dest_port(t(), non_neg_integer()) :: t()
  def match_dest_port(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    port_bin = <<port::16-big>>
    add_match(builder, fn pid ->
      with {:ok, payload_id} <- Expr.payload_dport(pid, @nft_reg_1),
           {:ok, cmp_id} <- Expr.cmp_eq(pid, @nft_reg_1, port_bin) do
        {:ok, [payload_id, cmp_id]}
      end
    end)
  end

  @doc """
  Match connection tracking state.

  ## States

  - `:invalid` - Invalid connection
  - `:established` - Established connection
  - `:related` - Related to existing connection
  - `:new` - New connection

  ## Example

      builder |> match_ct_state([:established, :related])
  """
  @spec match_ct_state(t(), list(atom())) :: t()
  def match_ct_state(builder, states) when is_list(states) do
    # Build bitmask from states
    bitmask = Enum.reduce(states, 0, fn state, acc ->
      bit = case state do
        :invalid -> 0x01
        :established -> 0x02
        :related -> 0x04
        :new -> 0x08
        _ -> 0
      end
      Bitwise.bor(acc, bit)
    end)

    add_match(builder, fn pid ->
      with {:ok, ct_id} <- Expr.ct_state(pid, @nft_reg_1),
           {:ok, cmp_id} <- Expr.cmp_eq(pid, @nft_reg_1, <<bitmask>>) do
        {:ok, [ct_id, cmp_id]}
      end
    end)
  end

  @doc "Match input interface name"
  @spec match_iif(t(), String.t()) :: t()
  def match_iif(builder, ifname) when is_binary(ifname) do
    add_match(builder, fn pid ->
      with {:ok, meta_id} <- Expr.meta_iifname(pid, @nft_reg_1),
           {:ok, cmp_id} <- Expr.cmp_eq(pid, @nft_reg_1, ifname) do
        {:ok, [meta_id, cmp_id]}
      end
    end)
  end

  @doc "Match output interface name"
  @spec match_oif(t(), String.t()) :: t()
  def match_oif(builder, ifname) when is_binary(ifname) do
    add_match(builder, fn pid ->
      with {:ok, meta_id} <- Expr.meta_oifname(pid, @nft_reg_1),
           {:ok, cmp_id} <- Expr.cmp_eq(pid, @nft_reg_1, ifname) do
        {:ok, [meta_id, cmp_id]}
      end
    end)
  end

  ## Action Functions

  @doc "Add counter expression"
  @spec counter(t()) :: t()
  def counter(builder) do
    add_expr(builder, fn pid -> Expr.counter(pid) end)
  end

  @doc """
  Add log expression.

  ## Example

      builder |> log("DROPPED: ")
      builder |> log("AUDIT: ", level: :warning)
  """
  @spec log(t(), String.t(), keyword()) :: t()
  def log(builder, prefix, opts \\ []) do
    opts = Keyword.put(opts, :prefix, prefix)
    add_expr(builder, fn pid -> Expr.log(pid, opts) end)
  end

  @doc """
  Add rate limiting.

  ## Example

      builder |> rate_limit(10, :minute)
      builder |> rate_limit(100, :second, burst: 20)
  """
  @spec rate_limit(t(), non_neg_integer(), atom(), keyword()) :: t()
  def rate_limit(builder, rate, unit, opts \\ []) do
    add_expr(builder, fn pid -> Expr.limit(pid, rate, unit, opts) end)
  end

  ## Verdict Functions

  @doc "Accept packets"
  @spec accept(t()) :: t()
  def accept(builder) do
    add_expr(builder, fn pid -> Expr.verdict_accept(pid) end)
  end

  @doc "Drop packets silently"
  @spec drop(t()) :: t()
  def drop(builder) do
    add_expr(builder, fn pid -> Expr.verdict_drop(pid) end)
  end

  @doc """
  Reject packets with ICMP error.

  ## Example

      builder |> reject()
      builder |> reject(:tcp_reset)
  """
  @spec reject(t(), atom()) :: t()
  def reject(builder, type \\ :icmp_port_unreachable) do
    add_expr(builder, fn pid -> Expr.reject(pid, type) end)
  end

  ## Build and Commit

  @doc """
  Commit the rule to the kernel.

  This allocates a rule, adds all configured expressions, sends it to the kernel,
  and cleans up resources.

  Returns `:ok` on success, `{:error, reason}` on failure.
  """
  @spec commit(t()) :: :ok | {:error, term()}
  def commit(%__MODULE__{} = builder) do
    family_int = family_to_int(builder.family)

    with {:ok, rule_id} <- Port.call(builder.pid, {:rule_alloc}),
         :ok <- Port.call(builder.pid, {:rule_set_str, rule_id, :table, builder.table}),
         :ok <- Port.call(builder.pid, {:rule_set_str, rule_id, :chain, builder.chain}),
         :ok <- Port.call(builder.pid, {:rule_set_u32, rule_id, :family, family_int}),
         :ok <- add_expressions_to_rule(builder, rule_id),
         :ok <- Port.call(builder.pid, {:rule_send_to_kernel, rule_id, :add}) do
      Port.call(builder.pid, {:rule_free, rule_id})
      :ok
    else
      error -> error
    end
  end

  # Private helpers

  defp add_match(builder, match_fn) do
    %{builder | expressions: builder.expressions ++ [match_fn]}
  end

  defp add_expr(builder, expr_fn) do
    %{builder | expressions: builder.expressions ++ [expr_fn]}
  end

  defp add_expressions_to_rule(builder, rule_id) do
    Enum.reduce_while(builder.expressions, :ok, fn expr_fn, :ok ->
      case expr_fn.(builder.pid) do
        {:ok, expr_ids} when is_list(expr_ids) ->
          # Multiple expressions (e.g., payload + cmp)
          result = Enum.reduce_while(expr_ids, :ok, fn expr_id, :ok ->
            case Port.call(builder.pid, {:rule_add_expr, rule_id, expr_id}) do
              :ok -> {:cont, :ok}
              error -> {:halt, error}
            end
          end)

          case result do
            :ok -> {:cont, :ok}
            error -> {:halt, error}
          end

        {:ok, expr_id} when is_integer(expr_id) ->
          # Single expression
          case Port.call(builder.pid, {:rule_add_expr, rule_id, expr_id}) do
            :ok -> {:cont, :ok}
            error -> {:halt, error}
          end

        error ->
          {:halt, error}
      end
    end)
  end

  defp family_to_int(:inet), do: 1
  defp family_to_int(:ip), do: 2
  defp family_to_int(:inet6), do: 10
  defp family_to_int(:ip6), do: 10
  defp family_to_int(:arp), do: 3
  defp family_to_int(:bridge), do: 7
  defp family_to_int(:netdev), do: 5
end
