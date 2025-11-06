defmodule NFTex.Rule do
  @moduledoc """
  High-level rule operations for nftables.

  Rules define packet filtering and manipulation logic within chains.

  ## Quick Example

      {:ok, pid} = NFTex.start_link()

      # Create table and chain first
      :ok = NFTex.Table.create(pid, %{name: "filter", family: :inet})
      :ok = NFTex.Chain.create(pid, %{
        table: "filter",
        name: "input",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      })

      # Block an IP address
      :ok = NFTex.Rule.block_ip(pid, "filter", "input", "192.168.1.100")

      # Accept an IP address
      :ok = NFTex.Rule.accept_ip(pid, "filter", "input", "10.0.0.1")

  """

  alias NFTex.JSONPort

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev

  @doc """
  Add a rule using nft syntax.

  ## Parameters

  - `family` - Protocol family
  - `table` - Table name
  - `chain` - Chain name
  - `expr` - nft expression/statement string

  ## Examples

      # Block specific IP
      NFTex.Rule.add(pid, %{
        family: :inet,
        table: "filter",
        chain: "input",
        expr: "ip saddr 192.168.1.100 drop"
      })

      # Accept on specific port
      NFTex.Rule.add(pid, %{
        family: :inet,
        table: "filter",
        chain: "input",
        expr: "tcp dport 22 accept"
      })

  """
  @spec add(pid(), map()) :: :ok | {:error, term()}
  def add(pid, %{family: family, table: table, chain: chain, expr: expr}) do
    # Build raw nft syntax command (not JSON!)
    # libnftables accepts text commands via nft_run_cmd_from_buffer
    nft_command = "add rule #{family} #{table} #{chain} #{expr}"

    # Send raw nft command to port
    case JSONPort.call(pid, nft_command) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response} ->
        # Non-empty response might be an error message
        if String.contains?(response, "Error") do
          {:error, {:nft_error, response}}
        else
          :ok
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Delete a rule by handle.

  ## Example

      NFTex.Rule.delete(pid, "filter", "input", :inet, 42)

  """
  @spec delete(pid(), String.t(), String.t(), family(), integer()) :: :ok | {:error, term()}
  def delete(pid, table, chain, family, handle) when is_integer(handle) do
    # Build raw nft syntax command
    nft_command = "delete rule #{family} #{table} #{chain} handle #{handle}"

    # Send raw nft command to port
    case JSONPort.call(pid, nft_command) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response} ->
        # Non-empty response might be an error message
        if String.contains?(response, "Error") do
          {:error, {:nft_error, response}}
        else
          :ok
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  List rules in a chain.

  This is a convenience function that calls `NFTex.Query.list_rules/3`.

  ## Example

      {:ok, rules} = NFTex.Rule.list(pid, "filter", "input")

  """
  @spec list(pid(), String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list(pid, table, chain, opts \\ []) do
    NFTex.Query.list_rules(pid, table, chain, opts)
  end

  @doc """
  Block an IPv4 address.

  ## Parameters

  - `ip_address` - IP address as string (e.g., "192.168.1.100")
  - `opts` - Options:
    - `:counter` - Add packet counter (default: false)
    - `:comment` - Add comment (default: nil)

  ## Example

      :ok = NFTex.Rule.block_ip(pid, "filter", "input", "192.168.1.100")
      :ok = NFTex.Rule.block_ip(pid, "filter", "input", "10.0.0.1", counter: true)

  """
  @spec block_ip(pid(), String.t(), String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def block_ip(pid, table, chain, ip_address, opts \\ []) when is_binary(ip_address) do
    counter = if Keyword.get(opts, :counter, false), do: "counter ", else: ""
    expr = "ip saddr #{ip_address} #{counter}drop"

    add(pid, %{
      family: :inet,
      table: table,
      chain: chain,
      expr: expr
    })
  end

  @doc """
  Accept an IPv4 address.

  ## Example

      :ok = NFTex.Rule.accept_ip(pid, "filter", "input", "10.0.0.1")

  """
  @spec accept_ip(pid(), String.t(), String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def accept_ip(pid, table, chain, ip_address, opts \\ []) when is_binary(ip_address) do
    counter = if Keyword.get(opts, :counter, false), do: "counter ", else: ""
    expr = "ip saddr #{ip_address} #{counter}accept"

    add(pid, %{
      family: :inet,
      table: table,
      chain: chain,
      expr: expr
    })
  end

  @doc """
  Block an IPv6 address.

  ## Example

      :ok = NFTex.Rule.block_ipv6(pid, "filter", "input", "2001:db8::1")

  """
  @spec block_ipv6(pid(), String.t(), String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def block_ipv6(pid, table, chain, ipv6_address, opts \\ []) when is_binary(ipv6_address) do
    counter = if Keyword.get(opts, :counter, false), do: "counter ", else: ""
    expr = "ip6 saddr #{ipv6_address} #{counter}drop"

    add(pid, %{
      family: :inet,
      table: table,
      chain: chain,
      expr: expr
    })
  end

  @doc """
  Accept an IPv6 address.

  ## Example

      :ok = NFTex.Rule.accept_ipv6(pid, "filter", "input", "2001:db8::1")

  """
  @spec accept_ipv6(pid(), String.t(), String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def accept_ipv6(pid, table, chain, ipv6_address, opts \\ []) when is_binary(ipv6_address) do
    counter = if Keyword.get(opts, :counter, false), do: "counter ", else: ""
    expr = "ip6 saddr #{ipv6_address} #{counter}accept"

    add(pid, %{
      family: :inet,
      table: table,
      chain: chain,
      expr: expr
    })
  end

  @doc """
  Add rate limiting rule.

  ## Parameters

  - `rate` - Rate limit number
  - `unit` - Time unit: `:second`, `:minute`, `:hour`, `:day`

  ## Example

      # Limit to 10 packets per second
      :ok = NFTex.Rule.rate_limit(pid, "filter", "input", 10, :second)

  """
  @spec rate_limit(pid(), String.t(), String.t(), integer(), atom(), keyword()) :: :ok | {:error, term()}
  def rate_limit(pid, table, chain, rate, unit, opts \\ []) do
    unit_str = case unit do
      :second -> "second"
      :minute -> "minute"
      :hour -> "hour"
      :day -> "day"
    end

    action = Keyword.get(opts, :action, :drop)
    action_str = to_string(action)

    expr = "limit rate #{rate}/#{unit_str} #{action_str}"

    add(pid, %{
      family: :inet,
      table: table,
      chain: chain,
      expr: expr
    })
  end
end
