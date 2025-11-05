defmodule NFTex.Validation do
  @moduledoc """
  Validation helpers for NFTex operations with user-friendly error messages.

  This module provides validation functions that return clear, actionable error messages
  to help users quickly identify and fix issues.
  """

  @type validation_error :: {:error, String.t()}

  @doc """
  Validate IPv4 address format.

  Returns `:ok` if valid, or `{:error, message}` with a helpful error message.

  ## Examples

      iex> NFTex.Validation.validate_ipv4(<<192, 168, 1, 1>>)
      :ok

      iex> NFTex.Validation.validate_ipv4(<<192, 168, 1>>)
      {:error, "Invalid IPv4 address: expected 4 bytes, got 3 bytes. IPv4 addresses must be exactly 4 bytes (e.g., <<192, 168, 1, 1>>)"}

      iex> NFTex.Validation.validate_ipv4("192.168.1.1")
      {:error, "Invalid IPv4 address: expected binary, got string. Use <<192, 168, 1, 1>> format, not \"192.168.1.1\""}
  """
  @spec validate_ipv4(term()) :: :ok | validation_error()
  def validate_ipv4(ip) when is_binary(ip) do
    size = byte_size(ip)

    cond do
      size == 4 and String.printable?(ip) ->
        {:error,
         "Invalid IPv4 address: got string \"#{ip}\". " <>
           "Use binary format <<192, 168, 1, 1>>, not strings"}

      size == 4 ->
        :ok

      size > 4 and String.printable?(ip) ->
        {:error,
         "Invalid IPv4 address: got string \"#{ip}\". " <>
           "Use binary format <<192, 168, 1, 1>>, not dot-decimal notation"}

      true ->
        {:error,
         "Invalid IPv4 address: expected 4 bytes, got #{size} bytes. " <>
           "IPv4 addresses must be exactly 4 bytes (e.g., <<192, 168, 1, 1>>)"}
    end
  end

  def validate_ipv4(ip) do
    type = get_type_name(ip)

    {:error,
     "Invalid IPv4 address: expected binary, got #{type}. " <>
       "Use <<192, 168, 1, 1>> format, not #{inspect(ip)}"}
  end

  @doc """
  Validate IPv6 address format.

  Returns `:ok` if valid, or `{:error, message}` with a helpful error message.

  ## Examples

      iex> ipv6 = <<0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>
      iex> NFTex.Validation.validate_ipv6(ipv6)
      :ok

      iex> NFTex.Validation.validate_ipv6(<<1, 2, 3, 4>>)
      {:error, "Invalid IPv6 address: expected 16 bytes, got 4 bytes. IPv6 addresses must be exactly 16 bytes"}
  """
  @spec validate_ipv6(term()) :: :ok | validation_error()
  def validate_ipv6(ip) when is_binary(ip) do
    size = byte_size(ip)

    cond do
      size == 16 and String.printable?(ip) ->
        {:error,
         "Invalid IPv6 address: got string \"#{ip}\". " <>
           "Use binary format (16 bytes), not colon-hex notation"}

      size == 16 ->
        :ok

      size > 0 and String.printable?(ip) ->
        {:error,
         "Invalid IPv6 address: got string \"#{ip}\". " <>
           "Use binary format (16 bytes), not colon-hex notation"}

      true ->
        {:error,
         "Invalid IPv6 address: expected 16 bytes, got #{size} bytes. " <>
           "IPv6 addresses must be exactly 16 bytes (e.g., <<0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>)"}
    end
  end

  def validate_ipv6(ip) do
    type = get_type_name(ip)

    {:error,
     "Invalid IPv6 address: expected binary, got #{type}. " <>
       "Use binary format, not #{inspect(ip)}"}
  end

  @doc """
  Validate and normalize protocol family value.

  Returns `{:ok, family_int}` if valid, or `{:error, message}` with a helpful error message.

  ## Examples

      iex> NFTex.Validation.validate_family(:inet)
      {:ok, 2}

      iex> NFTex.Validation.validate_family(:ip)
      {:ok, 2}

      iex> NFTex.Validation.validate_family(:invalid)
      {:error, "Invalid family: :invalid. Valid families are: :inet (or :ip), :ip6 (or :inet6), :arp, :bridge, :netdev"}
  """
  @spec validate_family(term()) :: {:ok, non_neg_integer()} | validation_error()
  def validate_family(family) when family in [:inet, :ip], do: {:ok, 2}
  def validate_family(family) when family in [:ip6, :inet6], do: {:ok, 10}
  def validate_family(:arp), do: {:ok, 3}
  def validate_family(:bridge), do: {:ok, 7}
  def validate_family(:netdev), do: {:ok, 5}

  def validate_family(family) do
    {:error,
     "Invalid family: #{inspect(family)}. " <>
       "Valid families are: :inet (or :ip), :ip6 (or :inet6), :arp, :bridge, :netdev"}
  end

  @doc """
  Enhance netlink error messages with context.

  Takes a raw netlink error string and adds helpful context based on the operation and error type.

  ## Examples

      iex> NFTex.Validation.enhance_netlink_error("No such file or directory (ENOENT)", %{operation: :rule_add, table: "filter", chain: "INPUT"})
      "Failed to add rule to filter/INPUT: Table or chain not found. Ensure the table and chain exist (e.g., 'nft add table filter' and 'nft add chain filter INPUT ...')"

      iex> NFTex.Validation.enhance_netlink_error("Operation not permitted (EPERM)", %{operation: :rule_add})
      "Failed to add rule: Permission denied. NFTex requires CAP_NET_ADMIN capability. Run: sudo setcap cap_net_admin=ep path/to/priv/libnf_ex"
  """
  @spec enhance_netlink_error(String.t(), map()) :: String.t()
  def enhance_netlink_error(error_msg, context \\ %{})

  # ENOENT - No such file or directory (table/chain not found)
  def enhance_netlink_error("No such file or directory (ENOENT)", context) do
    operation = context[:operation] || :unknown
    table = context[:table]
    chain = context[:chain]

    base_msg = operation_prefix(operation)

    location =
      case {table, chain} do
        {nil, nil} -> ""
        {t, nil} -> " in table '#{t}'"
        {t, c} -> " to #{t}/#{c}"
      end

    "#{base_msg}#{location}: Table or chain not found. " <>
      "Ensure the table and chain exist (e.g., 'nft add table #{table || "filter"}' and 'nft add chain #{table || "filter"} #{chain || "INPUT"} ...')"
  end

  # EPERM - Operation not permitted (likely missing CAP_NET_ADMIN)
  def enhance_netlink_error("Operation not permitted (EPERM)", context) do
    operation = context[:operation] || :unknown
    base_msg = operation_prefix(operation)

    "#{base_msg}: Permission denied. " <>
      "NFTex requires CAP_NET_ADMIN capability. " <>
      "Run: sudo setcap cap_net_admin=ep path/to/priv/libnf_ex"
  end

  # EACCES - Permission denied
  def enhance_netlink_error("Permission denied (EACCES)", context) do
    enhance_netlink_error("Operation not permitted (EPERM)", context)
  end

  # EEXIST - Already exists
  def enhance_netlink_error("File exists (EEXIST)", context) do
    operation = context[:operation] || :unknown
    base_msg = operation_prefix(operation)
    table = context[:table]
    chain = context[:chain]
    set_name = context[:set]

    location =
      case {table, chain, set_name} do
        {t, c, nil} when t != nil and c != nil -> " #{t}/#{c}"
        {t, nil, s} when t != nil and s != nil -> " #{t}/#{s}"
        {t, nil, nil} when t != nil -> " '#{t}'"
        _ -> ""
      end

    "#{base_msg}#{location}: Already exists. " <>
      "Use a different name or delete the existing resource first."
  end

  # EINVAL - Invalid argument
  def enhance_netlink_error("Invalid argument (EINVAL)", context) do
    operation = context[:operation] || :unknown
    base_msg = operation_prefix(operation)

    "#{base_msg}: Invalid argument. " <>
      "Check that all required attributes are set correctly (table, chain, family, etc.)"
  end

  # ENOBUFS - No buffer space available
  def enhance_netlink_error("No buffer space available (ENOBUFS)", context) do
    operation = context[:operation] || :unknown
    base_msg = operation_prefix(operation)

    "#{base_msg}: No buffer space available. " <>
      "This may indicate too many rules or a resource limit. Check system limits."
  end

  # Default - pass through the original error
  def enhance_netlink_error(error_msg, _context) do
    error_msg
  end

  # Private helpers

  defp operation_prefix(operation) do
    case operation do
      :rule_add -> "Failed to add rule"
      :rule_delete -> "Failed to delete rule"
      :table_add -> "Failed to add table"
      :table_delete -> "Failed to delete table"
      :chain_add -> "Failed to add chain"
      :chain_delete -> "Failed to delete chain"
      :set_add -> "Failed to add set"
      :set_delete -> "Failed to delete set"
      :setelem_add -> "Failed to add set element"
      :setelem_delete -> "Failed to delete set element"
      _ -> "Operation failed"
    end
  end

  defp get_type_name(value) do
    cond do
      is_binary(value) -> "binary"
      is_bitstring(value) -> "bitstring"
      is_list(value) -> "list"
      is_tuple(value) -> "tuple"
      is_map(value) -> "map"
      is_atom(value) -> "atom"
      is_integer(value) -> "integer"
      is_float(value) -> "float"
      true -> "unknown type"
    end
  end
end
