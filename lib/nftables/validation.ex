defmodule NFTables.Validation do
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

      iex> NFTables.Validation.validate_ipv4(<<192, 168, 1, 1>>)
      :ok

      iex> NFTables.Validation.validate_ipv4(<<192, 168, 1>>)
      {:error, "Invalid IPv4 address: expected 4 bytes, got 3 bytes. IPv4 addresses must be exactly 4 bytes (e.g., <<192, 168, 1, 1>>)"}

      iex> NFTables.Validation.validate_ipv4("192.168.1.1")
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
      iex> NFTables.Validation.validate_ipv6(ipv6)
      :ok

      iex> NFTables.Validation.validate_ipv6(<<1, 2, 3, 4>>)
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

      iex> NFTables.Validation.validate_family(:inet)
      {:ok, 2}

      iex> NFTables.Validation.validate_family(:ip)
      {:ok, 2}

      iex> NFTables.Validation.validate_family(:invalid)
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
  Convert errno to human-readable error message.

  Takes an errno integer (from netlink/kernel) and converts it to a descriptive string.
  This mirrors the functionality in the Zig native code but on the Elixir side.

  ## Examples

      iex> NFTables.Validation.errno_to_string(2)
      "No such file or directory (ENOENT)"

      iex> NFTables.Validation.errno_to_string(1)
      "Operation not permitted (EPERM)"

      iex> NFTables.Validation.errno_to_string(0)
      "Success"
  """
  @spec errno_to_string(integer()) :: String.t()
  def errno_to_string(errno) when is_integer(errno) do
    # errno can be negative or positive, normalize to positive
    errno = abs(errno)

    case errno do
      0 -> "Success"
      1 -> "Operation not permitted (EPERM)"
      2 -> "No such file or directory (ENOENT)"
      3 -> "No such process (ESRCH)"
      4 -> "Interrupted system call (EINTR)"
      5 -> "I/O error (EIO)"
      6 -> "No such device or address (ENXIO)"
      9 -> "Bad file descriptor (EBADF)"
      11 -> "Try again (EAGAIN)"
      12 -> "Out of memory (ENOMEM)"
      13 -> "Permission denied (EACCES)"
      14 -> "Bad address (EFAULT)"
      16 -> "Device or resource busy (EBUSY)"
      17 -> "File exists (EEXIST)"
      19 -> "No such device (ENODEV)"
      22 -> "Invalid argument (EINVAL)"
      24 -> "Too many open files (EMFILE)"
      28 -> "No space left on device (ENOSPC)"
      32 -> "Broken pipe (EPIPE)"
      71 -> "Protocol error (EPROTO)"
      90 -> "Message too long (EMSGSIZE)"
      92 -> "Protocol not available (ENOPROTOOPT)"
      93 -> "Protocol not supported (EPROTONOSUPPORT)"
      95 -> "Operation not supported (EOPNOTSUPP)"
      97 -> "Address family not supported (EAFNOSUPPORT)"
      98 -> "Address already in use (EADDRINUSE)"
      99 -> "Cannot assign requested address (EADDRNOTAVAIL)"
      100 -> "Network is down (ENETDOWN)"
      101 -> "Network is unreachable (ENETUNREACH)"
      103 -> "Software caused connection abort (ECONNABORTED)"
      104 -> "Connection reset by peer (ECONNRESET)"
      105 -> "No buffer space available (ENOBUFS)"
      106 -> "Transport endpoint is already connected (EISCONN)"
      107 -> "Transport endpoint is not connected (ENOTCONN)"
      110 -> "Connection timed out (ETIMEDOUT)"
      111 -> "Connection refused (ECONNREFUSED)"
      _ -> "Unknown error (errno=#{errno})"
    end
  end

  @doc """
  Enhance netlink error messages with context.

  Takes a raw netlink error (string or errno integer) and adds helpful context based on
  the operation and error type.

  ## Examples

      iex> NFTables.Validation.enhance_netlink_error("No such file or directory (ENOENT)", %{operation: :rule_add, table: "filter", chain: "INPUT"})
      "Failed to add rule to filter/INPUT: Table or chain not found. Ensure the table and chain exist (e.g., 'nft add table filter' and 'nft add chain filter INPUT ...')"

      iex> NFTables.Validation.enhance_netlink_error(2, %{operation: :rule_add, table: "filter", chain: "INPUT"})
      "Failed to add rule to filter/INPUT: Table or chain not found. Ensure the table and chain exist (e.g., 'nft add table filter' and 'nft add chain filter INPUT ...')"

      iex> NFTables.Validation.enhance_netlink_error("Operation not permitted (EPERM)", %{operation: :rule_add})
      "Failed to add rule: Permission denied. NFTex requires CAP_NET_ADMIN capability. Run: sudo setcap cap_net_admin=ep path/to/priv/port_nftables"
  """
  @spec enhance_netlink_error(String.t() | integer(), map()) :: String.t()
  def enhance_netlink_error(error, context \\ %{})

  def enhance_netlink_error(errno, context) when is_integer(errno) do
    # Convert errno to string first, then enhance
    errno
    |> errno_to_string()
    |> enhance_netlink_error(context)
  end

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
      "Run: sudo setcap cap_net_admin=ep path/to/priv/port_nftables"
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
  def enhance_netlink_error(error_msg, _context) when is_binary(error_msg) do
    error_msg
  end

  @doc """
  Validate flowtable hook.

  Flowtables only support the :ingress hook.

  ## Examples

      iex> NFTables.Validation.validate_flowtable_hook(:ingress)
      :ok

      iex> NFTables.Validation.validate_flowtable_hook(:input)
      {:error, "Invalid flowtable hook: :input. Flowtables only support :ingress hook"}
  """
  @spec validate_flowtable_hook(atom()) :: :ok | validation_error()
  def validate_flowtable_hook(:ingress), do: :ok

  def validate_flowtable_hook(hook) do
    {:error,
     "Invalid flowtable hook: #{inspect(hook)}. " <>
       "Flowtables only support :ingress hook"}
  end

  @doc """
  Validate flowtable devices list.

  Devices must be a non-empty list of strings (interface names).

  ## Examples

      iex> NFTables.Validation.validate_flowtable_devices(["eth0", "eth1"])
      :ok

      iex> NFTables.Validation.validate_flowtable_devices([])
      {:error, "Invalid flowtable devices: empty list. At least one device must be specified (e.g., [\\"eth0\\"])"}

      iex> NFTables.Validation.validate_flowtable_devices("eth0")
      {:error, "Invalid flowtable devices: expected list, got string. Use [\\"eth0\\"] not \\"eth0\\""}
  """
  @spec validate_flowtable_devices(term()) :: :ok | validation_error()
  def validate_flowtable_devices(devices) when is_list(devices) do
    cond do
      Enum.empty?(devices) ->
        {:error,
         "Invalid flowtable devices: empty list. " <>
           "At least one device must be specified (e.g., [\"eth0\"])"}

      not Enum.all?(devices, &is_binary/1) ->
        {:error,
         "Invalid flowtable devices: all devices must be strings (interface names). " <>
           "Got: #{inspect(devices)}"}

      true ->
        :ok
    end
  end

  def validate_flowtable_devices(devices) do
    type = get_type_name(devices)

    {:error,
     "Invalid flowtable devices: expected list, got #{type}. " <>
       "Use [\"eth0\"] not #{inspect(devices)}"}
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
