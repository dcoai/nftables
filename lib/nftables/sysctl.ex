defmodule NFTables.Sysctl do
  @moduledoc """
  Manage Linux network sysctl parameters via /proc/sys/net/*.

  This module provides safe read/write operations for network-related
  sysctl parameters. All operations require CAP_NET_ADMIN capability.

  ## Security

  - Parameter whitelist enforced by port (no arbitrary file access)
  - Value validation per parameter type
  - Limited to /proc/sys/net/* only
  - Uses existing CAP_NET_ADMIN capability

  ## Supported Parameters

  ### IPv4 Core
  - `net.ipv4.ip_forward` - IP forwarding (0/1)
  - `net.ipv4.conf.all.forwarding` - Enable forwarding on all interfaces
  - `net.ipv4.conf.default.forwarding` - Default forwarding for new interfaces

  ### IPv4 TCP
  - `net.ipv4.tcp_syncookies` - SYN cookie protection (0/1)
  - `net.ipv4.tcp_timestamps` - TCP timestamps (0/1)
  - `net.ipv4.tcp_tw_reuse` - Reuse TIME-WAIT sockets (0/1)
  - `net.ipv4.tcp_fin_timeout` - FIN timeout in seconds
  - `net.ipv4.tcp_keepalive_time` - Keepalive time in seconds
  - `net.ipv4.tcp_keepalive_probes` - Number of keepalive probes
  - `net.ipv4.tcp_keepalive_intvl` - Keepalive interval in seconds
  - `net.ipv4.ip_local_port_range` - Local port range (format: "min max")

  ### IPv6
  - `net.ipv6.conf.all.forwarding` - IPv6 forwarding
  - `net.ipv6.conf.default.forwarding` - Default IPv6 forwarding

  ### Netfilter / Connection Tracking
  - `net.netfilter.nf_conntrack_max` - Max conntrack entries
  - `net.netfilter.nf_conntrack_tcp_timeout_established` - TCP established timeout
  - `net.netfilter.nf_conntrack_tcp_timeout_time_wait` - TCP TIME-WAIT timeout
  - `net.netfilter.nf_conntrack_tcp_timeout_close_wait` - TCP CLOSE-WAIT timeout
  - `net.netfilter.nf_conntrack_tcp_timeout_fin_wait` - TCP FIN-WAIT timeout
  - `net.nf_conntrack_max` - Same as above (kernel alias)

  ### ICMP
  - `net.ipv4.icmp_echo_ignore_all` - Ignore all ping requests (0/1)
  - `net.ipv4.icmp_echo_ignore_broadcasts` - Ignore broadcast pings (0/1)
  - `net.ipv4.icmp_ratelimit` - ICMP rate limit

  ### IPv4 Security
  - `net.ipv4.conf.all.rp_filter` - Reverse path filtering
  - `net.ipv4.conf.default.rp_filter` - Default reverse path filtering
  - `net.ipv4.conf.all.accept_source_route` - Accept source routed packets
  - `net.ipv4.conf.default.accept_source_route` - Default accept source route
  - `net.ipv4.conf.all.send_redirects` - Send ICMP redirects
  - `net.ipv4.conf.default.send_redirects` - Default send redirects
  - `net.ipv4.conf.all.accept_redirects` - Accept ICMP redirects
  - `net.ipv4.conf.default.accept_redirects` - Default accept redirects

  ### IPv6 Security
  - `net.ipv6.conf.all.accept_redirects` - Accept ICMP redirects
  - `net.ipv6.conf.default.accept_redirects` - Default accept redirects
  - `net.ipv6.conf.all.accept_source_route` - Accept source routed packets
  - `net.ipv6.conf.default.accept_source_route` - Default accept source route

  ## Examples

      # Get current IP forwarding setting
      {:ok, "0"} = NFTables.Sysctl.get(pid, "net.ipv4.ip_forward")

      # Enable IP forwarding
      :ok = NFTables.Sysctl.set(pid, "net.ipv4.ip_forward", "1")

      # Configure connection tracking
      :ok = NFTables.Sysctl.set(pid, "net.netfilter.nf_conntrack_max", "131072")

      # Set local port range
      :ok = NFTables.Sysctl.set(pid, "net.ipv4.ip_local_port_range", "32768 60999")

  ## Error Handling

  - `{:error, reason}` - Parameter not in whitelist, not found, or invalid value
  - Port validates all parameters and values before applying changes
  """

  alias NFTables.Local

  @doc """
  Get a sysctl parameter value.

  ## Parameters

  - `pid_or_opts` - NFTables process pid or keyword list with `:pid` key
  - `parameter` - Sysctl parameter name (e.g., "net.ipv4.ip_forward")

  ## Returns

  - `{:ok, value}` - Parameter value as string
  - `{:error, reason}` - Error message

  ## Examples

      {:ok, "1"} = NFTables.Sysctl.get(pid, "net.ipv4.ip_forward")
      {:ok, "131072"} = NFTables.Sysctl.get(pid, "net.netfilter.nf_conntrack_max")
  """
  @spec get(pid() | keyword(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def get(pid_or_opts, parameter) when is_binary(parameter) do
    command_map = build_sysctl_get(parameter)

    case Local.submit(command_map, normalize_opts(pid_or_opts)) do
      {:ok, response} ->
        parse_get_response(response, parameter)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Set a sysctl parameter value.

  ## Parameters

  - `pid_or_opts` - NFTables process pid or keyword list with `:pid` key
  - `parameter` - Sysctl parameter name (e.g., "net.ipv4.ip_forward")
  - `value` - New value as string

  ## Returns

  - `:ok` - Parameter successfully set
  - `{:error, reason}` - Error message

  ## Examples

      :ok = NFTables.Sysctl.set(pid, "net.ipv4.ip_forward", "1")
      :ok = NFTables.Sysctl.set(pid, "net.ipv4.tcp_syncookies", "1")
      :ok = NFTables.Sysctl.set(pid, "net.ipv4.ip_local_port_range", "32768 60999")
  """
  @spec set(pid() | keyword(), String.t(), String.t()) :: :ok | {:error, term()}
  def set(pid_or_opts, parameter, value) when is_binary(parameter) and is_binary(value) do
    command_map = build_sysctl_set(parameter, value)

    case Local.submit(command_map, normalize_opts(pid_or_opts)) do
      {:ok, response} ->
        parse_set_response(response)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get a sysctl parameter value, raising on error.

  ## Parameters

  - `pid_or_opts` - NFTables process pid or keyword list with `:pid` key
  - `parameter` - Sysctl parameter name

  ## Returns

  Parameter value as string, or raises on error.

  ## Examples

      "1" = NFTables.Sysctl.get!(pid, "net.ipv4.ip_forward")
  """
  @spec get!(pid() | keyword(), String.t()) :: String.t()
  def get!(pid_or_opts, parameter) do
    case get(pid_or_opts, parameter) do
      {:ok, value} -> value
      {:error, reason} -> raise "Sysctl.get! failed: #{inspect(reason)}"
    end
  end

  @doc """
  Set a sysctl parameter value, raising on error.

  ## Parameters

  - `pid_or_opts` - NFTables process pid or keyword list with `:pid` key
  - `parameter` - Sysctl parameter name
  - `value` - New value as string

  ## Returns

  `:ok` or raises on error.

  ## Examples

      :ok = NFTables.Sysctl.set!(pid, "net.ipv4.ip_forward", "1")
  """
  @spec set!(pid() | keyword(), String.t(), String.t()) :: :ok
  def set!(pid_or_opts, parameter, value) do
    case set(pid_or_opts, parameter, value) do
      :ok -> :ok
      {:error, reason} -> raise "Sysctl.set! failed: #{inspect(reason)}"
    end
  end

  # Private functions

  defp normalize_opts(pid) when is_pid(pid), do: [pid: pid]
  defp normalize_opts(opts) when is_list(opts), do: opts

  defp parse_get_response(response, _parameter) do
    case response do
      %{"sysctl" => %{"value" => value}} ->
        {:ok, value}

      %{"error" => error} ->
        {:error, error}

      _ ->
        {:error, :invalid_response}
    end
  end

  defp parse_set_response(response) do
    case response do
      %{"sysctl" => %{"status" => "ok"}} ->
        :ok

      %{"error" => error} ->
        {:error, error}

      _ ->
        {:error, :invalid_response}
    end
  end

  # Build sysctl get command map
  defp build_sysctl_get(parameter) when is_binary(parameter) do
    %{
      "sysctl" => %{
        "operation" => "get",
        "parameter" => parameter
      }
    }
  end

  # Build sysctl set command map
  defp build_sysctl_set(parameter, value) when is_binary(parameter) and is_binary(value) do
    %{
      "sysctl" => %{
        "operation" => "set",
        "parameter" => parameter,
        "value" => value
      }
    }
  end
end
