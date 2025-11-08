defmodule NFTex.Sysctl.Network do
  @moduledoc """
  Convenience functions for common network sysctl operations.

  This module provides high-level helpers for frequently-used network
  configuration tasks, wrapping the low-level `NFTex.Sysctl` API.

  ## Examples

      # Enable IP forwarding (for routers)
      :ok = NFTex.Sysctl.Network.enable_ipv4_forwarding(pid)

      # Configure router settings
      :ok = NFTex.Sysctl.Network.configure_router(pid,
        ipv4_forwarding: true,
        ipv6_forwarding: true,
        syncookies: true
      )

      # Harden security settings
      :ok = NFTex.Sysctl.Network.harden_security(pid)
  """

  alias NFTex.Sysctl

  ## IPv4 Forwarding

  @doc """
  Enable IPv4 forwarding.

  Enables IP forwarding on all interfaces. Required for routers and NAT gateways.

  ## Example

      :ok = NFTex.Sysctl.Network.enable_ipv4_forwarding(pid)
  """
  @spec enable_ipv4_forwarding(pid() | keyword()) :: :ok | {:error, term()}
  def enable_ipv4_forwarding(pid_or_opts) do
    Sysctl.set(pid_or_opts, "net.ipv4.ip_forward", "1")
  end

  @doc """
  Disable IPv4 forwarding.

  ## Example

      :ok = NFTex.Sysctl.Network.disable_ipv4_forwarding(pid)
  """
  @spec disable_ipv4_forwarding(pid() | keyword()) :: :ok | {:error, term()}
  def disable_ipv4_forwarding(pid_or_opts) do
    Sysctl.set(pid_or_opts, "net.ipv4.ip_forward", "0")
  end

  @doc """
  Check if IPv4 forwarding is enabled.

  Returns `{:ok, true}` if enabled, `{:ok, false}` if disabled.

  ## Example

      {:ok, true} = NFTex.Sysctl.Network.ipv4_forwarding_enabled?(pid)
  """
  @spec ipv4_forwarding_enabled?(pid() | keyword()) :: {:ok, boolean()} | {:error, term()}
  def ipv4_forwarding_enabled?(pid_or_opts) do
    case Sysctl.get(pid_or_opts, "net.ipv4.ip_forward") do
      {:ok, "1"} -> {:ok, true}
      {:ok, "0"} -> {:ok, false}
      error -> error
    end
  end

  ## IPv6 Forwarding

  @doc """
  Enable IPv6 forwarding.

  ## Example

      :ok = NFTex.Sysctl.Network.enable_ipv6_forwarding(pid)
  """
  @spec enable_ipv6_forwarding(pid() | keyword()) :: :ok | {:error, term()}
  def enable_ipv6_forwarding(pid_or_opts) do
    Sysctl.set(pid_or_opts, "net.ipv6.conf.all.forwarding", "1")
  end

  @doc """
  Disable IPv6 forwarding.

  ## Example

      :ok = NFTex.Sysctl.Network.disable_ipv6_forwarding(pid)
  """
  @spec disable_ipv6_forwarding(pid() | keyword()) :: :ok | {:error, term()}
  def disable_ipv6_forwarding(pid_or_opts) do
    Sysctl.set(pid_or_opts, "net.ipv6.conf.all.forwarding", "0")
  end

  ## TCP Settings

  @doc """
  Enable TCP SYN cookies for DDoS protection.

  SYN cookies help protect against SYN flood attacks.

  ## Example

      :ok = NFTex.Sysctl.Network.enable_syncookies(pid)
  """
  @spec enable_syncookies(pid() | keyword()) :: :ok | {:error, term()}
  def enable_syncookies(pid_or_opts) do
    Sysctl.set(pid_or_opts, "net.ipv4.tcp_syncookies", "1")
  end

  @doc """
  Disable TCP SYN cookies.

  ## Example

      :ok = NFTex.Sysctl.Network.disable_syncookies(pid)
  """
  @spec disable_syncookies(pid() | keyword()) :: :ok | {:error, term()}
  def disable_syncookies(pid_or_opts) do
    Sysctl.set(pid_or_opts, "net.ipv4.tcp_syncookies", "0")
  end

  ## Connection Tracking

  @doc """
  Set maximum connection tracking entries.

  Higher values allow more concurrent connections but use more memory.

  ## Example

      :ok = NFTex.Sysctl.Network.set_conntrack_max(pid, 131072)
  """
  @spec set_conntrack_max(pid() | keyword(), pos_integer()) :: :ok | {:error, term()}
  def set_conntrack_max(pid_or_opts, max) when is_integer(max) and max > 0 do
    Sysctl.set(pid_or_opts, "net.netfilter.nf_conntrack_max", to_string(max))
  end

  @doc """
  Get current connection tracking max.

  ## Example

      {:ok, 65536} = NFTex.Sysctl.Network.get_conntrack_max(pid)
  """
  @spec get_conntrack_max(pid() | keyword()) :: {:ok, pos_integer()} | {:error, term()}
  def get_conntrack_max(pid_or_opts) do
    case Sysctl.get(pid_or_opts, "net.netfilter.nf_conntrack_max") do
      {:ok, value} -> {:ok, String.to_integer(value)}
      error -> error
    end
  end

  ## ICMP Settings

  @doc """
  Ignore all ICMP ping requests (stealth mode).

  ## Example

      :ok = NFTex.Sysctl.Network.ignore_ping(pid)
  """
  @spec ignore_ping(pid() | keyword()) :: :ok | {:error, term()}
  def ignore_ping(pid_or_opts) do
    Sysctl.set(pid_or_opts, "net.ipv4.icmp_echo_ignore_all", "1")
  end

  @doc """
  Allow ICMP ping requests.

  ## Example

      :ok = NFTex.Sysctl.Network.allow_ping(pid)
  """
  @spec allow_ping(pid() | keyword()) :: :ok | {:error, term()}
  def allow_ping(pid_or_opts) do
    Sysctl.set(pid_or_opts, "net.ipv4.icmp_echo_ignore_all", "0")
  end

  ## Composite Operations

  @doc """
  Configure router settings.

  Applies common settings for a router/gateway.

  ## Options

  - `:ipv4_forwarding` - Enable IPv4 forwarding (default: false)
  - `:ipv6_forwarding` - Enable IPv6 forwarding (default: false)
  - `:syncookies` - Enable SYN cookies (default: false)
  - `:send_redirects` - Enable ICMP redirects (default: false)

  ## Example

      :ok = NFTex.Sysctl.Network.configure_router(pid,
        ipv4_forwarding: true,
        ipv6_forwarding: true,
        syncookies: true,
        send_redirects: false
      )
  """
  @spec configure_router(pid() | keyword(), keyword()) :: :ok | {:error, term()}
  def configure_router(pid_or_opts, opts \\ []) do
    with :ok <- maybe_set(pid_or_opts, opts[:ipv4_forwarding], &enable_ipv4_forwarding/1),
         :ok <- maybe_set(pid_or_opts, opts[:ipv6_forwarding], &enable_ipv6_forwarding/1),
         :ok <- maybe_set(pid_or_opts, opts[:syncookies], &enable_syncookies/1),
         :ok <- maybe_set_bool(pid_or_opts, opts[:send_redirects], "net.ipv4.conf.all.send_redirects") do
      :ok
    end
  end

  @doc """
  Harden network security settings.

  Applies security-focused sysctl settings:
  - Enable reverse path filtering (anti-spoofing)
  - Disable source routing
  - Disable ICMP redirects
  - Enable SYN cookies

  ## Example

      :ok = NFTex.Sysctl.Network.harden_security(pid)
  """
  @spec harden_security(pid() | keyword()) :: :ok | {:error, term()}
  def harden_security(pid_or_opts) do
    with :ok <- Sysctl.set(pid_or_opts, "net.ipv4.conf.all.rp_filter", "1"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv4.conf.default.rp_filter", "1"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv4.conf.all.accept_source_route", "0"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv4.conf.default.accept_source_route", "0"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv4.conf.all.send_redirects", "0"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv4.conf.default.send_redirects", "0"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv4.conf.all.accept_redirects", "0"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv4.conf.default.accept_redirects", "0"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv6.conf.all.accept_redirects", "0"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv6.conf.default.accept_redirects", "0"),
         :ok <- Sysctl.set(pid_or_opts, "net.ipv4.tcp_syncookies", "1") do
      :ok
    end
  end

  # Private helpers

  defp maybe_set(_pid_or_opts, nil, _fun), do: :ok
  defp maybe_set(_pid_or_opts, false, _fun), do: :ok
  defp maybe_set(pid_or_opts, true, fun), do: fun.(pid_or_opts)

  defp maybe_set_bool(_pid_or_opts, nil, _param), do: :ok
  defp maybe_set_bool(pid_or_opts, value, param) when is_boolean(value) do
    Sysctl.set(pid_or_opts, param, if(value, do: "1", else: "0"))
  end
end
