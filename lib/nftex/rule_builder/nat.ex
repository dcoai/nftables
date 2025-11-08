defmodule NFTex.RuleBuilder.NAT do
  @moduledoc """
  Network Address Translation (NAT) functions for RuleBuilder.

  Provides functions for SNAT, DNAT, masquerading, and port redirection.
  """

  alias NFTex.RuleBuilder

  @doc """
  Apply source NAT (SNAT) to an IP address.

  ## Example

      # SNAT to single IP
      builder |> snat_to("203.0.113.1")

      # SNAT to IP:port
      builder |> snat_to("203.0.113.1", port: 1024)
  """
  @spec snat_to(RuleBuilder.t(), String.t(), keyword()) :: RuleBuilder.t()
  def snat_to(builder, ip, opts \\ []) when is_binary(ip) do
    port = Keyword.get(opts, :port)

    # Add family prefix for inet tables
    nat_type = case builder.family do
      :ip6 -> "snat ip6"
      :inet6 -> "snat ip6"
      _ -> "snat ip"
    end

    snat_str = if port do
      "#{nat_type} to #{ip}:#{port}"
    else
      "#{nat_type} to #{ip}"
    end
    RuleBuilder.add_part(builder, snat_str)
  end

  @doc """
  Apply destination NAT (DNAT) to an IP address.

  ## Example

      # DNAT to single IP
      builder |> dnat_to("192.168.1.100")

      # DNAT to IP:port (port forwarding)
      builder |> dnat_to("192.168.1.100", port: 8080)
  """
  @spec dnat_to(RuleBuilder.t(), String.t(), keyword()) :: RuleBuilder.t()
  def dnat_to(builder, ip, opts \\ []) when is_binary(ip) do
    port = Keyword.get(opts, :port)

    # Add family prefix for inet tables
    nat_type = case builder.family do
      :ip6 -> "dnat ip6"
      :inet6 -> "dnat ip6"
      _ -> "dnat ip"
    end

    dnat_str = if port do
      "#{nat_type} to #{ip}:#{port}"
    else
      "#{nat_type} to #{ip}"
    end
    RuleBuilder.add_part(builder, dnat_str)
  end

  @doc """
  Apply masquerading (dynamic SNAT).

  Automatically uses the outgoing interface's IP address.

  ## Example

      # Basic masquerade
      builder |> masquerade()

      # Masquerade with port range
      builder |> masquerade(port_range: "1024-65535")
  """
  @spec masquerade(RuleBuilder.t(), keyword()) :: RuleBuilder.t()
  def masquerade(builder, opts \\ []) do
    port_range = Keyword.get(opts, :port_range)
    masq_str = if port_range do
      "masquerade to :#{port_range}"
    else
      "masquerade"
    end
    RuleBuilder.add_part(builder, masq_str)
  end

  @doc """
  Redirect to local port.

  Used for transparent proxying.

  ## Example

      # Redirect HTTP to local proxy
      builder |> match_dest_port(80) |> redirect_to(3128)
  """
  @spec redirect_to(RuleBuilder.t(), non_neg_integer()) :: RuleBuilder.t()
  def redirect_to(builder, port) when is_integer(port) and port >= 0 and port <= 65535 do
    RuleBuilder.add_part(builder, "redirect to :#{port}")
  end
end
