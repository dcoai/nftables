defmodule NFTables.Expr.NAT do
  @moduledoc """
  Network Address Translation (NAT) functions for Expr.

  Provides functions for SNAT, DNAT, masquerading, and port redirection.
  """

  alias NFTables.Expr

  @doc """
  Apply source NAT (SNAT) to an IP address.

  ## Example

      # SNAT to single IP
      builder |> snat_to("203.0.113.1")

      # SNAT to IP:port
      builder |> snat_to("203.0.113.1", port: 1024)
  """
  @spec snat_to(Expr.t(), String.t(), keyword()) :: Expr.t()
  def snat_to(builder \\ Expr.expr(), ip, opts \\ []) when is_binary(ip) do
    port = Keyword.get(opts, :port)
    expr = Expr.Structs.snat(ip, port: port)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Apply destination NAT (DNAT) to an IP address.

  ## Example

      # DNAT to single IP
      builder |> dnat_to("192.168.1.100")

      # DNAT to IP:port (port forwarding)
      builder |> dnat_to("192.168.1.100", port: 8080)
  """
  @spec dnat_to(Expr.t(), String.t(), keyword()) :: Expr.t()
  def dnat_to(builder \\ Expr.expr(), ip, opts \\ []) when is_binary(ip) do
    port = Keyword.get(opts, :port)
    expr = Expr.Structs.dnat(ip, port: port)
    Expr.add_expr(builder, expr)
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
  @spec masquerade(Expr.t(), keyword()) :: Expr.t()
  def masquerade(builder \\ Expr.expr(), opts \\ []) do
    port_range = Keyword.get(opts, :port_range)

    expr = if port_range do
      %{"masquerade" => %{"port" => port_range}}
    else
      %{"masquerade" => nil}
    end

    Expr.add_expr(builder, expr)
  end

  @doc """
  Redirect to local port.

  Used for transparent proxying.

  ## Example

      # Redirect HTTP to local proxy
      builder |> tcp() |> dport(80) |> redirect_to(3128)
  """
  @spec redirect_to(Expr.t(), non_neg_integer()) :: Expr.t()
  def redirect_to(builder \\ Expr.expr(), port) when is_integer(port) and port >= 0 and port <= 65535 do
    expr = %{"redirect" => %{"port" => port}}
    Expr.add_expr(builder, expr)
  end
end
