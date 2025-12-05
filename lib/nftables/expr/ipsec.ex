defmodule NFTables.Expr.IPsec do
  @moduledoc """
  IPsec (IP Security) matching functions for firewall rules.

  This module provides functions to match IPsec traffic by matching the Security
  Parameter Index (SPI) values in AH (Authentication Header) and ESP (Encapsulating
  Security Payload) headers.

  IPsec is used to create VPNs and secure IP communications. These functions allow
  you to create firewall rules that specifically target IPsec traffic.

  ## Common Use Cases

  - Allow specific IPsec tunnels
  - Log IPsec traffic
  - Apply rate limiting to IPsec
  - Route IPsec traffic differently

  ## Import

      import NFTables.Expr.IPsec

  For more information, see the [RFC 4301 IPsec Architecture](https://tools.ietf.org/html/rfc4301).
  """

  alias NFTables.Expr

  @doc """
  Match IPsec AH (Authentication Header) SPI.

  The Security Parameter Index (SPI) is a 32-bit value that, together with the
  destination IP and security protocol, uniquely identifies a Security Association.

  ## Parameters

  - `spi` - Either a specific SPI value (integer) or `:any` to match any AH traffic

  ## Example

      # Match specific AH SPI
      ah_spi(12345) |> accept()

      # Log all IPsec AH traffic
      ah_spi(:any) |> log("IPSEC-AH")

      # Allow specific tunnel
      ah_spi(12345)
      |> source_ip("10.0.0.1")
      |> accept()

      # Rate limit AH traffic
      ah_spi(:any) |> limit(100, :second) |> accept()
  """
  @spec ah_spi(Expr.t(), non_neg_integer() | :any) :: Expr.t()
  def ah_spi(builder \\ Expr.expr(), spi)

  def ah_spi(builder, :any) do
    # Match any AH SPI (just check if AH header exists)
    expr = %{
      "match" => %{
        "left" => %{"payload" => %{"protocol" => "ah", "field" => "spi"}},
        "right" => 0,
        "op" => ">="
      }
    }

    Expr.add_expr(builder, expr)
  end

  def ah_spi(builder, spi) when is_integer(spi) and spi >= 0 do
    expr = Expr.Structs.payload_match("ah", "spi", spi)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match IPsec ESP (Encapsulating Security Payload) SPI.

  ESP provides confidentiality, authentication, and integrity for IP packets.
  The SPI field identifies the security association.

  ## Parameters

  - `spi` - Either a specific SPI value (integer) or `:any` to match any ESP traffic

  ## Example

      # Match specific ESP SPI
      esp_spi(54321) |> accept()

      # Log all IPsec ESP traffic
      esp_spi(:any) |> log("IPSEC-ESP")

      # Allow specific VPN endpoint
      esp_spi(54321)
      |> source_ip("192.168.100.1")
      |> accept()

      # Mark ESP traffic for routing
      esp_spi(:any) |> set_mark(100) |> accept()
  """
  @spec esp_spi(Expr.t(), non_neg_integer() | :any) :: Expr.t()
  def esp_spi(builder \\ Expr.expr(), spi)

  def esp_spi(builder, :any) do
    # Match any ESP SPI (just check if ESP header exists)
    expr = %{
      "match" => %{
        "left" => %{"payload" => %{"protocol" => "esp", "field" => "spi"}},
        "right" => 0,
        "op" => ">="
      }
    }

    Expr.add_expr(builder, expr)
  end

  def esp_spi(builder, spi) when is_integer(spi) and spi >= 0 do
    expr = Expr.Structs.payload_match("esp", "spi", spi)
    Expr.add_expr(builder, expr)
  end
end
