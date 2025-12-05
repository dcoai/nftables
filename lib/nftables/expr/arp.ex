defmodule NFTables.Expr.ARP do
  @moduledoc """
  ARP (Address Resolution Protocol) matching functions for firewall rules.

  ARP is a Layer 2 protocol used to resolve IP addresses to MAC addresses on local
  networks. This module provides functions to match ARP operations (requests and replies).

  ## Common Use Cases

  - Log ARP activity
  - Prevent ARP spoofing
  - Rate limit ARP requests
  - Monitor network discovery

  ## Import

      import NFTables.Expr.ARP

  For more information, see the [nftables ARP wiki](https://wiki.nftables.org/wiki-nftables/index.php/Matching_ARP_headers).
  """

  alias NFTables.Expr

  @doc """
  Match ARP operation.

  Matches ARP packets based on their operation type (request or reply).

  ## Operations

  - `:request` (1) - ARP request ("who has this IP?")
  - `:reply` (2) - ARP reply ("I have this IP")
  - Or numeric value (1-65535)

  ## Example

      # Log ARP requests
      arp_operation(:request) |> log("ARP-REQ")

      # Accept ARP replies
      arp_operation(:reply) |> accept()

      # Rate limit ARP requests (anti-flood)
      arp_operation(:request)
      |> limit(10, :second)
      |> accept()

      # Security: Only accept ARP from trusted hosts
      arp_operation(:reply)
      |> source_mac("aa:bb:cc:dd:ee:ff")
      |> accept()
  """
  @spec arp_operation(Expr.t(), atom() | non_neg_integer()) :: Expr.t()
  def arp_operation(builder \\ Expr.expr(), operation) do
    op_val =
      case operation do
        :request -> 1
        :reply -> 2
        num when is_integer(num) -> num
        _ -> raise ArgumentError, "Invalid ARP operation: #{inspect(operation)}"
      end

    expr = Expr.Structs.payload_match("arp", "operation", op_val)
    Expr.add_expr(builder, expr)
  end
end
