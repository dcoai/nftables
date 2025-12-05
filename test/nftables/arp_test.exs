defmodule NFTables.ARPTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.ARP

  describe "arp_operation/2" do
    test "adds arp_operation match expression with request" do
      builder = expr() |> arp_operation(:request)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds arp_operation match expression with reply" do
      builder = expr() |> arp_operation(:reply)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = arp_operation(:request)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "chaining" do
    test "chains with other expressions" do
      import NFTables.Expr.Layer2

      builder =
        expr()
        |> arp_operation(:request)
        |> source_mac("aa:bb:cc:dd:ee:ff")

      assert length(builder.expr_list) == 2
    end
  end
end
