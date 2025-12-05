defmodule NFTables.UDPTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.UDP

  describe "udp/1" do
    test "adds udp protocol match expression" do
      builder = expr() |> udp()

      assert %NFTables.Expr{} = builder
      assert builder.protocol == :udp
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = udp()

      assert %NFTables.Expr{} = builder
      assert builder.protocol == :udp
      assert length(builder.expr_list) == 1
    end

    test "sets protocol context for port matching" do
      import NFTables.Expr.Port

      builder = expr() |> udp() |> dport(53)

      assert builder.protocol == :udp
      assert length(builder.expr_list) == 2
    end

    test "chains with other expressions" do
      import NFTables.Expr.{Port, Verdict}

      builder = expr() |> udp() |> dport(53) |> accept()

      assert length(builder.expr_list) == 3
    end

    test "works with port ranges" do
      import NFTables.Expr.{Port, Verdict}

      builder = udp() |> dport(10000..20000) |> accept()

      assert %NFTables.Expr{} = builder
      assert builder.protocol == :udp
      assert length(builder.expr_list) == 3
    end

    test "can chain multiple UDP rules" do
      import NFTables.Expr.{Port, Verdict}

      rule1 = udp() |> dport(53) |> accept()
      rule2 = udp() |> sport(1024..65535) |> accept()

      assert rule1.protocol == :udp
      assert rule2.protocol == :udp
      assert length(rule1.expr_list) == 3
      assert length(rule2.expr_list) == 3
    end
  end
end
