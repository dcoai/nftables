defmodule NFTables.ICMPTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.ICMP

  describe "icmp_type/2" do
    test "adds icmp_type expression with numeric type" do
      builder = expr() |> icmp_type(8)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds icmp_type expression with atom type" do
      builder = expr() |> icmp_type(:echo_request)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = icmp_type(:echo_reply)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "chains with other expressions" do
      builder = expr() |> icmp_type(8) |> icmp_code(0)

      assert length(builder.expr_list) == 2
    end
  end

  describe "icmp_code/2" do
    test "adds icmp_code expression" do
      builder = expr() |> icmp_code(0)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = icmp_code(0)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "icmpv6_type/2" do
    test "adds icmpv6_type expression with numeric type" do
      builder = expr() |> icmpv6_type(128)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds icmpv6_type expression with atom type" do
      builder = expr() |> icmpv6_type(:echo_request)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = icmpv6_type(:neighbor_solicitation)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "icmpv6_code/2" do
    test "adds icmpv6_code expression" do
      builder = expr() |> icmpv6_code(0)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = icmpv6_code(0)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "chaining" do
    test "chains ICMP type and code" do
      builder = expr() |> icmp_type(:echo_request) |> icmp_code(0)

      assert length(builder.expr_list) == 2
    end

    test "chains ICMPv6 type and code" do
      builder = expr() |> icmpv6_type(:echo_request) |> icmpv6_code(0)

      assert length(builder.expr_list) == 2
    end
  end
end
