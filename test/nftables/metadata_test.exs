defmodule NFTables.MetadataTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.Metadata

  describe "mark/2" do
    test "adds mark match expression" do
      builder = expr() |> mark(100)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = mark(42)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "validates non-negative mark" do
      assert %NFTables.Expr{} = expr() |> mark(0)
      assert %NFTables.Expr{} = expr() |> mark(1000)
    end
  end

  describe "dscp/2" do
    test "adds dscp match expression" do
      builder = expr() |> dscp(46)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = dscp(0)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "validates DSCP range" do
      assert %NFTables.Expr{} = expr() |> dscp(0)
      assert %NFTables.Expr{} = expr() |> dscp(63)
    end
  end

  describe "fragmented/2" do
    test "adds fragmented match for true" do
      builder = expr() |> fragmented(true)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds fragmented match for false" do
      builder = expr() |> fragmented(false)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = fragmented(true)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "pkttype/2" do
    test "adds pkttype match with unicast" do
      builder = expr() |> pkttype(:unicast)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds pkttype match with broadcast" do
      builder = expr() |> pkttype(:broadcast)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds pkttype match with multicast" do
      builder = expr() |> pkttype(:multicast)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = pkttype(:unicast)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "priority/3" do
    test "adds priority match with eq operator" do
      builder = expr() |> priority(:eq, 5)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds priority match with lt operator" do
      builder = expr() |> priority(:lt, 10)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds priority match with gt operator" do
      builder = expr() |> priority(:gt, 3)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = priority(:eq, 0)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "chaining" do
    test "chains multiple metadata matchers" do
      builder =
        expr()
        |> mark(100)
        |> dscp(46)
        |> fragmented(false)
        |> pkttype(:unicast)

      assert length(builder.expr_list) == 4
    end
  end
end
