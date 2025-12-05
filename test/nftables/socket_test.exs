defmodule NFTables.SocketTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.Socket

  describe "skuid/2" do
    test "adds skuid match expression" do
      builder = expr() |> skuid(1000)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = skuid(0)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "validates non-negative UID" do
      assert %NFTables.Expr{} = expr() |> skuid(0)
      assert %NFTables.Expr{} = expr() |> skuid(65535)
    end
  end

  describe "skgid/2" do
    test "adds skgid match expression" do
      builder = expr() |> skgid(1000)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = skgid(0)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "validates non-negative GID" do
      assert %NFTables.Expr{} = expr() |> skgid(0)
      assert %NFTables.Expr{} = expr() |> skgid(65535)
    end
  end

  describe "cgroup/2" do
    test "adds cgroup match expression" do
      builder = expr() |> cgroup(100)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = cgroup(1)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "validates non-negative cgroup ID" do
      assert %NFTables.Expr{} = expr() |> cgroup(0)
      assert %NFTables.Expr{} = expr() |> cgroup(10000)
    end
  end

  describe "socket_transparent/1" do
    test "adds socket transparent match expression" do
      builder = expr() |> socket_transparent()

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = socket_transparent()

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "chaining" do
    test "chains multiple socket matchers" do
      builder =
        expr()
        |> skuid(1000)
        |> skgid(1000)
        |> cgroup(100)

      assert length(builder.expr_list) == 3
    end

    test "chains socket_transparent with other matchers" do
      builder =
        expr()
        |> socket_transparent()
        |> skuid(0)

      assert length(builder.expr_list) == 2
    end
  end
end
