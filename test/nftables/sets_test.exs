defmodule NFTables.SetsTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.{Sets, TCP}

  describe "set/3 with :saddr" do
    test "adds set match expression for source address" do
      builder = expr() |> set("blocklist", :saddr)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = set("allowed_ips", :saddr)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "set/3 with :daddr" do
    test "adds set match expression for destination address" do
      builder = expr() |> set("target_ips", :daddr)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = set("servers", :daddr)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "set/3 with :sport" do
    test "adds set match expression for source port with protocol context" do
      builder = expr() |> tcp() |> set("client_ports", :sport)

      assert %NFTables.Expr{} = builder
      # tcp() + set()
      assert length(builder.expr_list) == 2
    end

    test "raises without protocol context" do
      assert_raise ArgumentError, ~r/requires protocol context/, fn ->
        expr() |> set("ports", :sport)
      end
    end
  end

  describe "set/3 with :dport" do
    test "adds set match expression for destination port with protocol context" do
      builder = expr() |> tcp() |> set("service_ports", :dport)

      assert %NFTables.Expr{} = builder
      # tcp() + set()
      assert length(builder.expr_list) == 2
    end

    test "raises without protocol context" do
      assert_raise ArgumentError, ~r/requires protocol context/, fn ->
        expr() |> set("ports", :dport)
      end
    end
  end

  describe "chaining" do
    test "chains set match with other expressions" do
      import NFTables.Expr.Verdict

      builder =
        expr()
        |> set("blocklist", :saddr)
        |> drop()

      assert length(builder.expr_list) == 2
    end

    test "chains multiple set matches" do
      builder =
        expr()
        |> set("allowed_sources", :saddr)
        |> tcp()
        |> set("allowed_ports", :dport)

      # set() + tcp() + set()
      assert length(builder.expr_list) == 3
    end
  end
end
