defmodule NFTables.ProtocolsTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.Protocols

  describe "sctp/1" do
    test "adds sctp protocol match expression" do
      builder = expr() |> sctp()

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
      assert builder.protocol == :sctp
    end

    test "can start a new expression" do
      builder = sctp()

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
      assert builder.protocol == :sctp
    end

    test "works with port matching" do
      import NFTables.Expr.Port

      builder = expr() |> sctp() |> dport(9899)

      # sctp() + dport()
      assert length(builder.expr_list) == 2
    end
  end

  describe "dccp/1" do
    test "adds dccp protocol match expression" do
      builder = expr() |> dccp()

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
      assert builder.protocol == :dccp
    end

    test "can start a new expression" do
      builder = dccp()

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
      assert builder.protocol == :dccp
    end

    test "works with port matching" do
      import NFTables.Expr.Port

      builder = expr() |> dccp() |> dport(6000)

      # dccp() + dport()
      assert length(builder.expr_list) == 2
    end
  end

  describe "gre/1" do
    test "adds gre protocol match expression" do
      builder = expr() |> gre()

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
      assert builder.protocol == :gre
    end

    test "can start a new expression" do
      builder = gre()

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
      assert builder.protocol == :gre
    end
  end

  describe "gre_version/2" do
    test "adds gre_version match expression" do
      builder = expr() |> gre() |> gre_version(0)

      assert %NFTables.Expr{} = builder
      # gre() + gre_version()
      assert length(builder.expr_list) == 2
    end

    test "auto-adds gre() if not present" do
      builder = expr() |> gre_version(1)

      assert %NFTables.Expr{} = builder
      # auto gre() + gre_version()
      assert length(builder.expr_list) == 2
      assert builder.protocol == :gre
    end

    test "can start a new expression" do
      builder = gre_version(0)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 2
      assert builder.protocol == :gre
    end
  end

  describe "gre_key/2" do
    test "adds gre_key match expression" do
      builder = expr() |> gre() |> gre_key(12345)

      assert %NFTables.Expr{} = builder
      # gre() + gre_key()
      assert length(builder.expr_list) == 2
    end

    test "auto-adds gre() if not present" do
      builder = expr() |> gre_key(54321)

      assert %NFTables.Expr{} = builder
      # auto gre() + gre_key()
      assert length(builder.expr_list) == 2
      assert builder.protocol == :gre
    end

    test "can start a new expression" do
      builder = gre_key(100)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 2
      assert builder.protocol == :gre
    end

    test "validates non-negative key" do
      assert %NFTables.Expr{} = expr() |> gre_key(0)
      assert %NFTables.Expr{} = gre_key(999_999)
    end
  end

  describe "gre_flags/2" do
    test "adds gre_flags match expression" do
      builder = expr() |> gre() |> gre_flags(0x2000)

      assert %NFTables.Expr{} = builder
      # gre() + gre_flags()
      assert length(builder.expr_list) == 2
    end

    test "auto-adds gre() if not present" do
      builder = expr() |> gre_flags(0x8000)

      assert %NFTables.Expr{} = builder
      # auto gre() + gre_flags()
      assert length(builder.expr_list) == 2
      assert builder.protocol == :gre
    end

    test "can start a new expression" do
      builder = gre_flags(0x4000)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 2
      assert builder.protocol == :gre
    end

    test "validates non-negative flags" do
      assert %NFTables.Expr{} = expr() |> gre_flags(0)
      assert %NFTables.Expr{} = gre_flags(0xFFFF)
    end
  end

  describe "chaining" do
    test "chains multiple GRE matchers" do
      builder =
        expr()
        |> gre()
        |> gre_version(0)
        |> gre_key(12345)
        |> gre_flags(0x2000)

      # gre() + gre_version() + gre_key() + gre_flags()
      assert length(builder.expr_list) == 4
    end

    test "chains with other expressions" do
      import NFTables.Expr.Verdict

      builder =
        expr()
        |> sctp()
        |> accept()

      assert length(builder.expr_list) == 2
    end
  end
end
