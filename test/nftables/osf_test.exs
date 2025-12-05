defmodule NFTables.OSFTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.OSF

  describe "osf_name/2" do
    test "adds osf_name match expression without options" do
      builder = expr() |> osf_name("Linux")

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = osf_name("Windows")

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "osf_name/3" do
    test "adds osf_name match expression with loose ttl" do
      builder = expr() |> osf_name("Linux", ttl: :loose)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds osf_name match expression with skip ttl" do
      builder = expr() |> osf_name("Linux", ttl: :skip)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds osf_name match expression with strict ttl" do
      builder = expr() |> osf_name("Linux", ttl: :strict)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "osf_version/2" do
    test "adds osf_version match expression without options" do
      builder = expr() |> osf_version("2.6.x")

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = osf_version("10.0")

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "osf_version/3" do
    test "adds osf_version match expression with loose ttl" do
      builder = expr() |> osf_version("2.6.x", ttl: :loose)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds osf_version match expression with skip ttl" do
      builder = expr() |> osf_version("2.6.x", ttl: :skip)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds osf_version match expression with strict ttl" do
      builder = expr() |> osf_version("2.6.x", ttl: :strict)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end
  end

  describe "chaining" do
    test "chains osf_name and osf_version" do
      builder =
        expr()
        |> osf_name("Linux")
        |> osf_version("2.6.x")

      assert length(builder.expr_list) == 2
    end

    test "chains with other expressions" do
      import NFTables.Expr.Verdicts

      builder =
        expr()
        |> osf_name("Windows")
        |> drop()

      assert length(builder.expr_list) == 2
    end
  end
end
