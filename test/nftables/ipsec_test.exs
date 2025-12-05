defmodule NFTables.IPsecTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.IPsec

  describe "ah_spi/2" do
    test "adds ah_spi match expression with specific SPI" do
      builder = expr() |> ah_spi(12345)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds ah_spi match expression with :any" do
      builder = expr() |> ah_spi(:any)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = ah_spi(100)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "validates non-negative SPI" do
      assert %NFTables.Expr{} = expr() |> ah_spi(0)
      assert %NFTables.Expr{} = expr() |> ah_spi(999999)
    end
  end

  describe "esp_spi/2" do
    test "adds esp_spi match expression with specific SPI" do
      builder = expr() |> esp_spi(54321)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "adds esp_spi match expression with :any" do
      builder = expr() |> esp_spi(:any)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "can start a new expression" do
      builder = esp_spi(200)

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "validates non-negative SPI" do
      assert %NFTables.Expr{} = expr() |> esp_spi(0)
      assert %NFTables.Expr{} = esp_spi(999999)
    end
  end

  describe "chaining" do
    test "chains AH and ESP matchers" do
      builder =
        expr()
        |> ah_spi(12345)
        |> esp_spi(54321)

      assert length(builder.expr_list) == 2
    end
  end
end
