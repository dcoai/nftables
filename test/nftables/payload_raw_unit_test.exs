defmodule NFTables.PayloadRawUnitTest do
  use ExUnit.Case, async: true

  alias NFTables.Builder
  alias NFTables.Expr.Structs
  import NFTables.Expr
  import NFTables.Expr.{TCP, Payload, Verdicts}

  describe "raw payload expression building" do
    test "builds payload_raw expression for network header" do
      expr = Structs.payload_raw(:nh, 96, 32)

      assert expr == %{
               payload: %{
                 base: "nh",
                 offset: 96,
                 len: 32
               }
             }
    end

    test "builds payload_raw expression for transport header" do
      expr = Structs.payload_raw(:th, 16, 16)

      assert expr == %{
               payload: %{
                 base: "th",
                 offset: 16,
                 len: 16
               }
             }
    end

    test "builds payload_raw expression for link layer" do
      expr = Structs.payload_raw(:ll, 0, 48)

      assert expr == %{
               payload: %{
                 base: "ll",
                 offset: 0,
                 len: 48
               }
             }
    end

    test "builds payload_raw expression for inner header" do
      expr = Structs.payload_raw(:ih, 32, 16)

      assert expr == %{
               payload: %{
                 base: "ih",
                 offset: 32,
                 len: 16
               }
             }
    end

    test "builds payload_raw_match expression" do
      expr = Structs.payload_raw_match(:th, 16, 16, 53)

      assert expr[:match][:left] == %{payload: %{base: "th", offset: 16, len: 16}}
      assert expr[:match][:right] == 53
      assert expr[:match][:op] == "=="
    end

    test "builds payload_raw_match with custom operator" do
      expr = Structs.payload_raw_match(:nh, 96, 32, <<192, 168, 1, 1>>, "!=")

      assert expr[:match][:op] == "!="
    end
  end

  describe "Match API raw payload" do
    test "builds raw payload match in rule" do
      expr =
        expr()
        |> protocol(:udp)
        |> payload_raw(:th, 16, 16, 53)
        |> to_list()

      # Should contain match with raw payload
      raw_match =
        Enum.find(expr, fn e ->
          Map.has_key?(e, :match) and
            is_map(e[:match][:left]) and
            Map.has_key?(e[:match][:left], :payload) and
            Map.has_key?(e[:match][:left][:payload], :base)
        end)

      assert raw_match != nil
      assert raw_match[:match][:left][:payload][:base] == "th"
      assert raw_match[:match][:left][:payload][:offset] == 16
      assert raw_match[:match][:left][:payload][:len] == 16
      assert raw_match[:match][:right] == 53
    end

    test "builds masked raw payload match in rule" do
      expr =
        expr()
        |> protocol(:tcp)
        |> payload_raw_masked(:th, 104, 8, 0x02, 0x02)
        |> to_list()

      # Should contain match with bitwise AND
      masked_match =
        Enum.find(expr, fn e ->
          Map.has_key?(e, :match) and
            is_map(e[:match][:left]) and
            Map.has_key?(e[:match][:left], :&)
        end)

      assert masked_match != nil
      assert masked_match[:match][:right] == 0x02
    end
  end

  describe "all base types" do
    test "supports :ll (link layer) base" do
      expr =
        expr()
        |> payload_raw(:ll, 96, 32, <<0x00, 0x11, 0x22, 0x33>>)
        |> to_list()

      raw_match =
        Enum.find(expr, fn e ->
          Map.has_key?(e, :match) and
            is_map(e[:match][:left][:payload]) and
            e[:match][:left][:payload][:base] == "ll"
        end)

      assert raw_match != nil
    end

    test "supports :nh (network header) base" do
      expr =
        expr()
        |> payload_raw(:nh, 96, 32, <<192, 168, 1, 1>>)
        |> to_list()

      raw_match =
        Enum.find(expr, fn e ->
          Map.has_key?(e, :match) and
            is_map(e[:match][:left][:payload]) and
            e[:match][:left][:payload][:base] == "nh"
        end)

      assert raw_match != nil
    end

    test "supports :th (transport header) base" do
      expr =
        expr()
        |> protocol(:tcp)
        |> payload_raw(:th, 16, 16, 80)
        |> to_list()

      raw_match =
        Enum.find(expr, fn e ->
          Map.has_key?(e, :match) and
            is_map(e[:match][:left][:payload]) and
            e[:match][:left][:payload][:base] == "th"
        end)

      assert raw_match != nil
    end

    test "supports :ih (inner header) base" do
      expr =
        expr()
        |> payload_raw(:ih, 0, 32, "GET ")
        |> to_list()

      raw_match =
        Enum.find(expr, fn e ->
          Map.has_key?(e, :match) and
            is_map(e[:match][:left][:payload]) and
            e[:match][:left][:payload][:base] == "ih"
        end)

      assert raw_match != nil
    end
  end

  describe "JSON generation" do
    test "generates correct JSON for raw payload rule" do
      dns_rule =
        expr()
        |> protocol(:udp)
        |> payload_raw(:th, 16, 16, 53)
        |> accept()

      builder =
        NFTables.add(rule: dns_rule, table: "filter", chain: "input")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{"nftables" => [command]} = decoded
      assert %{"add" => %{"rule" => rule}} = command

      # Find raw payload expression
      raw_expr =
        Enum.find(rule["expr"], fn e ->
          Map.has_key?(e, "match") and
            is_map(e["match"]["left"]) and
            Map.has_key?(e["match"]["left"], "payload") and
            Map.has_key?(e["match"]["left"]["payload"], "base")
        end)

      assert raw_expr != nil
      assert raw_expr["match"]["left"]["payload"]["base"] == "th"
      assert raw_expr["match"]["left"]["payload"]["offset"] == 16
      assert raw_expr["match"]["left"]["payload"]["len"] == 16
      assert raw_expr["match"]["right"] == 53
    end

    test "generates correct JSON for masked raw payload" do
      syn_rule =
        expr()
        |> protocol(:tcp)
        |> payload_raw_masked(:th, 104, 8, 0x02, 0x02)
        |> accept()

      builder =
        NFTables.add(rule: syn_rule, table: "filter", chain: "input")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{"nftables" => [command]} = decoded
      assert %{"add" => %{"rule" => rule}} = command

      # Find bitwise AND expression
      bitwise_expr =
        Enum.find(rule["expr"], fn e ->
          Map.has_key?(e, "match") and
            is_map(e["match"]["left"]) and
            Map.has_key?(e["match"]["left"], "&")
        end)

      assert bitwise_expr != nil
      assert bitwise_expr["match"]["right"] == 0x02
    end
  end

  describe "payload_raw_expr helper" do
    test "returns raw payload expression for use in other contexts" do
      expr = payload_raw_expr(:nh, 96, 32)

      assert expr == %{
               payload: %{
                 base: "nh",
                 offset: 96,
                 len: 32
               }
             }
    end
  end
end
