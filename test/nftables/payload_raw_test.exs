defmodule NFTables.PayloadRawTest do
  use ExUnit.Case, async: false

  alias NFTables.{Builder, Expr}
  import NFTables.Match

  @moduletag :sudo_required

  setup do
    {:ok, pid} = NFTables.start_link()
    test_table = "raw_test_#{:rand.uniform(1_000_000)}"

    # Create test table and chain
    Builder.new(family: :inet)
    |> Builder.add(table: test_table)
    |> Builder.add(
      chain: "input",
      type: :filter,
      hook: :input,
      priority: 0,
      policy: :accept
    )
    |> Builder.execute(pid)

    on_exit(fn ->
      # Cleanup: delete test table
      if Process.alive?(pid) do
        Builder.new()
        |> Builder.delete(table: test_table, family: :inet)
        |> Builder.execute(pid)
      end
    end)

    {:ok, pid: pid, table: test_table}
  end

  describe "raw payload expression building" do
    test "builds payload_raw expression for network header" do
      expr = Expr.payload_raw(:nh, 96, 32)

      assert expr == %{
               payload: %{
                 base: "nh",
                 offset: 96,
                 len: 32
               }
             }
    end

    test "builds payload_raw expression for transport header" do
      expr = Expr.payload_raw(:th, 16, 16)

      assert expr == %{
               payload: %{
                 base: "th",
                 offset: 16,
                 len: 16
               }
             }
    end

    test "builds payload_raw expression for link layer" do
      expr = Expr.payload_raw(:ll, 0, 48)

      assert expr == %{
               payload: %{
                 base: "ll",
                 offset: 0,
                 len: 48
               }
             }
    end

    test "builds payload_raw expression for inner header" do
      expr = Expr.payload_raw(:ih, 32, 16)

      assert expr == %{
               payload: %{
                 base: "ih",
                 offset: 32,
                 len: 16
               }
             }
    end

    test "builds payload_raw_match expression" do
      expr = Expr.payload_raw_match(:th, 16, 16, 53)

      assert expr[:match][:left] == %{payload: %{base: "th", offset: 16, len: 16}}
      assert expr[:match][:right] == 53
      assert expr[:match][:op] == "=="
    end

    test "builds payload_raw_match with custom operator" do
      expr = Expr.payload_raw_match(:nh, 96, 32, <<192, 168, 1, 1>>, "!=")

      assert expr[:match][:op] == "!="
    end
  end

  describe "Match API raw payload" do
    test "builds raw payload match in rule" do
      expr =
        rule()
        |> udp()
        |> payload_raw(:th, 16, 16, 53)
        |> to_expr()

      # Should contain match with raw payload
      raw_match = Enum.find(expr, fn e ->
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
        rule()
        |> tcp()
        |> payload_raw_masked(:th, 104, 8, 0x02, 0x02)
        |> to_expr()

      # Should contain match with bitwise AND
      masked_match = Enum.find(expr, fn e ->
        Map.has_key?(e, :match) and
          is_map(e[:match][:left]) and
          Map.has_key?(e[:match][:left], :"&")
      end)

      assert masked_match != nil
      assert masked_match[:match][:right] == 0x02
    end
  end

  describe "all base types" do
    test "supports :ll (link layer) base" do
      expr =
        rule()
        |> payload_raw(:ll, 96, 32, <<0x00, 0x11, 0x22, 0x33>>)
        |> to_expr()

      raw_match = Enum.find(expr, fn e ->
        Map.has_key?(e, :match) and
          is_map(e[:match][:left][:payload]) and
          e[:match][:left][:payload][:base] == "ll"
      end)

      assert raw_match != nil
    end

    test "supports :nh (network header) base" do
      expr =
        rule()
        |> payload_raw(:nh, 96, 32, <<192, 168, 1, 1>>)
        |> to_expr()

      raw_match = Enum.find(expr, fn e ->
        Map.has_key?(e, :match) and
          is_map(e[:match][:left][:payload]) and
          e[:match][:left][:payload][:base] == "nh"
      end)

      assert raw_match != nil
    end

    test "supports :th (transport header) base" do
      expr =
        rule()
        |> tcp()
        |> payload_raw(:th, 16, 16, 80)
        |> to_expr()

      raw_match = Enum.find(expr, fn e ->
        Map.has_key?(e, :match) and
          is_map(e[:match][:left][:payload]) and
          e[:match][:left][:payload][:base] == "th"
      end)

      assert raw_match != nil
    end

    test "supports :ih (inner header) base" do
      expr =
        rule()
        |> payload_raw(:ih, 0, 32, "GET ")
        |> to_expr()

      raw_match = Enum.find(expr, fn e ->
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
        rule()
        |> udp()
        |> payload_raw(:th, 16, 16, 53)
        |> accept()
        |> to_expr()

      builder =
        Builder.new(family: :inet)
        |> Builder.add(rule: dns_rule, table: "filter", chain: "input")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{"nftables" => [command]} = decoded
      assert %{"add" => %{"rule" => rule}} = command

      # Find raw payload expression
      raw_expr = Enum.find(rule["expr"], fn e ->
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
        rule()
        |> tcp()
        |> payload_raw_masked(:th, 104, 8, 0x02, 0x02)
        |> accept()
        |> to_expr()

      builder =
        Builder.new(family: :inet)
        |> Builder.add(rule: syn_rule, table: "filter", chain: "input")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{"nftables" => [command]} = decoded
      assert %{"add" => %{"rule" => rule}} = command

      # Find bitwise AND expression
      bitwise_expr = Enum.find(rule["expr"], fn e ->
        Map.has_key?(e, "match") and
          is_map(e["match"]["left"]) and
          Map.has_key?(e["match"]["left"], "&")
      end)

      assert bitwise_expr != nil
      assert bitwise_expr["match"]["right"] == 0x02
    end
  end

  describe "real-world use cases" do
    test "DNS query matching by raw payload", %{pid: pid, table: table} do
      # Match DNS queries (port 53) using raw payload
      dns_rule =
        rule()
        |> udp()
        |> payload_raw(:th, 16, 16, 53)
        |> counter()
        |> accept()
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: dns_rule, table: table, chain: "input", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "HTTP GET detection using raw payload", %{pid: pid, table: table} do
      # Match HTTP GET requests by looking at first 4 bytes of payload
      http_get_rule =
        rule()
        |> tcp()
        |> dport(80)
        |> payload_raw(:ih, 0, 32, "GET ")
        |> log("HTTP GET detected: ")
        |> accept()
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: http_get_rule, table: table, chain: "input", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "TCP SYN flag detection using masked raw payload", %{pid: pid, table: table} do
      # Match TCP SYN packets by checking flags byte
      # TCP flags are at offset 13 bytes (104 bits) in TCP header
      # SYN flag is bit 1 (0x02)
      syn_rule =
        rule()
        |> tcp()
        |> payload_raw_masked(:th, 104, 8, 0x02, 0x02)
        |> counter()
        |> accept()
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: syn_rule, table: table, chain: "input", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "IPv4 source address matching by raw payload", %{pid: pid, table: table} do
      # Match specific source IP using raw payload
      # Source IP is at offset 12 bytes (96 bits) in IPv4 header
      ip_rule =
        rule()
        |> payload_raw(:nh, 96, 32, <<192, 168, 1, 1>>)
        |> drop()
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: ip_rule, table: table, chain: "input", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end

    test "IP DF (Don't Fragment) flag detection", %{pid: pid, table: table} do
      # Match packets with DF flag set
      # Flags/Fragment offset is at byte 6-7 (bits 48-63)
      # DF flag is 0x4000
      df_rule =
        rule()
        |> payload_raw_masked(:nh, 48, 16, 0x4000, 0x4000)
        |> counter()
        |> accept()
        |> to_expr()

      result =
        Builder.new()
        |> Builder.add(rule: df_rule, table: table, chain: "input", family: :inet)
        |> Builder.execute(pid)

      assert :ok == result
    end
  end

  describe "batch operations" do
    test "creates multiple raw payload rules atomically", %{pid: pid, table: table} do
      dns_rule =
        rule()
        |> udp()
        |> payload_raw(:th, 16, 16, 53)
        |> accept()
        |> to_expr()

      http_rule =
        rule()
        |> tcp()
        |> payload_raw(:th, 16, 16, 80)
        |> accept()
        |> to_expr()

      result =
        Builder.new(family: :inet)
        |> Builder.add(rule: dns_rule, table: table, chain: "input")
        |> Builder.add(rule: http_rule, table: table, chain: "input")
        |> Builder.execute(pid)

      assert :ok == result
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
