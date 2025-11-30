defmodule NFTables.PayloadRawIntegrationTest do
  use ExUnit.Case, async: false

  alias NFTables.Builder
  import NFTables.Match

  @moduletag :integration
  @moduletag :slow

  setup do
    {:ok, pid} = NFTables.start_link()
    test_table = "raw_test_#{:rand.uniform(1_000_000)}"

    # Create test table
    Builder.new()
    |> Builder.add(table: test_table)
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

      # Create a simple chain without hooks to avoid Builder bug
      result =
        Builder.new()
        |> Builder.add(table: table)
        |> Builder.add(chain: "test_chain")
        |> Builder.add(rule: dns_rule)
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
        |> Builder.add(table: table)
        |> Builder.add(chain: "test_chain")
        |> Builder.add(rule: http_get_rule)
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
        |> Builder.add(table: table)
        |> Builder.add(chain: "test_chain")
        |> Builder.add(rule: syn_rule)
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
        |> Builder.add(table: table)
        |> Builder.add(chain: "test_chain")
        |> Builder.add(rule: ip_rule)
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
        |> Builder.add(table: table)
        |> Builder.add(chain: "test_chain")
        |> Builder.add(rule: df_rule)
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
        Builder.new()
        |> Builder.add(table: table)
        |> Builder.add(chain: "test_chain")
        |> Builder.add(rule: dns_rule)
        |> Builder.add(rule: http_rule)
        |> Builder.execute(pid)

      assert :ok == result
    end
  end
end
