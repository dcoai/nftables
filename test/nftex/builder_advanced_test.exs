defmodule NFTablesEx.BuilderAdvancedTest do
  use ExUnit.Case, async: true

  alias NFTablesEx.Builder

  describe "Maps - add_map/3" do
    test "adds a map with key-value type" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_map("port_map", type: {:inet_service, :verdict})

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{
               "nftables" => [
                 %{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}},
                 %{
                   "add" => %{
                     "map" => %{
                       "family" => "inet",
                       "table" => "filter",
                       "name" => "port_map",
                       "type" => "inet_service",
                       "map" => "verdict"
                     }
                   }
                 }
               ]
             } = decoded
    end

    test "adds map with different types" do
      builder =
        Builder.new(family: :ip)
        |> Builder.add_table("nat")
        |> Builder.add_map("addr_map", type: {:ipv4_addr, :ipv4_addr})

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      map_cmd = Enum.at(decoded["nftables"], 1)
      assert map_cmd["add"]["map"]["type"] == "ipv4_addr"
      assert map_cmd["add"]["map"]["map"] == "ipv4_addr"
    end

    test "raises when table not specified" do
      assert_raise ArgumentError, "table must be specified", fn ->
        Builder.new()
        |> Builder.add_map("test_map", type: {:ipv4_addr, :verdict})
      end
    end

    test "raises when type not provided" do
      assert_raise KeyError, fn ->
        Builder.new()
        |> Builder.set_table("filter")
        |> Builder.add_map("test_map", [])
      end
    end
  end

  describe "Maps - delete_map/3" do
    test "deletes a map" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.delete_map("port_map")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{
               "nftables" => [
                 %{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}},
                 %{
                   "delete" => %{
                     "map" => %{
                       "family" => "inet",
                       "table" => "filter",
                       "name" => "port_map"
                     }
                   }
                 }
               ]
             } = decoded
    end
  end

  describe "Maps - add_map_elements/4" do
    test "adds elements to a map" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_map_elements("port_map", [
          {80, "accept"},
          {443, "accept"},
          {8080, "drop"}
        ])

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      element_cmd = Enum.at(decoded["nftables"], 1)

      assert element_cmd["add"]["element"]["name"] == "port_map"
      assert element_cmd["add"]["element"]["elem"] == [[80, "accept"], [443, "accept"], [8080, "drop"]]
    end

    test "handles single element" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_map_elements("test_map", [{22, "accept"}])

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      element_cmd = Enum.at(decoded["nftables"], 1)
      assert element_cmd["add"]["element"]["elem"] == [[22, "accept"]]
    end
  end

  describe "Maps - delete_map_elements/4" do
    test "deletes elements from a map" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.delete_map_elements("port_map", [80, 443])

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      element_cmd = Enum.at(decoded["nftables"], 1)

      assert element_cmd["delete"]["element"]["name"] == "port_map"
      assert element_cmd["delete"]["element"]["elem"] == [80, 443]
    end
  end

  describe "Named Counters - add_counter/3" do
    test "adds a counter with default values" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_counter("http_counter")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{
               "nftables" => [
                 %{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}},
                 %{
                   "add" => %{
                     "counter" => %{
                       "family" => "inet",
                       "table" => "filter",
                       "name" => "http_counter",
                       "packets" => 0,
                       "bytes" => 0
                     }
                   }
                 }
               ]
             } = decoded
    end

    test "adds counter with initial values" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_counter("test_counter", packets: 100, bytes: 5000)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      counter_cmd = Enum.at(decoded["nftables"], 1)
      assert counter_cmd["add"]["counter"]["packets"] == 100
      assert counter_cmd["add"]["counter"]["bytes"] == 5000
    end

    test "raises when table not specified" do
      assert_raise ArgumentError, "table must be specified", fn ->
        Builder.new()
        |> Builder.add_counter("test_counter")
      end
    end
  end

  describe "Named Counters - delete_counter/3" do
    test "deletes a counter" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.delete_counter("http_counter")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{
               "nftables" => [
                 %{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}},
                 %{
                   "delete" => %{
                     "counter" => %{
                       "family" => "inet",
                       "table" => "filter",
                       "name" => "http_counter"
                     }
                   }
                 }
               ]
             } = decoded
    end
  end

  describe "Quotas - add_quota/4" do
    test "adds a quota with default values" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_quota("monthly_limit", 1_000_000_000)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{
               "nftables" => [
                 %{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}},
                 %{
                   "add" => %{
                     "quota" => %{
                       "family" => "inet",
                       "table" => "filter",
                       "name" => "monthly_limit",
                       "bytes" => 1_000_000_000,
                       "used" => 0,
                       "over" => false
                     }
                   }
                 }
               ]
             } = decoded
    end

    test "adds quota with custom values" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_quota("test_quota", 500_000, used: 100_000, over: true)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      quota_cmd = Enum.at(decoded["nftables"], 1)
      assert quota_cmd["add"]["quota"]["bytes"] == 500_000
      assert quota_cmd["add"]["quota"]["used"] == 100_000
      assert quota_cmd["add"]["quota"]["over"] == true
    end

    test "raises when table not specified" do
      assert_raise ArgumentError, "table must be specified", fn ->
        Builder.new()
        |> Builder.add_quota("test_quota", 1000)
      end
    end

    test "validates non-negative bytes" do
      # This should work
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_quota("test", 0)

      assert %Builder{} = builder
    end
  end

  describe "Quotas - delete_quota/3" do
    test "deletes a quota" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.delete_quota("monthly_limit")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{
               "nftables" => [
                 %{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}},
                 %{
                   "delete" => %{
                     "quota" => %{
                       "family" => "inet",
                       "table" => "filter",
                       "name" => "monthly_limit"
                     }
                   }
                 }
               ]
             } = decoded
    end
  end

  describe "Named Limits - add_limit/5" do
    test "adds a limit with default burst" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_limit("ssh_limit", 10, :minute)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{
               "nftables" => [
                 %{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}},
                 %{
                   "add" => %{
                     "limit" => %{
                       "family" => "inet",
                       "table" => "filter",
                       "name" => "ssh_limit",
                       "rate" => 10,
                       "per" => "minute",
                       "burst" => 0
                     }
                   }
                 }
               ]
             } = decoded
    end

    test "adds limit with burst value" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_limit("http_limit", 100, :second, burst: 50)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      limit_cmd = Enum.at(decoded["nftables"], 1)
      assert limit_cmd["add"]["limit"]["rate"] == 100
      assert limit_cmd["add"]["limit"]["per"] == "second"
      assert limit_cmd["add"]["limit"]["burst"] == 50
    end

    test "supports different time units" do
      units = [:second, :minute, :hour, :day]

      for unit <- units do
        builder =
          Builder.new()
          |> Builder.add_table("filter")
          |> Builder.add_limit("test_limit", 5, unit)

        json = Builder.to_json(builder)
        decoded = Jason.decode!(json)

        limit_cmd = Enum.at(decoded["nftables"], 1)
        assert limit_cmd["add"]["limit"]["per"] == to_string(unit)
      end
    end

    test "raises when table not specified" do
      assert_raise ArgumentError, "table must be specified", fn ->
        Builder.new()
        |> Builder.add_limit("test_limit", 10, :minute)
      end
    end
  end

  describe "Named Limits - delete_limit/3" do
    test "deletes a limit" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.delete_limit("ssh_limit")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert %{
               "nftables" => [
                 %{"add" => %{"table" => %{"family" => "inet", "name" => "filter"}}},
                 %{
                   "delete" => %{
                     "limit" => %{
                       "family" => "inet",
                       "table" => "filter",
                       "name" => "ssh_limit"
                     }
                   }
                 }
               ]
             } = decoded
    end
  end

  describe "Advanced features integration" do
    test "combines map creation with element addition" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_map("port_verdict", type: {:inet_service, :verdict})
        |> Builder.add_map_elements("port_verdict", [
          {22, "accept"},
          {80, "accept"},
          {443, "accept"}
        ])

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert length(decoded["nftables"]) == 3
      assert Enum.at(decoded["nftables"], 1)["add"]["map"] != nil
      assert Enum.at(decoded["nftables"], 2)["add"]["element"] != nil
    end

    test "creates multiple named objects in sequence" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_counter("web_counter")
        |> Builder.add_quota("daily_quota", 10_000_000_000)
        |> Builder.add_limit("rate_limit", 100, :second, burst: 50)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert length(decoded["nftables"]) == 4
      assert Enum.at(decoded["nftables"], 1)["add"]["counter"] != nil
      assert Enum.at(decoded["nftables"], 2)["add"]["quota"] != nil
      assert Enum.at(decoded["nftables"], 3)["add"]["limit"] != nil
    end

    test "mixes advanced features with basic operations" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_chain("INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
        |> Builder.add_counter("input_counter")
        |> Builder.add_set("blocklist", type: :ipv4_addr)
        |> Builder.add_limit("ssh_limit", 10, :minute, burst: 5)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      assert length(decoded["nftables"]) == 5
      # Verify each type of operation exists
      commands = decoded["nftables"]
      assert Enum.any?(commands, fn cmd -> Map.has_key?(cmd, "add") and Map.has_key?(cmd["add"], "table") end)
      assert Enum.any?(commands, fn cmd -> Map.has_key?(cmd, "add") and Map.has_key?(cmd["add"], "chain") end)
      assert Enum.any?(commands, fn cmd -> Map.has_key?(cmd, "add") and Map.has_key?(cmd["add"], "counter") end)
      assert Enum.any?(commands, fn cmd -> Map.has_key?(cmd, "add") and Map.has_key?(cmd["add"], "set") end)
      assert Enum.any?(commands, fn cmd -> Map.has_key?(cmd, "add") and Map.has_key?(cmd["add"], "limit") end)
    end
  end

  describe "Family support" do
    test "uses builder's family for map operations" do
      builder =
        Builder.new(family: :ip6)
        |> Builder.add_table("filter")
        |> Builder.add_map("ipv6_map", type: {:ipv6_addr, :verdict})

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      map_cmd = Enum.at(decoded["nftables"], 1)
      assert map_cmd["add"]["map"]["family"] == "ip6"
    end

    test "allows family override for counter" do
      builder =
        Builder.new(family: :inet)
        |> Builder.add_table("filter")
        |> Builder.add_counter("test", family: :ip)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      counter_cmd = Enum.at(decoded["nftables"], 1)
      assert counter_cmd["add"]["counter"]["family"] == "ip"
    end
  end

  describe "Table specification" do
    test "uses current_table when set" do
      builder =
        Builder.new()
        |> Builder.add_table("nat")
        |> Builder.add_counter("nat_counter")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      counter_cmd = Enum.at(decoded["nftables"], 1)
      assert counter_cmd["add"]["counter"]["table"] == "nat"
    end

    test "allows table override" do
      builder =
        Builder.new()
        |> Builder.add_table("filter")
        |> Builder.add_table("nat")
        |> Builder.set_table("filter")
        |> Builder.add_counter("other_counter", table: "nat")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      # Find the counter command (skip the two table commands)
      counter_cmd = Enum.find(decoded["nftables"], fn cmd ->
        Map.has_key?(cmd, "add") && Map.has_key?(cmd["add"], "counter")
      end)
      assert counter_cmd["add"]["counter"]["table"] == "nat"
    end
  end
end
