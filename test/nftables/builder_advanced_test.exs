defmodule NFTables.BuilderAdvancedTest do
  use ExUnit.Case, async: true

  alias NFTables.Builder

  describe "Maps - add(map:)" do
    test "adds a map with key-value type" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.add(map: "port_map", type: {:inet_service, :verdict})

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
        |> Builder.add(table: "nat")
        |> Builder.add(map: "addr_map", type: {:ipv4_addr, :ipv4_addr})

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      map_cmd = Enum.at(decoded["nftables"], 1)
      assert map_cmd["add"]["map"]["type"] == "ipv4_addr"
      assert map_cmd["add"]["map"]["map"] == "ipv4_addr"
    end

    test "raises when table not specified" do
      assert_raise ArgumentError, ~r/table must be specified/, fn ->
        Builder.new()
        |> Builder.add(map: "test_map", type: {:ipv4_addr, :verdict})
      end
    end

    test "raises when type not provided" do
      assert_raise ArgumentError, ~r/type must be/, fn ->
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.add(map: "test_map")
      end
    end
  end

  describe "Maps - delete(map:)" do
    test "deletes a map" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.delete(map: "port_map", type: {:inet_service, :verdict})

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

  describe "Maps - add(element:) for maps" do
    test "adds elements to a map" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter", map: "port_map", type: {:inet_service, :verdict})
        |> Builder.add(element: [
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
        |> Builder.add(table: "filter", map: "test_map", type: {:inet_service, :verdict})
        |> Builder.add(element: [{22, "accept"}])

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      element_cmd = Enum.at(decoded["nftables"], 1)
      assert element_cmd["add"]["element"]["elem"] == [[22, "accept"]]
    end
  end

  describe "Maps - delete(element:) for maps" do
    test "deletes elements from a map" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter", map: "port_map", type: {:inet_service, :verdict})
        |> Builder.delete(element: [80, 443])

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      element_cmd = Enum.at(decoded["nftables"], 1)

      assert element_cmd["delete"]["element"]["name"] == "port_map"
      assert element_cmd["delete"]["element"]["elem"] == [80, 443]
    end
  end

  describe "Named Counters - add(counter:)" do
    test "adds a counter with default values" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.add(counter: "http_counter")

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
        |> Builder.add(table: "filter")
        |> Builder.add(counter: "test_counter", packets: 100, bytes: 5000)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      counter_cmd = Enum.at(decoded["nftables"], 1)
      assert counter_cmd["add"]["counter"]["packets"] == 100
      assert counter_cmd["add"]["counter"]["bytes"] == 5000
    end

    test "raises when table not specified" do
      assert_raise ArgumentError, ~r/table must be specified/, fn ->
        Builder.new()
        |> Builder.add(counter: "test_counter")
      end
    end
  end

  describe "Named Counters - delete(counter:)" do
    test "deletes a counter" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.delete(counter: "http_counter")

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

  describe "Quotas - add(quota:)" do
    test "adds a quota with default values" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.add(quota: "monthly_limit", bytes: 1_000_000_000)

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
        |> Builder.add(table: "filter")
        |> Builder.add(quota: "test_quota", bytes: 500_000, used: 100_000, over: true)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      quota_cmd = Enum.at(decoded["nftables"], 1)
      assert quota_cmd["add"]["quota"]["bytes"] == 500_000
      assert quota_cmd["add"]["quota"]["used"] == 100_000
      assert quota_cmd["add"]["quota"]["over"] == true
    end

    test "raises when table not specified" do
      assert_raise ArgumentError, ~r/table must be specified/, fn ->
        Builder.new()
        |> Builder.add(quota: "test_quota", bytes: 1000)
      end
    end

    test "validates non-negative bytes" do
      # This should work
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.add(quota: "test", bytes: 0)

      assert %Builder{} = builder
    end
  end

  describe "Quotas - delete(quota:)" do
    test "deletes a quota" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.delete(quota: "monthly_limit")

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

  describe "Named Limits - add(limit:)" do
    test "adds a limit with default burst" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.add(limit: "ssh_limit", rate: 10, unit: :minute)

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
        |> Builder.add(table: "filter")
        |> Builder.add(limit: "http_limit", rate: 100, unit: :second, burst: 50)

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
          |> Builder.add(table: "filter")
          |> Builder.add(limit: "test_limit", rate: 5, unit: unit)

        json = Builder.to_json(builder)
        decoded = Jason.decode!(json)

        limit_cmd = Enum.at(decoded["nftables"], 1)
        assert limit_cmd["add"]["limit"]["per"] == to_string(unit)
      end
    end

    test "raises when table not specified" do
      assert_raise ArgumentError, ~r/table must be specified/, fn ->
        Builder.new()
        |> Builder.add(limit: "test_limit", rate: 10, unit: :minute)
      end
    end
  end

  describe "Named Limits - delete(limit:)" do
    test "deletes a limit" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.delete(limit: "ssh_limit", rate: 10, unit: :minute)

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
        |> Builder.add(table: "filter")
        |> Builder.add(map: "port_verdict", type: {:inet_service, :verdict})
        |> Builder.add(element: [
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
        |> Builder.add(table: "filter")
        |> Builder.add(counter: "web_counter")
        |> Builder.add(quota: "daily_quota", bytes: 10_000_000_000)
        |> Builder.add(limit: "rate_limit", rate: 100, unit: :second, burst: 50)

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
        |> Builder.add(table: "filter")
        |> Builder.add(chain: "INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
        |> Builder.add(counter: "input_counter")
        |> Builder.add(set: "blocklist", type: :ipv4_addr)
        |> Builder.add(limit: "ssh_limit", rate: 10, unit: :minute, burst: 5)

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
        |> Builder.add(table: "filter")
        |> Builder.add(map: "ipv6_map", type: {:ipv6_addr, :verdict})

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      map_cmd = Enum.at(decoded["nftables"], 1)
      assert map_cmd["add"]["map"]["family"] == "ip6"
    end

    test "allows family override for counter" do
      builder =
        Builder.new(family: :inet)
        |> Builder.add(table: "filter")
        |> Builder.add(counter: "test", family: :ip)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      counter_cmd = Enum.at(decoded["nftables"], 1)
      assert counter_cmd["add"]["counter"]["family"] == "ip"
    end
  end

  describe "Table specification" do
    test "uses table context when set" do
      builder =
        Builder.new()
        |> Builder.add(table: "nat")
        |> Builder.add(counter: "nat_counter")

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json)

      counter_cmd = Enum.at(decoded["nftables"], 1)
      assert counter_cmd["add"]["counter"]["table"] == "nat"
    end

    test "allows table override" do
      builder =
        Builder.new()
        |> Builder.add(table: "filter")
        |> Builder.add(table: "nat")
        |> Builder.add(counter: "other_counter", table: "nat")

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
