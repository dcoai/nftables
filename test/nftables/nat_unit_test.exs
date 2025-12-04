defmodule NFTables.NATUnitTest do
  use ExUnit.Case, async: true

  alias NFTables.{NAT, Builder}

  describe "setup_masquerade/3" do
    test "generates correct JSON structure" do
      builder = NAT.setup_masquerade(Builder.new(), "eth0")
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.table == "nat"
      assert rule.chain == "postrouting"

      # Should have oifname match and masquerade
      assert Enum.any?(rule.expr, fn e ->
               match?(%{match: %{left: %{meta: %{key: "oifname"}}, right: "eth0"}}, e)
             end)

      assert Enum.any?(rule.expr, fn e -> Map.has_key?(e, :masquerade) end)
    end
  end

  describe "port_forward/5" do
    test "generates correct JSON for basic port forward" do
      builder = NAT.port_forward(Builder.new(), 80, "192.168.1.100", 8080)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have TCP match, port match, and DNAT
      assert Enum.any?(rule.expr, fn e ->
               match?(%{match: %{left: %{payload: %{protocol: "tcp"}}}}, e)
             end)

      assert Enum.any?(rule.expr, fn e -> Map.has_key?(e, :dnat) end)
    end

    test "supports UDP protocol" do
      builder = NAT.port_forward(Builder.new(), 53, "192.168.1.1", 53, protocol: :udp)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have UDP match
      assert Enum.any?(rule.expr, fn e ->
               match?(%{match: %{left: %{payload: %{protocol: "udp"}}}}, e)
             end)
    end
  end

  describe "source_nat/4" do
    test "generates correct JSON structure" do
      builder = NAT.source_nat(Builder.new(), "192.168.1.0/24", "203.0.113.1")
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.chain == "postrouting"
      assert Enum.any?(rule.expr, fn e -> Map.has_key?(e, :snat) end)
    end
  end

  describe "destination_nat/4" do
    test "generates correct JSON structure" do
      builder = NAT.destination_nat(Builder.new(), "203.0.113.1", "192.168.1.100")
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.chain == "prerouting"
      assert Enum.any?(rule.expr, fn e -> Map.has_key?(e, :dnat) end)
    end
  end

  describe "redirect_port/4" do
    test "generates correct JSON for port redirect" do
      builder = NAT.redirect_port(Builder.new(), 80, 3128)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert Enum.any?(rule.expr, fn e -> Map.has_key?(e, :redirect) end)
    end
  end

  describe "static_nat/4" do
    test "generates correct JSON for 1:1 NAT (both DNAT and SNAT)" do
      builder = NAT.static_nat(Builder.new(), "203.0.113.1", "192.168.1.100")
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: commands} = decoded
      # Should have 2 commands (DNAT + SNAT)
      assert length(commands) == 2

      # First should be DNAT (prerouting)
      assert %{add: %{rule: dnat_rule}} = Enum.at(commands, 0)
      assert dnat_rule.chain == "prerouting"
      assert Enum.any?(dnat_rule.expr, fn e -> Map.has_key?(e, :dnat) end)

      # Second should be SNAT (postrouting)
      assert %{add: %{rule: snat_rule}} = Enum.at(commands, 1)
      assert snat_rule.chain == "postrouting"
      assert Enum.any?(snat_rule.expr, fn e -> Map.has_key?(e, :snat) end)
    end
  end
end
