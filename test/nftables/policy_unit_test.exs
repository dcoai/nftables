defmodule NFTables.PolicyUnitTest do
  use ExUnit.Case, async: true

  alias NFTables.{Policy, Builder}

  describe "build_accept_loopback/1" do
    test "generates correct JSON structure with defaults" do
      builder = Policy.build_accept_loopback()
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.table == "filter"
      assert rule.chain == "INPUT"
      assert rule.family == "inet"

      # Should have iifname match for "lo" and accept
      assert length(rule.expr) >= 2

      [match_expr, accept_expr] = rule.expr
      assert %{match: %{left: %{meta: %{key: "iifname"}}, right: "lo"}} = match_expr
      assert %{accept: nil} = accept_expr
    end

    test "generates correct JSON with custom table/chain" do
      builder = Policy.build_accept_loopback(table: "custom", chain: "FORWARD")
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.table == "custom"
      assert rule.chain == "FORWARD"
    end

    test "generates correct JSON with custom family" do
      builder = Policy.build_accept_loopback(family: :ip6)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.family == "ip6"
    end
  end

  describe "build_accept_established/1" do
    test "generates correct JSON structure" do
      builder = Policy.build_accept_established()
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.table == "filter"
      assert rule.chain == "INPUT"

      # Should have ct state match and accept
      assert length(rule.expr) >= 2

      [ct_expr, accept_expr] = rule.expr
      assert %{match: %{left: %{ct: %{key: "state"}}, right: state}} = ct_expr
      assert "established" in state
      assert "related" in state
      assert %{accept: nil} = accept_expr
    end

    test "works with custom options" do
      builder = Policy.build_accept_established(
        table: "test",
        chain: "CUSTOM",
        family: :inet
      )

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.table == "test"
      assert rule.chain == "CUSTOM"
    end
  end

  describe "build_drop_invalid/1" do
    test "generates correct JSON structure" do
      builder = Policy.build_drop_invalid()
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have ct state match for invalid and drop
      [ct_expr, drop_expr] = rule.expr
      assert %{match: %{op: "in", left: %{ct: %{key: "state"}}, right: ["invalid"]}} = ct_expr
      assert %{drop: nil} = drop_expr
    end

    test "works with custom options" do
      builder = Policy.build_drop_invalid(table: "test", chain: "INPUT", family: :inet)

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.table == "test"
    end
  end

  describe "build_allow_ssh/1" do
    test "generates correct JSON with defaults" do
      builder = Policy.build_allow_ssh()
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have tcp match, dport match for 22, and accept
      assert length(rule.expr) >= 3

      # Find TCP protocol match
      tcp_expr = Enum.find(rule.expr, fn e ->
        match?(%{match: %{left: %{payload: %{protocol: "tcp"}}}}, e)
      end)
      assert tcp_expr != nil

      # Find port 22 match
      port_expr = Enum.find(rule.expr, fn e ->
        match?(%{match: %{right: 22}}, e)
      end)
      assert port_expr != nil

      # Find accept
      accept_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :accept) end)
      assert accept_expr != nil
    end

    test "generates correct JSON with rate limiting" do
      builder = Policy.build_allow_ssh(rate_limit: 10)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have limit expression
      limit_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :limit) end)
      assert limit_expr != nil
      assert limit_expr.limit.rate == 10
      assert limit_expr.limit.per == "minute"
    end

    test "generates correct JSON with logging" do
      builder = Policy.build_allow_ssh(log: true)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have log expression
      log_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :log) end)
      assert log_expr != nil
      assert String.contains?(log_expr.log.prefix, "SSH")
    end

    test "generates correct JSON with rate limiting and logging" do
      builder = Policy.build_allow_ssh(rate_limit: 10, log: true)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have both limit and log expressions
      limit_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :limit) end)
      log_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :log) end)

      assert limit_expr != nil
      assert log_expr != nil
    end
  end

  describe "build_allow_http/1" do
    test "generates correct JSON for HTTP (port 80)" do
      builder = Policy.build_allow_http()
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Find port 80 match
      port_expr = Enum.find(rule.expr, fn e ->
        match?(%{match: %{right: 80}}, e)
      end)
      assert port_expr != nil
    end

    test "generates correct JSON with rate limiting" do
      builder = Policy.build_allow_http(rate_limit: 100)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      limit_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :limit) end)
      assert limit_expr != nil
      assert limit_expr.limit.rate == 100
    end

    test "generates correct JSON with logging" do
      builder = Policy.build_allow_http(log: true)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      log_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :log) end)
      assert log_expr != nil
      assert String.contains?(log_expr.log.prefix, "HTTP")
    end
  end

  describe "build_allow_https/1" do
    test "generates correct JSON for HTTPS (port 443)" do
      builder = Policy.build_allow_https()
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Find port 443 match
      port_expr = Enum.find(rule.expr, fn e ->
        match?(%{match: %{right: 443}}, e)
      end)
      assert port_expr != nil
    end

    test "generates correct JSON with options" do
      builder = Policy.build_allow_https(rate_limit: 200)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      limit_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :limit) end)
      assert limit_expr != nil
      assert limit_expr.limit.rate == 200
    end
  end

  describe "build_allow_dns/1" do
    test "generates correct JSON for DNS (port 53)" do
      builder = Policy.build_allow_dns()
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Find port 53 match
      port_expr = Enum.find(rule.expr, fn e ->
        match?(%{match: %{right: 53}}, e)
      end)
      assert port_expr != nil
    end
  end

  describe "build_allow_any/1" do
    test "generates correct JSON for accept all" do
      builder = Policy.build_allow_any()
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have just accept, no matches
      assert length(rule.expr) == 1
      assert %{accept: nil} = List.first(rule.expr)
    end

    test "generates correct JSON with logging" do
      builder = Policy.build_allow_any(log: true)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have log and accept
      assert length(rule.expr) == 2
      log_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :log) end)
      assert log_expr != nil
      assert String.contains?(log_expr.log.prefix, "ALLOW ANY")
    end
  end

  describe "build_deny_all/1" do
    test "generates correct JSON for drop all" do
      builder = Policy.build_deny_all()
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have just drop, no matches
      assert length(rule.expr) == 1
      assert %{drop: nil} = List.first(rule.expr)
    end

    test "generates correct JSON with logging" do
      builder = Policy.build_deny_all(log: true)
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      # Should have log and drop
      assert length(rule.expr) == 2
      log_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :log) end)
      assert log_expr != nil
      assert String.contains?(log_expr.log.prefix, "DENY ALL")
    end
  end

  describe "option handling" do
    test "accepts empty options for loopback" do
      builder = Policy.build_accept_loopback([])
      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      # Should use defaults
      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command
      assert rule.table == "filter"
      assert rule.chain == "INPUT"
    end

    test "merges default and custom options" do
      builder = Policy.build_allow_ssh(
        table: "test",
        chain: "INPUT",
        rate_limit: 5,
        family: :inet
      )

      json = Builder.to_json(builder)
      decoded = Jason.decode!(json, keys: :atoms)

      assert %{nftables: [command]} = decoded
      assert %{add: %{rule: rule}} = command

      assert rule.table == "test"
      assert rule.chain == "INPUT"
      assert rule.family == "inet"

      limit_expr = Enum.find(rule.expr, fn e -> Map.has_key?(e, :limit) end)
      assert limit_expr.limit.rate == 5
    end
  end
end
