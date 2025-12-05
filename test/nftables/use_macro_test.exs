defmodule NFTables.UseMacroTest do
  use ExUnit.Case

  # Test the use macro by creating a test module that uses it
  defmodule TestModule do
    use NFTables

    def test_tcp_rule do
      tcp() |> dport(22) |> accept()
    end

    def test_udp_rule do
      udp() |> dport(53) |> accept()
    end

    def test_icmp_rule do
      icmp() |> accept()
    end

    def test_ip_functions do
      source("192.168.1.1") |> dest("10.0.0.1") |> drop()
    end

    def test_port_functions do
      tcp() |> dport(80) |> sport(1024) |> accept()
    end

    def test_ct_functions do
      state([:established, :related]) |> accept()
    end

    def test_actions do
      tcp() |> dport(22) |> counter() |> accept()
    end

    def test_rate_limiting do
      tcp() |> dport(22) |> limit(10, :minute) |> accept()
    end

    def test_nat do
      tcp() |> dport(8080) |> dnat_to("192.168.1.100:80")
    end

    def test_all_functions do
      # Verify various functions from different modules are available
      rule1 = tcp() |> dport(80) |> accept()
      rule2 = source("192.168.1.1") |> drop()
      rule3 = state([:established]) |> accept()
      rule4 = counter() |> accept()
      rule5 = udp() |> dport(53) |> accept()
      {rule1, rule2, rule3, rule4, rule5}
    end
  end

  test "use NFTables imports tcp() function" do
    rule = TestModule.test_tcp_rule()
    assert %NFTables.Expr{} = rule
    assert rule.protocol == :tcp
    assert length(rule.expr_list) > 0
  end

  test "use NFTables imports udp() function" do
    rule = TestModule.test_udp_rule()
    assert %NFTables.Expr{} = rule
    assert rule.protocol == :udp
    assert length(rule.expr_list) > 0
  end

  test "use NFTables imports icmp() function" do
    rule = TestModule.test_icmp_rule()
    assert %NFTables.Expr{} = rule
    assert rule.protocol == :icmp
  end

  test "use NFTables imports IP functions" do
    rule = TestModule.test_ip_functions()
    assert %NFTables.Expr{} = rule
    assert length(rule.expr_list) > 0
  end

  test "use NFTables imports port functions" do
    rule = TestModule.test_port_functions()
    assert %NFTables.Expr{} = rule
    assert length(rule.expr_list) > 0
  end

  test "use NFTables imports CT functions" do
    rule = TestModule.test_ct_functions()
    assert %NFTables.Expr{} = rule
    assert length(rule.expr_list) > 0
  end

  test "use NFTables imports action functions" do
    rule = TestModule.test_actions()
    assert %NFTables.Expr{} = rule
    assert length(rule.expr_list) > 0
  end

  test "use NFTables imports rate limiting functions" do
    rule = TestModule.test_rate_limiting()
    assert %NFTables.Expr{} = rule
    assert length(rule.expr_list) > 0
  end

  test "use NFTables imports NAT functions" do
    rule = TestModule.test_nat()
    assert %NFTables.Expr{} = rule
    assert length(rule.expr_list) > 0
  end

  test "all module functions accessible" do
    assert {r1, r2, r3, r4, r5} = TestModule.test_all_functions()
    assert %NFTables.Expr{} = r1
    assert %NFTables.Expr{} = r2
    assert %NFTables.Expr{} = r3
    assert %NFTables.Expr{} = r4
    assert %NFTables.Expr{} = r5
  end

  test "functions produce valid expression lists" do
    rule = TestModule.test_tcp_rule()
    expr_list = NFTables.Expr.to_list(rule)
    assert is_list(expr_list)
    assert length(expr_list) > 0
    # Verify expression maps are properly formed
    Enum.each(expr_list, fn expr ->
      assert is_map(expr)
    end)
  end
end
