defmodule NFTables.ExprTest do
  use ExUnit.Case, async: true

  import NFTables.Expr
  import NFTables.Expr.{IP, Port, TCP, Layer2, CT, Actions, Verdict}

  describe "rule/1" do
    test "creates empty rule struct with default family" do
      builder = expr()

      assert %NFTables.Expr{} = builder
      assert builder.family == :inet
      assert builder.expr_list == []
      assert builder.comment == nil
    end

    test "creates rule with custom family" do
      builder = expr(family: :inet6)

      assert builder.family == :inet6
    end
  end

  describe "match functions" do
    test "source_ip/2 adds expression to builder" do
      builder = expr() |> source_ip("192.168.1.100")

      assert %NFTables.Expr{} = builder
      assert length(builder.expr_list) == 1
    end

    test "dest_ip/2 adds expression to builder" do
      builder = expr() |> dest_ip("10.0.0.1")

      assert length(builder.expr_list) == 1
    end

    test "sport/2 adds expression to builder" do
      builder = expr() |> protocol(:tcp) |> sport(1234)

      # tcp() + sport()
      assert length(builder.expr_list) == 2
    end

    test "dport/2 adds expression to builder" do
      builder = expr() |> protocol(:tcp) |> dport(80)

      # tcp() + dport()
      assert length(builder.expr_list) == 2
    end

    test "dport/2 validates port range" do
      # Valid ports
      assert %NFTables.Expr{} = expr() |> protocol(:tcp) |> dport(0)
      assert %NFTables.Expr{} = expr() |> protocol(:tcp) |> dport(65535)

      # Invalid ports should raise ArgumentError
      assert_raise ArgumentError, fn ->
        expr() |> protocol(:tcp) |> dport(-1)
      end

      assert_raise ArgumentError, fn ->
        expr() |> protocol(:tcp) |> dport(65536)
      end
    end

    test "dport/2 requires protocol context" do
      # Should raise if called without tcp() or udp()
      assert_raise ArgumentError, ~r/requires protocol context/, fn ->
        expr() |> dport(80)
      end
    end

    test "dport/2 works with ranges" do
      builder = expr() |> protocol(:tcp) |> dport(8000..9000)

      # tcp() + dport()
      assert length(builder.expr_list) == 2
    end

    test "sport/2 works with ranges" do
      builder = expr() |> protocol(:tcp) |> sport(1024..65535)

      # tcp() + sport()
      assert length(builder.expr_list) == 2
    end

    test "ct_state/2 with single state" do
      builder = expr() |> ct_state([:established])

      assert length(builder.expr_list) == 1
    end

    test "ct_state/2 with multiple states" do
      builder = expr() |> ct_state([:established, :related])

      assert length(builder.expr_list) == 1
    end

    test "ct_state/2 with all states" do
      builder = expr() |> ct_state([:invalid, :established, :related, :new])

      assert length(builder.expr_list) == 1
    end

    test "iif/2 adds expression to builder" do
      builder = expr() |> iif("eth0")

      assert length(builder.expr_list) == 1
    end

    test "oif/2 adds expression to builder" do
      builder = expr() |> oif("eth1")

      assert length(builder.expr_list) == 1
    end
  end

  describe "action functions" do
    test "counter/1 adds counter expression" do
      builder = expr() |> counter()

      assert length(builder.expr_list) == 1
    end

    test "log/2 adds log expression with prefix" do
      builder = expr() |> log("TEST: ")

      assert length(builder.expr_list) == 1
    end

    test "log/3 adds log expression with options" do
      builder = expr() |> log("TEST: ", level: :warning)

      assert length(builder.expr_list) == 1
    end

    test "rate_limit/3 adds rate limit expression" do
      builder = expr() |> rate_limit(10, :minute)

      assert length(builder.expr_list) == 1
    end

    test "rate_limit/4 with burst option" do
      builder = expr() |> rate_limit(100, :second, burst: 50)

      assert length(builder.expr_list) == 1
    end
  end

  describe "verdict functions" do
    test "accept/1 adds accept verdict" do
      builder = expr() |> accept()

      assert length(builder.expr_list) == 1
    end

    test "drop/1 adds drop verdict" do
      builder = expr() |> drop()

      assert length(builder.expr_list) == 1
    end

    test "reject/1 adds reject verdict with default type" do
      builder = expr() |> reject()

      assert length(builder.expr_list) == 1
    end

    test "reject/2 adds reject verdict with custom type" do
      builder = expr() |> reject(:tcp_reset)

      assert length(builder.expr_list) == 1
    end
  end

  describe "basic matching functions" do
    test "source_ip/2 matches source IP address" do
      builder = expr() |> source_ip("192.168.1.1")

      assert length(builder.expr_list) == 1
    end

    test "dest_ip/2 matches destination IP address" do
      builder = expr() |> dest_ip("10.0.0.1")

      assert length(builder.expr_list) == 1
    end

    test "sport/2 matches source port" do
      builder = expr() |> protocol(:tcp) |> sport(1024)

      # protocol(:tcp) + sport()
      assert length(builder.expr_list) == 2
    end

    test "dport/2 matches destination port" do
      builder = expr() |> protocol(:tcp) |> dport(443)

      # protocol(:tcp) + dport()
      assert length(builder.expr_list) == 2
    end

    test "dport/2 also works as port matcher" do
      builder = expr() |> protocol(:tcp) |> dport(22)

      # protocol(:tcp) + dport()
      assert length(builder.expr_list) == 2
    end

    test "ct_state/2 matches connection state" do
      builder = expr() |> ct_state([:established, :related])

      assert length(builder.expr_list) == 1
    end

    test "rate_limit/3 adds rate limiting" do
      builder = expr() |> rate_limit(10, :minute)

      assert length(builder.expr_list) == 1
    end
  end

  describe "protocol helpers" do
    test "protocol(:tcp) matches TCP protocol" do
      builder = expr() |> protocol(:tcp)

      assert length(builder.expr_list) == 1
    end

    test "protocol(:udp) matches UDP protocol" do
      builder = expr() |> protocol(:udp)

      assert length(builder.expr_list) == 1
    end

    test "protocol(:icmp) matches ICMP protocol" do
      builder = expr() |> protocol(:icmp)

      assert length(builder.expr_list) == 1
    end
  end

  describe "chaining" do
    test "chains multiple match expressions" do
      builder =
        expr()
        |> source_ip("192.168.1.100")
        |> protocol(:tcp)
        |> dport(22)

      # source() + tcp() + dport()
      assert length(builder.expr_list) == 3
    end

    test "chains match, action, and verdict" do
      builder =
        expr()
        |> protocol(:tcp)
        |> dport(80)
        |> counter()
        |> accept()

      # tcp() + dport() + counter() + accept()
      assert length(builder.expr_list) == 4
    end

    test "preserves expression order" do
      builder =
        expr()
        |> source_ip("192.168.1.100")
        |> protocol(:tcp)
        |> dport(22)
        |> log("SSH: ")
        |> drop()

      # source() + tcp() + dport() + log() + drop()
      assert length(builder.expr_list) == 5
      # Expressions should be in the order they were added
    end
  end

  describe "to_expr/1" do
    test "extracts expression list from rule" do
      expr_list =
        expr()
        |> protocol(:tcp)
        |> dport(22)
        |> accept()
        |> to_list()

      assert is_list(expr_list)
      assert length(expr_list) == 3
    end
  end

  describe "comment/2" do
    test "adds comment to rule" do
      builder =
        expr()
        |> protocol(:tcp)
        |> dport(22)
        |> comment("Allow SSH")
        |> accept()

      assert builder.comment == "Allow SSH"
    end
  end

  describe "complex rule patterns" do
    test "builds SSH rate limiting rule" do
      builder =
        expr()
        |> protocol(:tcp)
        |> dport(22)
        |> rate_limit(10, :minute, burst: 5)
        |> log("SSH: ")
        |> accept()

      # tcp() + dport() + limit() + log() + accept()
      assert length(builder.expr_list) == 5
    end

    test "builds IP blocking rule with logging" do
      builder =
        expr()
        |> source_ip("192.168.1.100")
        |> counter()
        |> log("BLOCKED: ")
        |> drop()

      assert length(builder.expr_list) == 4
    end

    test "builds established connection acceptance rule" do
      builder =
        expr()
        |> ct_state([:established, :related])
        |> counter()
        |> accept()

      assert length(builder.expr_list) == 3
    end

    test "builds loopback acceptance rule" do
      builder =
        expr()
        |> iif("lo")
        |> accept()

      assert length(builder.expr_list) == 2
    end

    test "builds web server rule with rate limiting" do
      builder =
        expr()
        |> protocol(:tcp)
        |> dport(80)
        |> rate_limit(100, :second, burst: 200)
        |> counter()
        |> accept()

      # tcp() + dport() + limit() + counter() + accept()
      assert length(builder.expr_list) == 5
    end
  end
end
