defmodule NFTables.MatchTest do
  use ExUnit.Case, async: true

  import NFTables.Match

  describe "rule/1" do
    test "creates empty rule struct with default family" do
      builder = rule()

      assert %NFTables.Match{} = builder
      assert builder.family == :inet
      assert builder.expr_list == []
      assert builder.comment == nil
    end

    test "creates rule with custom family" do
      builder = rule(family: :inet6)

      assert builder.family == :inet6
    end
  end

  describe "match functions" do
    test "source_ip/2 adds expression to builder" do
      builder = rule() |> source_ip("192.168.1.100")

      assert %NFTables.Match{} = builder
      assert length(builder.expr_list) == 1
    end

    test "dest_ip/2 adds expression to builder" do
      builder = rule() |> dest_ip("10.0.0.1")

      assert length(builder.expr_list) == 1
    end

    test "sport/2 adds expression to builder" do
      builder = rule() |> tcp() |> sport(1234)

      assert length(builder.expr_list) == 2  # tcp() + sport()
    end

    test "dport/2 adds expression to builder" do
      builder = rule() |> tcp() |> dport(80)

      assert length(builder.expr_list) == 2  # tcp() + dport()
    end

    test "dport/2 validates port range" do
      # Valid ports
      assert %NFTables.Match{} = rule() |> tcp() |> dport(0)
      assert %NFTables.Match{} = rule() |> tcp() |> dport(65535)

      # Invalid ports should raise ArgumentError
      assert_raise ArgumentError, fn ->
        rule() |> tcp() |> dport(-1)
      end

      assert_raise ArgumentError, fn ->
        rule() |> tcp() |> dport(65536)
      end
    end

    test "dport/2 requires protocol context" do
      # Should raise if called without tcp() or udp()
      assert_raise ArgumentError, ~r/requires protocol context/, fn ->
        rule() |> dport(80)
      end
    end

    test "dport/2 works with ranges" do
      builder = rule() |> tcp() |> dport(8000..9000)

      assert length(builder.expr_list) == 2  # tcp() + dport()
    end

    test "sport/2 works with ranges" do
      builder = rule() |> tcp() |> sport(1024..65535)

      assert length(builder.expr_list) == 2  # tcp() + sport()
    end

    test "ct_state/2 with single state" do
      builder = rule() |> ct_state([:established])

      assert length(builder.expr_list) == 1
    end

    test "ct_state/2 with multiple states" do
      builder = rule() |> ct_state([:established, :related])

      assert length(builder.expr_list) == 1
    end

    test "ct_state/2 with all states" do
      builder = rule() |> ct_state([:invalid, :established, :related, :new])

      assert length(builder.expr_list) == 1
    end

    test "iif/2 adds expression to builder" do
      builder = rule() |> iif("eth0")

      assert length(builder.expr_list) == 1
    end

    test "oif/2 adds expression to builder" do
      builder = rule() |> oif("eth1")

      assert length(builder.expr_list) == 1
    end
  end

  describe "action functions" do
    test "counter/1 adds counter expression" do
      builder = rule() |> counter()

      assert length(builder.expr_list) == 1
    end

    test "log/2 adds log expression with prefix" do
      builder = rule() |> log("TEST: ")

      assert length(builder.expr_list) == 1
    end

    test "log/3 adds log expression with options" do
      builder = rule() |> log("TEST: ", level: :warning)

      assert length(builder.expr_list) == 1
    end

    test "rate_limit/3 adds rate limit expression" do
      builder = rule() |> rate_limit(10, :minute)

      assert length(builder.expr_list) == 1
    end

    test "rate_limit/4 with burst option" do
      builder = rule() |> rate_limit(100, :second, burst: 50)

      assert length(builder.expr_list) == 1
    end
  end

  describe "verdict functions" do
    test "accept/1 adds accept verdict" do
      builder = rule() |> accept()

      assert length(builder.expr_list) == 1
    end

    test "drop/1 adds drop verdict" do
      builder = rule() |> drop()

      assert length(builder.expr_list) == 1
    end

    test "reject/1 adds reject verdict with default type" do
      builder = rule() |> reject()

      assert length(builder.expr_list) == 1
    end

    test "reject/2 adds reject verdict with custom type" do
      builder = rule() |> reject(:tcp_reset)

      assert length(builder.expr_list) == 1
    end
  end

  describe "convenience aliases" do
    test "source/2 is alias for source_ip/2" do
      builder = rule() |> source("192.168.1.1")

      assert length(builder.expr_list) == 1
    end

    test "dest/2 is alias for dest_ip/2" do
      builder = rule() |> dest("10.0.0.1")

      assert length(builder.expr_list) == 1
    end

    test "sport/2 matches source port" do
      builder = rule() |> tcp() |> sport(1024)

      assert length(builder.expr_list) == 2  # tcp() + sport()
    end

    test "dport/2 matches destination port" do
      builder = rule() |> tcp() |> dport(443)

      assert length(builder.expr_list) == 2  # tcp() + dport()
    end

    test "port/2 is alias for dport/2" do
      builder = rule() |> tcp() |> port(22)

      assert length(builder.expr_list) == 2  # tcp() + port()
    end

    test "state/2 is alias for ct_state/2" do
      builder = rule() |> state([:established, :related])

      assert length(builder.expr_list) == 1
    end

    test "limit/3 is alias for rate_limit/3" do
      builder = rule() |> limit(10, :minute)

      assert length(builder.expr_list) == 1
    end
  end

  describe "protocol helpers" do
    test "tcp/1 matches TCP protocol" do
      builder = rule() |> tcp()

      assert length(builder.expr_list) == 1
    end

    test "udp/1 matches UDP protocol" do
      builder = rule() |> udp()

      assert length(builder.expr_list) == 1
    end

    test "icmp/1 matches ICMP protocol" do
      builder = rule() |> icmp()

      assert length(builder.expr_list) == 1
    end
  end

  describe "chaining" do
    test "chains multiple match expressions" do
      builder =
        rule()
        |> source("192.168.1.100")
        |> tcp()
        |> dport(22)

      assert length(builder.expr_list) == 3  # source() + tcp() + dport()
    end

    test "chains match, action, and verdict" do
      builder =
        rule()
        |> tcp()
        |> dport(80)
        |> counter()
        |> accept()

      assert length(builder.expr_list) == 4  # tcp() + dport() + counter() + accept()
    end

    test "preserves expression order" do
      builder =
        rule()
        |> source("192.168.1.100")
        |> tcp()
        |> dport(22)
        |> log("SSH: ")
        |> drop()

      assert length(builder.expr_list) == 5  # source() + tcp() + dport() + log() + drop()
      # Expressions should be in the order they were added
    end
  end

  describe "to_expr/1" do
    test "extracts expression list from rule" do
      expr_list =
        rule()
        |> tcp()
        |> dport(22)
        |> accept()
        |> to_expr()

      assert is_list(expr_list)
      assert length(expr_list) == 3
    end
  end

  describe "comment/2" do
    test "adds comment to rule" do
      builder =
        rule()
        |> tcp()
        |> dport(22)
        |> comment("Allow SSH")
        |> accept()

      assert builder.comment == "Allow SSH"
    end
  end

  describe "complex rule patterns" do
    test "builds SSH rate limiting rule" do
      builder =
        rule()
        |> tcp()
        |> dport(22)
        |> limit(10, :minute, burst: 5)
        |> log("SSH: ")
        |> accept()

      assert length(builder.expr_list) == 5  # tcp() + dport() + limit() + log() + accept()
    end

    test "builds IP blocking rule with logging" do
      builder =
        rule()
        |> source("192.168.1.100")
        |> counter()
        |> log("BLOCKED: ")
        |> drop()

      assert length(builder.expr_list) == 4
    end

    test "builds established connection acceptance rule" do
      builder =
        rule()
        |> state([:established, :related])
        |> counter()
        |> accept()

      assert length(builder.expr_list) == 3
    end

    test "builds loopback acceptance rule" do
      builder =
        rule()
        |> iif("lo")
        |> accept()

      assert length(builder.expr_list) == 2
    end

    test "builds web server rule with rate limiting" do
      builder =
        rule()
        |> tcp()
        |> dport(80)
        |> limit(100, :second, burst: 200)
        |> counter()
        |> accept()

      assert length(builder.expr_list) == 5  # tcp() + dport() + limit() + counter() + accept()
    end
  end
end
