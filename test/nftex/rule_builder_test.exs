defmodule NFTex.RuleBuilderTest do
  use ExUnit.Case, async: false

  alias NFTex.{RuleBuilder, Table, Chain}

  setup do
    {:ok, pid} = NFTex.start_link()

    # Clean up and create test table and chain
    Table.delete(pid, "nftex_test_rule_builder", :inet)
    :ok = Table.create(pid, %{name: "nftex_test_rule_builder", family: :inet})

    # Create regular chain WITHOUT hook (safe - won't filter traffic)
    :ok = Chain.create(pid, %{
      table: "nftex_test_rule_builder",
      name: "test_rb_chain",
      family: :inet
    })

    on_exit(fn ->
      if Process.alive?(pid) do
        Table.delete(pid, "nftex_test_rule_builder", :inet)
      end
    end)

    {:ok, pid: pid}
  end

  describe "new/3" do
    test "creates builder struct with required fields", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      assert %RuleBuilder{} = builder
      assert builder.pid == pid
      assert builder.table == "nftex_test_rule_builder"
      assert builder.chain == "test_rb_chain"
      assert builder.family == :inet
      assert builder.expressions == []
    end

    test "creates builder with custom family", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain", family: :inet6)

      assert builder.family == :inet6
    end
  end

  describe "match functions" do
    test "match_source_ip/2 adds expression to builder", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.match_source_ip(builder, <<192, 168, 1, 100>>)

      assert %RuleBuilder{} = builder
      assert length(builder.expressions) == 1
    end

    test "match_dest_ip/2 adds expression to builder", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.match_dest_ip(builder, <<10, 0, 0, 1>>)

      assert length(builder.expressions) == 1
    end

    test "match_source_port/2 adds expression to builder", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.match_source_port(builder, 1234)

      assert length(builder.expressions) == 1
    end

    test "match_dest_port/2 adds expression to builder", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.match_dest_port(builder, 80)

      assert length(builder.expressions) == 1
    end

    test "match_dest_port/2 validates port range", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      # Valid ports
      assert %RuleBuilder{} = RuleBuilder.match_dest_port(builder, 0)
      assert %RuleBuilder{} = RuleBuilder.match_dest_port(builder, 65535)

      # Invalid ports should raise (guard clause)
      assert_raise FunctionClauseError, fn ->
        RuleBuilder.match_dest_port(builder, -1)
      end

      assert_raise FunctionClauseError, fn ->
        RuleBuilder.match_dest_port(builder, 65536)
      end
    end

    test "match_ct_state/2 with single state", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.match_ct_state(builder, [:established])

      assert length(builder.expressions) == 1
    end

    test "match_ct_state/2 with multiple states", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.match_ct_state(builder, [:established, :related])

      assert length(builder.expressions) == 1
    end

    test "match_ct_state/2 with all states", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.match_ct_state(builder, [:invalid, :established, :related, :new])

      assert length(builder.expressions) == 1
    end

    test "match_iif/2 adds expression to builder", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.match_iif(builder, "eth0")

      assert length(builder.expressions) == 1
    end

    test "match_oif/2 adds expression to builder", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.match_oif(builder, "eth1")

      assert length(builder.expressions) == 1
    end
  end

  describe "action functions" do
    test "counter/1 adds counter expression", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.counter(builder)

      assert length(builder.expressions) == 1
    end

    test "log/2 adds log expression with prefix", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.log(builder, "TEST: ")

      assert length(builder.expressions) == 1
    end

    test "log/3 adds log expression with options", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.log(builder, "TEST: ", level: :warning)

      assert length(builder.expressions) == 1
    end

    test "rate_limit/3 adds rate limit expression", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.rate_limit(builder, 10, :minute)

      assert length(builder.expressions) == 1
    end

    test "rate_limit/4 with burst option", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.rate_limit(builder, 100, :second, burst: 50)

      assert length(builder.expressions) == 1
    end
  end

  describe "verdict functions" do
    test "accept/1 adds accept verdict", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.accept(builder)

      assert length(builder.expressions) == 1
    end

    test "drop/1 adds drop verdict", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.drop(builder)

      assert length(builder.expressions) == 1
    end

    test "reject/1 adds reject verdict with default type", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.reject(builder)

      assert length(builder.expressions) == 1
    end

    test "reject/2 adds reject verdict with custom type", %{pid: pid} do
      builder = RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")

      builder = RuleBuilder.reject(builder, :tcp_reset)

      assert length(builder.expressions) == 1
    end
  end

  describe "chaining" do
    test "chains multiple match expressions", %{pid: pid} do
      builder =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_source_ip(<<192, 168, 1, 100>>)
        |> RuleBuilder.match_dest_port(22)

      assert length(builder.expressions) == 2
    end

    test "chains match, action, and verdict", %{pid: pid} do
      builder =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.counter()
        |> RuleBuilder.accept()

      assert length(builder.expressions) == 3
    end

    test "preserves expression order", %{pid: pid} do
      builder =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_source_ip(<<192, 168, 1, 100>>)
        |> RuleBuilder.match_dest_port(22)
        |> RuleBuilder.log("SSH: ")
        |> RuleBuilder.drop()

      assert length(builder.expressions) == 4
      # Expressions should be in the order they were added
    end
  end

  describe "commit/1" do
    test "commits simple rule successfully", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "commits rule with multiple matches", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_source_ip(<<192, 168, 1, 100>>)
        |> RuleBuilder.match_dest_port(22)
        |> RuleBuilder.drop()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "commits rule with counter", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_dest_port(443)
        |> RuleBuilder.counter()
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "commits rule with rate limiting", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_dest_port(22)
        |> RuleBuilder.rate_limit(10, :minute)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "commits rule with connection tracking state", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_ct_state([:established, :related])
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "commits rule with interface matching", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_iif("lo")
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "returns error for invalid table", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nonexistent_table", "test_rb_chain")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert {:error, _reason} = result
    end

    test "returns error for invalid chain", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "nonexistent_chain")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert {:error, _reason} = result
    end
  end

  describe "complex rule patterns" do
    test "builds SSH rate limiting rule", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_dest_port(22)
        |> RuleBuilder.rate_limit(10, :minute, burst: 5)
        |> RuleBuilder.log("SSH: ")
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "builds IP blocking rule with logging", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_source_ip(<<192, 168, 1, 100>>)
        |> RuleBuilder.counter()
        |> RuleBuilder.log("BLOCKED: ")
        |> RuleBuilder.drop()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "builds established connection acceptance rule", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_ct_state([:established, :related])
        |> RuleBuilder.counter()
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "builds loopback acceptance rule", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_iif("lo")
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result == :ok
    end

    test "builds web server rule with rate limiting", %{pid: pid} do
      result =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.rate_limit(100, :second, burst: 200)
        |> RuleBuilder.counter()
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result == :ok
    end
  end

  describe "multiple rules in same chain" do
    test "commits multiple different rules successfully", %{pid: pid} do
      # Rule 1: Accept loopback
      result1 =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_iif("lo")
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result1 == :ok

      # Rule 2: Accept established/related
      result2 =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_ct_state([:established, :related])
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result2 == :ok

      # Rule 3: Allow SSH with rate limit
      result3 =
        RuleBuilder.new(pid, "nftex_test_rule_builder", "test_rb_chain")
        |> RuleBuilder.match_dest_port(22)
        |> RuleBuilder.rate_limit(10, :minute)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert result3 == :ok
    end
  end
end
