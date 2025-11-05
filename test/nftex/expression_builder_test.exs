Code.require_file("../test_helper.exs", __DIR__)

defmodule NFTex.ExpressionBuilderTest do
  use ExUnit.Case
  require Logger

  alias NFTex.ExpressionBuilder

  @moduletag :integration

  describe "payload expressions" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn ->
        if Process.alive?(pid) do
          NFTex.stop(pid)
        end
      end)
      {:ok, pid: pid}
    end

    test "payload_ipv4_saddr/2 creates payload expression", %{pid: pid} do
      {:ok, expr_id} = ExpressionBuilder.payload_ipv4_saddr(pid, 1)
      assert is_integer(expr_id)
      assert expr_id > 0
    end

    test "payload_ipv4_daddr/2 creates payload expression", %{pid: pid} do
      {:ok, expr_id} = ExpressionBuilder.payload_ipv4_daddr(pid, 1)
      assert is_integer(expr_id)
      assert expr_id > 0
    end

    test "payload_ipv4_protocol/2 creates payload expression", %{pid: pid} do
      {:ok, expr_id} = ExpressionBuilder.payload_ipv4_protocol(pid, 1)
      assert is_integer(expr_id)
      assert expr_id > 0
    end

    test "payload_network/4 creates payload expression with custom params", %{pid: pid} do
      # Load 2 bytes at offset 20 (IPv4 src port for TCP/UDP)
      {:ok, expr_id} = ExpressionBuilder.payload_network(pid, 1, 20, 2)
      assert is_integer(expr_id)
      assert expr_id > 0
    end
  end

  describe "comparison expressions" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn ->
        if Process.alive?(pid) do
          NFTex.stop(pid)
        end
      end)
      {:ok, pid: pid}
    end

    test "cmp_eq/3 creates equality comparison", %{pid: pid} do
      ip = <<192, 168, 1, 100>>
      {:ok, expr_id} = ExpressionBuilder.cmp_eq(pid, 1, ip)
      assert is_integer(expr_id)
      assert expr_id > 0
    end

    test "cmp_neq/3 creates inequality comparison", %{pid: pid} do
      ip = <<10, 0, 0, 1>>
      {:ok, expr_id} = ExpressionBuilder.cmp_neq(pid, 1, ip)
      assert is_integer(expr_id)
      assert expr_id > 0
    end

    test "cmp/4 creates comparison with custom operator", %{pid: pid} do
      data = <<192, 168, 1, 100>>
      # 0 = EQ, 1 = NEQ, 2 = LT, 3 = LTE, 4 = GT, 5 = GTE
      {:ok, expr_id} = ExpressionBuilder.cmp(pid, 1, 0, data)
      assert is_integer(expr_id)
      assert expr_id > 0
    end
  end

  describe "counter expression" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn ->
        if Process.alive?(pid) do
          NFTex.stop(pid)
        end
      end)
      {:ok, pid: pid}
    end

    test "counter/1 creates counter expression", %{pid: pid} do
      {:ok, expr_id} = ExpressionBuilder.counter(pid)
      assert is_integer(expr_id)
      assert expr_id > 0
    end
  end

  describe "verdict expressions" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn ->
        if Process.alive?(pid) do
          NFTex.stop(pid)
        end
      end)
      {:ok, pid: pid}
    end

    test "verdict_drop/1 creates DROP verdict", %{pid: pid} do
      {:ok, expr_id} = ExpressionBuilder.verdict_drop(pid)
      assert is_integer(expr_id)
      assert expr_id > 0
    end

    test "verdict_accept/1 creates ACCEPT verdict", %{pid: pid} do
      {:ok, expr_id} = ExpressionBuilder.verdict_accept(pid)
      assert is_integer(expr_id)
      assert expr_id > 0
    end

    test "verdict/2 creates verdict with custom code", %{pid: pid} do
      # 0 = DROP, 1 = ACCEPT
      {:ok, expr_id} = ExpressionBuilder.verdict(pid, 0)
      assert is_integer(expr_id)
      assert expr_id > 0
    end
  end

  describe "expression combination" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn ->
        if Process.alive?(pid) do
          NFTex.stop(pid)
        end
      end)
      {:ok, pid: pid}
    end

    test "can create multiple expressions for a rule", %{pid: pid} do
      # Simulate building expressions for an IP blocking rule
      {:ok, payload_id} = ExpressionBuilder.payload_ipv4_saddr(pid, 1)
      {:ok, cmp_id} = ExpressionBuilder.cmp_eq(pid, 1, <<192, 168, 1, 100>>)
      {:ok, counter_id} = ExpressionBuilder.counter(pid)
      {:ok, verdict_id} = ExpressionBuilder.verdict_drop(pid)

      # All should be unique IDs
      assert payload_id != cmp_id
      assert cmp_id != counter_id
      assert counter_id != verdict_id
    end
  end
end
