Code.require_file("test_helper.exs", __DIR__)

defmodule ResourceTest do
  use ExUnit.Case
  require Logger

  @moduletag :integration

  describe "NFTex resource management" do
    test "can allocate multiple tables" do
      {:ok, pid} = NFTex.start_link()

      # Allocate multiple tables
      {:ok, id1} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      {:ok, id2} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      {:ok, id3} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      # Each should have unique IDs
      assert id1 != id2
      assert id2 != id3
      assert id1 != id3

      # All should be positive integers
      assert id1 > 0
      assert id2 > 0
      assert id3 > 0

      NFTex.stop(pid)
    end

    test "can allocate chains" do
      {:ok, pid} = NFTex.start_link()

      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)
      assert is_integer(chain_id)
      assert chain_id > 0

      NFTex.stop(pid)
    end

    test "can allocate rules" do
      {:ok, pid} = NFTex.start_link()

      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)
      assert is_integer(rule_id)
      assert rule_id > 0

      NFTex.stop(pid)
    end

    test "can allocate expressions" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.Port.call(pid, {:expr_alloc, "counter"}, 5000)
      assert is_integer(expr_id)
      assert expr_id > 0

      NFTex.stop(pid)
    end

    test "can allocate mixed resource types" do
      {:ok, pid} = NFTex.start_link()

      # Allocate various resources
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)
      {:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc}, 5000)
      {:ok, expr_id} = NFTex.Port.call(pid, {:expr_alloc, "counter"}, 5000)

      # All should have unique IDs
      ids = [table_id, chain_id, rule_id, expr_id]
      assert length(Enum.uniq(ids)) == 4

      NFTex.stop(pid)
    end

    test "resource IDs increment sequentially" do
      {:ok, pid} = NFTex.start_link()

      # Allocate resources and check they increment
      {:ok, id1} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      {:ok, id2} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      {:ok, id3} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      assert id2 == id1 + 1
      assert id3 == id2 + 1

      NFTex.stop(pid)
    end
  end
end
