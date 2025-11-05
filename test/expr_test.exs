Code.require_file("test_helper.exs", __DIR__)

defmodule ExprTest do
  use ExUnit.Case
  require Logger

  @moduletag :integration

  describe "NFTex expression operations" do
    test "can allocate expression with name" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a counter expression
      {:ok, expr_id} = NFTex.expr_alloc(pid, "counter")
      assert is_integer(expr_id)

      NFTex.stop(pid)
    end

    test "can allocate different expression types" do
      {:ok, pid} = NFTex.start_link()

      # Test various expression types
      {:ok, counter_id} = NFTex.expr_alloc(pid, "counter")
      {:ok, payload_id} = NFTex.expr_alloc(pid, "payload")
      {:ok, cmp_id} = NFTex.expr_alloc(pid, "cmp")
      {:ok, immediate_id} = NFTex.expr_alloc(pid, "immediate")
      {:ok, limit_id} = NFTex.expr_alloc(pid, "limit")

      assert is_integer(counter_id)
      assert is_integer(payload_id)
      assert is_integer(cmp_id)
      assert is_integer(immediate_id)
      assert is_integer(limit_id)

      NFTex.stop(pid)
    end

    test "can free expression" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "counter")
      :ok = NFTex.expr_free(pid, expr_id)

      # Verify the resource is no longer valid
      {:error, msg} = NFTex.expr_free(pid, expr_id)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "can set u8 attribute on expression" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "payload")

      # Set a u8 attribute (using generic attribute name)
      :ok = NFTex.expr_set_u8(pid, expr_id, :dreg, 1)

      NFTex.stop(pid)
    end

    test "can set u16 attribute on expression" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "payload")

      # Set a u16 attribute (using generic attribute name)
      :ok = NFTex.expr_set_u16(pid, expr_id, :offset, 12)

      NFTex.stop(pid)
    end

    test "can set u32 attribute on expression" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "payload")

      # Set a u32 attribute (using generic attribute name)
      :ok = NFTex.expr_set_u32(pid, expr_id, :base, 1)

      NFTex.stop(pid)
    end

    test "can set u64 attribute on expression" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "counter")

      # Set a u64 attribute (using generic attribute name)
      :ok = NFTex.expr_set_u64(pid, expr_id, :bytes, 1234567890)

      NFTex.stop(pid)
    end

    test "can set string attribute on expression" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "counter")

      # Set a string attribute (using generic attribute name)
      :ok = NFTex.expr_set_str(pid, expr_id, :name, "my_counter")

      NFTex.stop(pid)
    end

    test "can set binary data on expression" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "immediate")

      # Set binary data (e.g., IP address)
      data = <<192, 168, 1, 1>>
      :ok = NFTex.expr_set_data(pid, expr_id, :data, data)

      NFTex.stop(pid)
    end

    test "can configure payload expression completely" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "payload")

      # Configure payload expression to match source IP
      :ok = NFTex.expr_set_u32(pid, expr_id, :base, 1)  # NFT_PAYLOAD_NETWORK_HEADER
      :ok = NFTex.expr_set_u32(pid, expr_id, :offset, 12)  # Source IP offset
      :ok = NFTex.expr_set_u32(pid, expr_id, :len, 4)  # 4 bytes
      :ok = NFTex.expr_set_u8(pid, expr_id, :dreg, 1)  # Destination register

      NFTex.stop(pid)
    end

    test "can configure immediate expression with data" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "immediate")

      # Set register and data
      :ok = NFTex.expr_set_u8(pid, expr_id, :dreg, 1)
      :ok = NFTex.expr_set_data(pid, expr_id, :data, <<192, 168, 1, 1>>)

      NFTex.stop(pid)
    end

    test "can configure cmp expression" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "cmp")

      # Configure comparison operation
      :ok = NFTex.expr_set_u8(pid, expr_id, :sreg, 1)  # Source register
      :ok = NFTex.expr_set_u32(pid, expr_id, :op, 0)  # NFT_CMP_EQ
      :ok = NFTex.expr_set_data(pid, expr_id, :data, <<192, 168, 1, 1>>)

      NFTex.stop(pid)
    end

    test "returns error for invalid expression name" do
      {:ok, pid} = NFTex.start_link()

      # Try to allocate with invalid expression name
      {:error, msg} = NFTex.expr_alloc(pid, "nonexistent_expr")
      assert msg =~ "expr_alloc_failed"

      NFTex.stop(pid)
    end

    test "returns error for invalid resource ID in set operations" do
      {:ok, pid} = NFTex.start_link()

      # Try to set on non-existent resource
      {:error, msg} = NFTex.Port.call(pid, {:expr_set_u8, 99999, :dreg, 1}, 5000)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "returns error for invalid resource ID in free" do
      {:ok, pid} = NFTex.start_link()

      # Try to free non-existent resource
      {:error, msg} = NFTex.expr_free(pid, 99999)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "returns error for value exceeding u8 range" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "payload")

      # Try to set value > 255 for u8 attribute
      {:error, msg} = NFTex.expr_set_u8(pid, expr_id, :dreg, 256)
      assert msg =~ "exceeds u8 range"

      NFTex.stop(pid)
    end

    test "returns error for value exceeding u16 range" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "payload")

      # Try to set value > 65535 for u16 attribute
      {:error, msg} = NFTex.expr_set_u16(pid, expr_id, :offset, 65536)
      assert msg =~ "exceeds u16 range"

      NFTex.stop(pid)
    end

    test "returns error for wrong resource type in set operations" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a table instead of an expression
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      # Try to use expression set operation on table
      {:error, msg} = NFTex.Port.call(pid, {:expr_set_u8, table_id, :dreg, 1}, 5000)
      assert msg =~ "not an expr resource"

      NFTex.stop(pid)
    end

    test "expr_alloc requires expression name argument" do
      {:ok, pid} = NFTex.start_link()

      # Try to allocate without providing expression name
      {:error, msg} = NFTex.Port.call(pid, {:expr_alloc}, 5000)
      assert msg =~ "expected 1 arg"

      NFTex.stop(pid)
    end

    test "can set multiple attributes on same expression" do
      {:ok, pid} = NFTex.start_link()

      {:ok, expr_id} = NFTex.expr_alloc(pid, "payload")

      # Set multiple attributes
      :ok = NFTex.expr_set_u32(pid, expr_id, :base, 1)
      :ok = NFTex.expr_set_u32(pid, expr_id, :offset, 12)
      :ok = NFTex.expr_set_u32(pid, expr_id, :len, 4)
      :ok = NFTex.expr_set_u8(pid, expr_id, :dreg, 1)
      :ok = NFTex.expr_set_str(pid, expr_id, :name, "src_ip")

      NFTex.stop(pid)
    end

    test "can allocate and configure multiple expressions" do
      {:ok, pid} = NFTex.start_link()

      # Allocate and configure multiple expressions
      {:ok, payload_id} = NFTex.expr_alloc(pid, "payload")
      :ok = NFTex.expr_set_u32(pid, payload_id, :base, 1)
      :ok = NFTex.expr_set_u8(pid, payload_id, :dreg, 1)

      {:ok, cmp_id} = NFTex.expr_alloc(pid, "cmp")
      :ok = NFTex.expr_set_u8(pid, cmp_id, :sreg, 1)
      :ok = NFTex.expr_set_u32(pid, cmp_id, :op, 0)

      {:ok, counter_id} = NFTex.expr_alloc(pid, "counter")
      :ok = NFTex.expr_set_u64(pid, counter_id, :bytes, 0)

      NFTex.stop(pid)
    end
  end
end
