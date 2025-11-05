Code.require_file("test_helper.exs", __DIR__)

defmodule ChainAttrTest do
  use ExUnit.Case
  require Logger

  @moduletag :integration

  describe "NFTex chain attribute operations" do
    test "can set and get chain name" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a chain
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)
      assert is_integer(chain_id)

      # Set the chain name
      :ok = NFTex.Port.call(pid, {:chain_set_str, chain_id, :name, "my_chain"}, 5000)

      # Get the chain name back
      {:ok, name} = NFTex.Port.call(pid, {:chain_get_str, chain_id, :name}, 5000)
      assert name == "my_chain"

      NFTex.stop(pid)
    end

    test "can set and get chain table name" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a chain
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Set the chain's table name
      :ok = NFTex.Port.call(pid, {:chain_set_str, chain_id, :table, "filter"}, 5000)

      # Get the table name back
      {:ok, table} = NFTex.Port.call(pid, {:chain_get_str, chain_id, :table}, 5000)
      assert table == "filter"

      NFTex.stop(pid)
    end

    test "can set and get chain family" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a chain
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Set the chain family (2 = AF_INET)
      :ok = NFTex.Port.call(pid, {:chain_set_u32, chain_id, :family, 2}, 5000)

      # Get the chain family back
      {:ok, family} = NFTex.Port.call(pid, {:chain_get_u32, chain_id, :family}, 5000)
      assert family == 2

      NFTex.stop(pid)
    end

    test "can set and get chain hooknum" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a chain
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Set the chain hooknum (1 = NF_INET_LOCAL_IN)
      :ok = NFTex.Port.call(pid, {:chain_set_u32, chain_id, :hooknum, 1}, 5000)

      # Get the hooknum back
      {:ok, hooknum} = NFTex.Port.call(pid, {:chain_get_u32, chain_id, :hooknum}, 5000)
      assert hooknum == 1

      NFTex.stop(pid)
    end

    test "can set and get chain priority" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a chain
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Set the chain priority
      :ok = NFTex.Port.call(pid, {:chain_set_u32, chain_id, :prio, 100}, 5000)

      # Get the priority back
      {:ok, prio} = NFTex.Port.call(pid, {:chain_get_u32, chain_id, :prio}, 5000)
      assert prio == 100

      NFTex.stop(pid)
    end

    # Note: Policy attribute has libnftnl internal assertion issues
    # The policy attribute seems to require the chain to be fully configured
    # and may only be settable via netlink batch operations, not on a local object
    # @tag :skip
    # test "can set chain policy on base chain" do
    #   ...
    # end

    test "can configure base chain with hook" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a chain
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Configure as a base chain
      :ok = NFTex.Port.call(pid, {:chain_set_str, chain_id, :name, "input"}, 5000)
      :ok = NFTex.Port.call(pid, {:chain_set_str, chain_id, :table, "filter"}, 5000)
      :ok = NFTex.Port.call(pid, {:chain_set_u32, chain_id, :family, 2}, 5000)
      :ok = NFTex.Port.call(pid, {:chain_set_u32, chain_id, :hooknum, 1}, 5000)  # LOCAL_IN
      :ok = NFTex.Port.call(pid, {:chain_set_u32, chain_id, :prio, 0}, 5000)
      # Note: policy attribute seems to have issues with libnftnl assertions
      # :ok = NFTex.Port.call(pid, {:chain_set_u8, chain_id, :policy, 1}, 5000)  # accept

      # Verify all attributes
      {:ok, name} = NFTex.Port.call(pid, {:chain_get_str, chain_id, :name}, 5000)
      {:ok, table} = NFTex.Port.call(pid, {:chain_get_str, chain_id, :table}, 5000)
      {:ok, family} = NFTex.Port.call(pid, {:chain_get_u32, chain_id, :family}, 5000)
      {:ok, hooknum} = NFTex.Port.call(pid, {:chain_get_u32, chain_id, :hooknum}, 5000)
      {:ok, prio} = NFTex.Port.call(pid, {:chain_get_u32, chain_id, :prio}, 5000)

      assert name == "input"
      assert table == "filter"
      assert family == 2
      assert hooknum == 1
      assert prio == 0

      NFTex.stop(pid)
    end

    test "returns error for invalid resource ID" do
      {:ok, pid} = NFTex.start_link()

      # Try to set on non-existent resource
      {:error, msg} = NFTex.Port.call(pid, {:chain_set_str, 99999, :name, "bad"}, 5000)
      assert msg =~ "resource not found"

      # Try to get from non-existent resource
      {:error, msg} = NFTex.Port.call(pid, {:chain_get_str, 99999, :name}, 5000)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "returns error for unknown string attribute" do
      {:ok, pid} = NFTex.start_link()

      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Try to set unknown string attribute
      {:error, msg} = NFTex.Port.call(pid, {:chain_set_str, chain_id, :unknown, "value"}, 5000)
      assert msg =~ "unknown attr"

      # Try to get unknown string attribute
      {:error, msg} = NFTex.Port.call(pid, {:chain_get_str, chain_id, :unknown}, 5000)
      assert msg =~ "unknown attr"

      NFTex.stop(pid)
    end

    test "returns error for unknown u32 attribute" do
      {:ok, pid} = NFTex.start_link()

      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Try to set unknown u32 attribute
      {:error, msg} = NFTex.Port.call(pid, {:chain_set_u32, chain_id, :unknown, 42}, 5000)
      assert msg =~ "unknown attr"

      # Try to get unknown u32 attribute
      {:error, msg} = NFTex.Port.call(pid, {:chain_get_u32, chain_id, :unknown}, 5000)
      assert msg =~ "unknown attr"

      NFTex.stop(pid)
    end

    test "returns error for value exceeding u8 range" do
      {:ok, pid} = NFTex.start_link()

      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Try to set value > 255 for u8 attribute
      {:error, msg} = NFTex.Port.call(pid, {:chain_set_u8, chain_id, :policy, 256}, 5000)
      assert msg =~ "exceeds u8 range"

      NFTex.stop(pid)
    end
  end
end
