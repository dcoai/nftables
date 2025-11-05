Code.require_file("test_helper.exs", __DIR__)

defmodule TableAttrTest do
  use ExUnit.Case
  require Logger

  @moduletag :integration

  describe "NFTex table attribute operations" do
    test "can set and get table name" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a table
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      assert is_integer(table_id)

      # Set the table name
      :ok = NFTex.Port.call(pid, {:table_set_str, table_id, :name, "my_table"}, 5000)

      # Get the table name back
      {:ok, name} = NFTex.Port.call(pid, {:table_get_str, table_id, :name}, 5000)
      assert name == "my_table"

      NFTex.stop(pid)
    end

    test "can set and get table family" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a table
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      # Set the table family (2 = AF_INET)
      :ok = NFTex.Port.call(pid, {:table_set_u32, table_id, :family, 2}, 5000)

      # Get the table family back
      {:ok, family} = NFTex.Port.call(pid, {:table_get_u32, table_id, :family}, 5000)
      assert family == 2

      NFTex.stop(pid)
    end

    test "can set and get table flags" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a table
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      # Set the table flags
      :ok = NFTex.Port.call(pid, {:table_set_u32, table_id, :flags, 1}, 5000)

      # Get the table flags back
      {:ok, flags} = NFTex.Port.call(pid, {:table_get_u32, table_id, :flags}, 5000)
      assert flags == 1

      NFTex.stop(pid)
    end

    test "can set multiple attributes on same table" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a table
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      # Set multiple attributes
      :ok = NFTex.Port.call(pid, {:table_set_str, table_id, :name, "test_table"}, 5000)
      :ok = NFTex.Port.call(pid, {:table_set_u32, table_id, :family, 10}, 5000)
      :ok = NFTex.Port.call(pid, {:table_set_u32, table_id, :flags, 0}, 5000)

      # Get them all back
      {:ok, name} = NFTex.Port.call(pid, {:table_get_str, table_id, :name}, 5000)
      {:ok, family} = NFTex.Port.call(pid, {:table_get_u32, table_id, :family}, 5000)
      {:ok, flags} = NFTex.Port.call(pid, {:table_get_u32, table_id, :flags}, 5000)

      assert name == "test_table"
      assert family == 10
      assert flags == 0

      NFTex.stop(pid)
    end

    test "returns error for invalid resource ID" do
      {:ok, pid} = NFTex.start_link()

      # Try to set on non-existent resource
      {:error, msg} = NFTex.Port.call(pid, {:table_set_str, 99999, :name, "bad"}, 5000)
      assert msg =~ "resource not found"

      # Try to get from non-existent resource
      {:error, msg} = NFTex.Port.call(pid, {:table_get_str, 99999, :name}, 5000)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "returns error for unknown attribute" do
      {:ok, pid} = NFTex.start_link()

      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      # Try to set unknown string attribute
      {:error, msg} = NFTex.Port.call(pid, {:table_set_str, table_id, :unknown, "value"}, 5000)
      assert msg =~ "unknown attr"

      # Try to get unknown string attribute
      {:error, msg} = NFTex.Port.call(pid, {:table_get_str, table_id, :unknown}, 5000)
      assert msg =~ "unknown attr"

      NFTex.stop(pid)
    end
  end
end
