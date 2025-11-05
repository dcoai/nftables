Code.require_file("test_helper.exs", __DIR__)

defmodule SetTest do
  use ExUnit.Case
  require Logger

  @moduletag :integration

  describe "NFTex set operations" do
    test "can allocate and free set" do
      {:ok, pid} = NFTex.start_link()

      {:ok, set_id} = NFTex.set_alloc(pid)
      assert is_integer(set_id)

      :ok = NFTex.set_free(pid, set_id)

      # Verify the resource is no longer valid
      {:error, msg} = NFTex.set_free(pid, set_id)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "can set string attributes on set" do
      {:ok, pid} = NFTex.start_link()

      {:ok, set_id} = NFTex.set_alloc(pid)

      # Set attributes
      :ok = NFTex.set_set_str(pid, set_id, :name, "blacklist")
      :ok = NFTex.set_set_str(pid, set_id, :table, "filter")

      NFTex.stop(pid)
    end

    test "can set u32 attributes on set" do
      {:ok, pid} = NFTex.start_link()

      {:ok, set_id} = NFTex.set_alloc(pid)

      # Set various u32 attributes
      :ok = NFTex.set_set_u32(pid, set_id, :family, 2)  # AF_INET
      :ok = NFTex.set_set_u32(pid, set_id, :key_type, 7)  # NFT_DATA_VALUE
      :ok = NFTex.set_set_u32(pid, set_id, :key_len, 4)  # 4 bytes for IPv4
      :ok = NFTex.set_set_u32(pid, set_id, :flags, 0)

      NFTex.stop(pid)
    end

    test "can configure complete set" do
      {:ok, pid} = NFTex.start_link()

      {:ok, set_id} = NFTex.set_alloc(pid)

      # Configure as IPv4 address set
      :ok = NFTex.set_set_str(pid, set_id, :name, "ipv4_blacklist")
      :ok = NFTex.set_set_str(pid, set_id, :table, "filter")
      :ok = NFTex.set_set_u32(pid, set_id, :family, 2)  # AF_INET
      :ok = NFTex.set_set_u32(pid, set_id, :key_type, 7)  # NFT_DATA_VALUE
      :ok = NFTex.set_set_u32(pid, set_id, :key_len, 4)  # IPv4 = 4 bytes

      NFTex.stop(pid)
    end

    test "returns error for invalid set resource ID" do
      {:ok, pid} = NFTex.start_link()

      {:error, msg} = NFTex.set_set_str(pid, 99999, :name, "bad")
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "returns error for unknown string attribute" do
      {:ok, pid} = NFTex.start_link()

      {:ok, set_id} = NFTex.set_alloc(pid)

      {:error, msg} = NFTex.set_set_str(pid, set_id, :unknown, "value")
      assert msg =~ "unknown attr"

      NFTex.stop(pid)
    end

    test "returns error for unknown u32 attribute" do
      {:ok, pid} = NFTex.start_link()

      {:ok, set_id} = NFTex.set_alloc(pid)

      {:error, msg} = NFTex.set_set_u32(pid, set_id, :unknown, 42)
      assert msg =~ "unknown attr"

      NFTex.stop(pid)
    end

    test "returns error for wrong resource type in set operations" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a table instead of a set
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      # Try to use set operation on table
      {:error, msg} = NFTex.set_set_str(pid, table_id, :name, "test")
      assert msg =~ "not a set resource"

      NFTex.stop(pid)
    end
  end

  describe "NFTex set element operations" do
    test "can allocate and free set element" do
      {:ok, pid} = NFTex.start_link()

      {:ok, elem_id} = NFTex.set_elem_alloc(pid)
      assert is_integer(elem_id)

      :ok = NFTex.set_elem_free(pid, elem_id)

      # Verify the resource is no longer valid
      {:error, msg} = NFTex.set_elem_free(pid, elem_id)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "can set binary data on set element" do
      {:ok, pid} = NFTex.start_link()

      {:ok, elem_id} = NFTex.set_elem_alloc(pid)

      # Set IP address as key (192.168.1.1)
      ip_key = <<192, 168, 1, 1>>
      :ok = NFTex.set_elem_set_data(pid, elem_id, :key, ip_key)

      NFTex.stop(pid)
    end

    test "can set u32 attributes on set element" do
      {:ok, pid} = NFTex.start_link()

      {:ok, elem_id} = NFTex.set_elem_alloc(pid)

      # Set flags and timeout
      :ok = NFTex.set_elem_set_u32(pid, elem_id, :flags, 0)
      :ok = NFTex.set_elem_set_u32(pid, elem_id, :timeout, 3600)

      NFTex.stop(pid)
    end

    test "can configure complete set element" do
      {:ok, pid} = NFTex.start_link()

      {:ok, elem_id} = NFTex.set_elem_alloc(pid)

      # Configure element with IP address key
      ip_key = <<10, 0, 0, 1>>
      :ok = NFTex.set_elem_set_data(pid, elem_id, :key, ip_key)
      :ok = NFTex.set_elem_set_u32(pid, elem_id, :flags, 0)

      NFTex.stop(pid)
    end

    test "can add element to set" do
      {:ok, pid} = NFTex.start_link()

      # Create set
      {:ok, set_id} = NFTex.set_alloc(pid)
      :ok = NFTex.set_set_str(pid, set_id, :name, "test_set")
      :ok = NFTex.set_set_u32(pid, set_id, :key_len, 4)

      # Create element
      {:ok, elem_id} = NFTex.set_elem_alloc(pid)
      :ok = NFTex.set_elem_set_data(pid, elem_id, :key, <<192, 168, 1, 1>>)

      # Add element to set
      :ok = NFTex.set_elem_add(pid, set_id, elem_id)

      NFTex.stop(pid)
    end

    test "can add multiple elements to set" do
      {:ok, pid} = NFTex.start_link()

      # Create set
      {:ok, set_id} = NFTex.set_alloc(pid)
      :ok = NFTex.set_set_str(pid, set_id, :name, "ip_set")
      :ok = NFTex.set_set_u32(pid, set_id, :key_len, 4)

      # Create and add multiple elements
      {:ok, elem1_id} = NFTex.set_elem_alloc(pid)
      :ok = NFTex.set_elem_set_data(pid, elem1_id, :key, <<192, 168, 1, 1>>)
      :ok = NFTex.set_elem_add(pid, set_id, elem1_id)

      {:ok, elem2_id} = NFTex.set_elem_alloc(pid)
      :ok = NFTex.set_elem_set_data(pid, elem2_id, :key, <<192, 168, 1, 2>>)
      :ok = NFTex.set_elem_add(pid, set_id, elem2_id)

      {:ok, elem3_id} = NFTex.set_elem_alloc(pid)
      :ok = NFTex.set_elem_set_data(pid, elem3_id, :key, <<192, 168, 1, 3>>)
      :ok = NFTex.set_elem_add(pid, set_id, elem3_id)

      NFTex.stop(pid)
    end

    test "returns error for invalid set element resource ID" do
      {:ok, pid} = NFTex.start_link()

      {:error, msg} = NFTex.set_elem_set_data(pid, 99999, :key, <<1, 2, 3, 4>>)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "returns error for unknown set element attribute" do
      {:ok, pid} = NFTex.start_link()

      {:ok, elem_id} = NFTex.set_elem_alloc(pid)

      {:error, msg} = NFTex.set_elem_set_data(pid, elem_id, :unknown, <<1, 2, 3, 4>>)
      assert msg =~ "unknown attr"

      NFTex.stop(pid)
    end

    test "returns error for set_elem_add with non-existent set" do
      {:ok, pid} = NFTex.start_link()

      {:ok, elem_id} = NFTex.set_elem_alloc(pid)

      {:error, msg} = NFTex.set_elem_add(pid, 99999, elem_id)
      assert msg =~ "set not found"

      NFTex.stop(pid)
    end

    test "returns error for set_elem_add with non-existent elem" do
      {:ok, pid} = NFTex.start_link()

      {:ok, set_id} = NFTex.set_alloc(pid)

      {:error, msg} = NFTex.set_elem_add(pid, set_id, 99999)
      assert msg =~ "elem not found"

      NFTex.stop(pid)
    end

    test "returns error for set_elem_add with wrong resource types" do
      {:ok, pid} = NFTex.start_link()

      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)

      # Try to add chain to table (wrong types)
      {:error, msg} = NFTex.set_elem_add(pid, table_id, chain_id)
      assert msg =~ "not a set resource" or msg =~ "not a set_elem resource"

      NFTex.stop(pid)
    end

    test "returns error for wrong resource type in set_elem operations" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a table instead of a set element
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      # Try to use set_elem operation on table
      {:error, msg} = NFTex.set_elem_set_data(pid, table_id, :key, <<1, 2, 3, 4>>)
      assert msg =~ "not a set_elem resource"

      NFTex.stop(pid)
    end
  end

  describe "NFTex set integration" do
    test "can build complete set with elements" do
      {:ok, pid} = NFTex.start_link()

      # Create and configure set
      {:ok, set_id} = NFTex.set_alloc(pid)
      :ok = NFTex.set_set_str(pid, set_id, :name, "banned_ips")
      :ok = NFTex.set_set_str(pid, set_id, :table, "filter")
      :ok = NFTex.set_set_u32(pid, set_id, :family, 2)  # AF_INET
      :ok = NFTex.set_set_u32(pid, set_id, :key_type, 7)  # NFT_DATA_VALUE
      :ok = NFTex.set_set_u32(pid, set_id, :key_len, 4)  # IPv4

      # Add multiple IP addresses
      banned_ips = [
        <<192, 168, 1, 100>>,
        <<192, 168, 1, 101>>,
        <<10, 0, 0, 50>>,
        <<172, 16, 0, 10>>
      ]

      for ip <- banned_ips do
        {:ok, elem_id} = NFTex.set_elem_alloc(pid)
        :ok = NFTex.set_elem_set_data(pid, elem_id, :key, ip)
        :ok = NFTex.set_elem_add(pid, set_id, elem_id)
      end

      NFTex.stop(pid)
    end

    test "can create map set with key and data" do
      {:ok, pid} = NFTex.start_link()

      # Create map set (IP -> counter)
      {:ok, set_id} = NFTex.set_alloc(pid)
      :ok = NFTex.set_set_str(pid, set_id, :name, "ip_counters")
      :ok = NFTex.set_set_u32(pid, set_id, :family, 2)  # AF_INET
      :ok = NFTex.set_set_u32(pid, set_id, :key_type, 7)  # NFT_DATA_VALUE
      :ok = NFTex.set_set_u32(pid, set_id, :key_len, 4)  # IPv4
      :ok = NFTex.set_set_u32(pid, set_id, :data_type, 1)  # NFT_DATA_VALUE
      :ok = NFTex.set_set_u32(pid, set_id, :data_len, 4)  # 4 bytes

      # Add element with both key and data
      {:ok, elem_id} = NFTex.set_elem_alloc(pid)
      :ok = NFTex.set_elem_set_data(pid, elem_id, :key, <<192, 168, 1, 1>>)
      :ok = NFTex.set_elem_set_data(pid, elem_id, :data, <<0, 0, 0, 100>>)
      :ok = NFTex.set_elem_add(pid, set_id, elem_id)

      NFTex.stop(pid)
    end
  end
end
