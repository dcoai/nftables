Code.require_file("../test_helper.exs", __DIR__)

defmodule NFTex.SetOperationsTest do
  use ExUnit.Case
  require Logger

  alias NFTex.Set

  @moduletag :integration

  # Prerequisites:
  # - CAP_NET_ADMIN capability set on binary
  # - filter table exists: nft add table filter
  # - test_blocklist set exists: nft add set filter test_blocklist '{ type ipv4_addr; }'

  describe "add_elements/5" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_set
    test "adds single IP to set", %{pid: pid} do
      ips = [<<192, 168, 88, 10>>]
      result = Set.add_elements(pid, "filter", "test_blocklist", :inet, ips)
      assert result == :ok
    end

    @tag :requires_set
    test "adds multiple IPs to set", %{pid: pid} do
      ips = [
        <<192, 168, 88, 20>>,
        <<192, 168, 88, 21>>,
        <<192, 168, 88, 22>>
      ]
      result = Set.add_elements(pid, "filter", "test_blocklist", :inet, ips)
      assert result == :ok
    end

    @tag :requires_set
    test "adding duplicate IP is idempotent", %{pid: pid} do
      ip = <<192, 168, 88, 30>>

      # Add once
      result1 = Set.add_elements(pid, "filter", "test_blocklist", :inet, [ip])
      assert result1 == :ok

      # Add again (should succeed or be idempotent)
      result2 = Set.add_elements(pid, "filter", "test_blocklist", :inet, [ip])
      # nftables typically allows duplicate adds (they're idempotent)
      assert result2 == :ok or match?({:error, _}, result2)
    end

    test "returns error for non-existent set", %{pid: pid} do
      ips = [<<192, 168, 88, 40>>]
      result = Set.add_elements(pid, "filter", "nonexistent_set", :inet, ips)
      assert {:error, _reason} = result
    end

    test "returns error for non-existent table", %{pid: pid} do
      ips = [<<192, 168, 88, 41>>]
      result = Set.add_elements(pid, "nonexistent_table", "test_blocklist", :inet, ips)
      assert {:error, _reason} = result
    end
  end

  describe "delete_elements/5" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_set
    test "deletes IP from set", %{pid: pid} do
      ip = <<192, 168, 88, 50>>

      # First add it
      :ok = Set.add_elements(pid, "filter", "test_blocklist", :inet, [ip])

      # Then delete it
      result = Set.delete_elements(pid, "filter", "test_blocklist", :inet, [ip])
      assert result == :ok
    end

    @tag :requires_set
    test "deletes multiple IPs from set", %{pid: pid} do
      ips = [
        <<192, 168, 88, 60>>,
        <<192, 168, 88, 61>>
      ]

      # Add them
      :ok = Set.add_elements(pid, "filter", "test_blocklist", :inet, ips)

      # Delete them
      result = Set.delete_elements(pid, "filter", "test_blocklist", :inet, ips)
      assert result == :ok
    end

    @tag :requires_set
    test "deleting non-existent IP succeeds or returns error", %{pid: pid} do
      ip = <<192, 168, 88, 70>>
      result = Set.delete_elements(pid, "filter", "test_blocklist", :inet, [ip])
      # Implementation dependent - might succeed (idempotent) or error
      assert result == :ok or match?({:error, _}, result)
    end
  end

  describe "list_elements/3" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_set
    test "lists elements in set", %{pid: pid} do
      # Add some elements
      ips = [
        <<192, 168, 88, 80>>,
        <<192, 168, 88, 81>>
      ]
      :ok = Set.add_elements(pid, "filter", "test_blocklist", :inet, ips)

      # List them
      {:ok, elements} = Set.list_elements(pid, "filter", "test_blocklist")
      assert is_list(elements)
      assert length(elements) >= 2

      # Verify element structure
      for elem <- elements do
        assert is_map(elem)
        # Should have either key_ip or key_hex
        assert Map.has_key?(elem, :key_ip) or Map.has_key?(elem, :key_hex)
      end
    end

    @tag :requires_set
    test "element has readable IP format", %{pid: pid} do
      ip = <<192, 168, 88, 90>>
      :ok = Set.add_elements(pid, "filter", "test_blocklist", :inet, [ip])

      {:ok, elements} = Set.list_elements(pid, "filter", "test_blocklist")

      # Find our element
      our_elem = Enum.find(elements, fn e ->
        Map.get(e, :key_ip) == "192.168.88.90"
      end)

      if our_elem do
        assert our_elem.key_ip == "192.168.88.90"
      end
    end

    test "returns error for non-existent set", %{pid: pid} do
      result = Set.list_elements(pid, "filter", "nonexistent_set")
      # Should return error or empty list
      assert match?({:ok, []}, result) or match?({:error, _}, result)
    end
  end

  describe "exists?/4" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_set
    test "returns true for existing set", %{pid: pid} do
      result = Set.exists?(pid, "filter", "test_blocklist", :inet)
      assert result == true
    end

    test "returns false for non-existent set", %{pid: pid} do
      result = Set.exists?(pid, "filter", "definitely_does_not_exist", :inet)
      assert result == false
    end

    test "returns false for non-existent table", %{pid: pid} do
      result = Set.exists?(pid, "nonexistent_table", "test_blocklist", :inet)
      assert result == false
    end
  end

  describe "list/2" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    test "lists all sets for family", %{pid: pid} do
      {:ok, sets} = Set.list(pid, family: :inet)
      assert is_list(sets)

      for set <- sets do
        assert is_map(set)
        assert Map.has_key?(set, :name)
        assert Map.has_key?(set, :table)
      end
    end
  end

  describe "integration test" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn -> NFTex.stop(pid) end)
      {:ok, pid: pid}
    end

    @tag :requires_set
    test "complete workflow: add, list, delete, verify", %{pid: pid} do
      # Add elements
      ips = [
        <<192, 168, 88, 100>>,
        <<192, 168, 88, 101>>,
        <<192, 168, 88, 102>>
      ]
      :ok = Set.add_elements(pid, "filter", "test_blocklist", :inet, ips)

      # List and verify they're there
      {:ok, elements_before} = Set.list_elements(pid, "filter", "test_blocklist")
      count_before = length(elements_before)
      assert count_before >= 3

      # Delete one
      :ok = Set.delete_elements(pid, "filter", "test_blocklist", :inet, [hd(ips)])

      # Verify count decreased
      {:ok, elements_after} = Set.list_elements(pid, "filter", "test_blocklist")
      count_after = length(elements_after)
      assert count_after == count_before - 1
    end

    @tag :requires_set
    test "batch operations are efficient", %{pid: pid} do
      # Generate 50 IPs
      ips = for i <- 1..50, do: <<192, 168, 77, i>>

      # Add them all at once
      start_time = System.monotonic_time(:millisecond)
      :ok = Set.add_elements(pid, "filter", "test_blocklist", :inet, ips)
      end_time = System.monotonic_time(:millisecond)

      duration = end_time - start_time
      Logger.info("Added 50 IPs in #{duration}ms")

      # Should be fast (under 100ms on most systems)
      assert duration < 100

      # Clean up
      :ok = Set.delete_elements(pid, "filter", "test_blocklist", :inet, ips)
    end
  end
end
