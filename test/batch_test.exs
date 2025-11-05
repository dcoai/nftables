Code.require_file("test_helper.exs", __DIR__)

defmodule BatchTest do
  use ExUnit.Case
  require Logger

  @moduletag :integration

  describe "NFTex batch operations" do
    test "can allocate and free batch" do
      {:ok, pid} = NFTex.start_link()

      {:ok, batch_id} = NFTex.batch_alloc(pid)
      assert is_integer(batch_id)

      :ok = NFTex.batch_free(pid, batch_id)

      # Verify the resource is no longer valid
      {:error, msg} = NFTex.batch_free(pid, batch_id)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "can allocate batch with custom page size and max pages" do
      {:ok, pid} = NFTex.start_link()

      {:ok, batch_id} = NFTex.batch_alloc(pid, 8192, 10)
      assert is_integer(batch_id)

      :ok = NFTex.batch_free(pid, batch_id)

      NFTex.stop(pid)
    end

    test "can allocate batch with default parameters" do
      {:ok, pid} = NFTex.start_link()

      # Uses defaults: page_size=4096, max_pages=20
      {:ok, batch_id} = NFTex.batch_alloc(pid)
      assert is_integer(batch_id)

      :ok = NFTex.batch_free(pid, batch_id)

      NFTex.stop(pid)
    end

    test "can allocate multiple batches" do
      {:ok, pid} = NFTex.start_link()

      {:ok, batch1_id} = NFTex.batch_alloc(pid)
      {:ok, batch2_id} = NFTex.batch_alloc(pid)
      {:ok, batch3_id} = NFTex.batch_alloc(pid)

      assert is_integer(batch1_id)
      assert is_integer(batch2_id)
      assert is_integer(batch3_id)

      # All should have unique IDs
      assert batch1_id != batch2_id
      assert batch2_id != batch3_id
      assert batch1_id != batch3_id

      :ok = NFTex.batch_free(pid, batch1_id)
      :ok = NFTex.batch_free(pid, batch2_id)
      :ok = NFTex.batch_free(pid, batch3_id)

      NFTex.stop(pid)
    end

    test "returns error for invalid batch resource ID" do
      {:ok, pid} = NFTex.start_link()

      {:error, msg} = NFTex.batch_free(pid, 99999)
      assert msg =~ "resource not found"

      NFTex.stop(pid)
    end

    test "returns error for wrong resource type in batch_free" do
      {:ok, pid} = NFTex.start_link()

      # Allocate a table instead of a batch
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)

      # Try to use batch_free on table
      {:error, msg} = NFTex.batch_free(pid, table_id)
      assert msg =~ "not a batch resource"

      NFTex.stop(pid)
    end

    test "batch allocation validates page_size parameter" do
      {:ok, pid} = NFTex.start_link()

      # Test with valid page sizes
      {:ok, batch1_id} = NFTex.batch_alloc(pid, 1024, 10)
      {:ok, batch2_id} = NFTex.batch_alloc(pid, 4096, 10)
      {:ok, batch3_id} = NFTex.batch_alloc(pid, 8192, 10)

      assert is_integer(batch1_id)
      assert is_integer(batch2_id)
      assert is_integer(batch3_id)

      NFTex.stop(pid)
    end

    test "batch allocation validates max_pages parameter" do
      {:ok, pid} = NFTex.start_link()

      # Test with different max_pages values
      {:ok, batch1_id} = NFTex.batch_alloc(pid, 4096, 1)
      {:ok, batch2_id} = NFTex.batch_alloc(pid, 4096, 20)
      {:ok, batch3_id} = NFTex.batch_alloc(pid, 4096, 100)

      assert is_integer(batch1_id)
      assert is_integer(batch2_id)
      assert is_integer(batch3_id)

      NFTex.stop(pid)
    end
  end

  describe "NFTex batch integration" do
    test "can allocate batch alongside other resources" do
      {:ok, pid} = NFTex.start_link()

      # Allocate various resources
      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      {:ok, chain_id} = NFTex.Port.call(pid, {:chain_alloc}, 5000)
      {:ok, batch_id} = NFTex.batch_alloc(pid)
      {:ok, set_id} = NFTex.set_alloc(pid)

      # All should have unique IDs
      ids = [table_id, chain_id, batch_id, set_id]
      assert length(Enum.uniq(ids)) == 4

      # Free resources
      :ok = NFTex.batch_free(pid, batch_id)

      NFTex.stop(pid)
    end

    test "batch cleanup doesn't affect other resources" do
      {:ok, pid} = NFTex.start_link()

      {:ok, table_id} = NFTex.Port.call(pid, {:table_alloc}, 5000)
      {:ok, batch_id} = NFTex.batch_alloc(pid)

      # Free batch
      :ok = NFTex.batch_free(pid, batch_id)

      # Table should still be valid
      :ok = NFTex.Port.call(pid, {:table_set_str, table_id, :name, "test"}, 5000)

      NFTex.stop(pid)
    end
  end
end
