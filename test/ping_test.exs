Code.require_file("test_helper.exs", __DIR__)

defmodule PingTest do
  use ExUnit.Case
  require Logger

  @moduletag :integration

  describe "NFTex basic communication" do
    test "ping/pong works" do
      {:ok, pid} = NFTex.start_link()

      # Send a ping command
      result = NFTex.Port.call(pid, {:ping}, 5000)

      assert result == :ok

      NFTex.stop(pid)
    end

    test "unknown command returns error" do
      {:ok, pid} = NFTex.start_link()

      # Send an unknown command
      result = NFTex.Port.call(pid, {:unknown_command}, 5000)

      assert {:error, error_msg} = result
      assert error_msg =~ "unknown_command"

      NFTex.stop(pid)
    end

    test "table_alloc returns resource ID" do
      {:ok, pid} = NFTex.start_link()

      # Try to allocate a table (will be stub implementation for now)
      result = NFTex.Port.call(pid, {:table_alloc}, 5000)

      assert {:ok, resource_id} = result
      assert is_integer(resource_id)

      NFTex.stop(pid)
    end
  end
end
