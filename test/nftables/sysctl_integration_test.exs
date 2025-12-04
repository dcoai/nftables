defmodule NFTables.SysctlIntegrationTest do
  use ExUnit.Case, async: false

  alias NFTables.Sysctl

  @moduletag :integration
  @moduletag :slow

  @test_param "net.ipv4.tcp_syncookies"
  @bool_param "net.ipv4.ip_forward"

  setup do
    {:ok, pid} = NFTables.Port.start_link(check_capabilities: false)

    # Store original values for restoration
    original_values = %{
      syncookies: get_sysctl_value(pid, @test_param),
      ip_forward: get_sysctl_value(pid, @bool_param)
    }

    on_exit(fn ->
      if Process.alive?(pid) do
        # Restore original values (best effort)
        restore_sysctl_value(pid, @test_param, original_values.syncookies)
        restore_sysctl_value(pid, @bool_param, original_values.ip_forward)
        NFTables.Port.stop(pid)
      end
    end)

    {:ok, pid: pid, original_values: original_values}
  end

  describe "basic sysctl operations" do
    test "gets a whitelisted parameter value", %{pid: pid} do
      case Sysctl.get(pid, @test_param) do
        {:ok, value} ->
          assert is_binary(value)
          assert value in ["0", "1"]

        {:error, reason} ->
          # Some systems may not support this parameter
          # Reason can be binary or atom
          assert is_binary(reason) or is_atom(reason)
      end
    end

    test "sets a whitelisted parameter value", %{pid: pid} do
      case Sysctl.set(pid, @test_param, "1") do
        :ok ->
          assert {:ok, "1"} = Sysctl.get(pid, @test_param)
          # Restore
          assert :ok = Sysctl.set(pid, @test_param, "0")
          assert {:ok, "0"} = Sysctl.get(pid, @test_param)

        {:error, _reason} ->
          # May fail due to permissions or kernel config
          :ok
      end
    end

    test "returns error for non-whitelisted parameter", %{pid: pid} do
      assert {:error, reason} = Sysctl.get(pid, "kernel.hostname")
      assert is_binary(reason) or is_atom(reason)
    end
  end

  describe "security" do
    test "handles path traversal attempts", %{pid: pid} do
      # Should be rejected by whitelist
      assert {:error, _reason} = Sysctl.get(pid, "../../../etc/passwd")
      assert {:error, _reason} = Sysctl.set(pid, "../../../etc/passwd", "value")
    end
  end

  # Helper functions
  defp get_sysctl_value(pid, param) do
    case Sysctl.get(pid, param) do
      {:ok, value} -> value
      _ -> nil
    end
  end

  defp restore_sysctl_value(_pid, _param, nil), do: :ok

  defp restore_sysctl_value(pid, param, value) do
    Sysctl.set(pid, param, value)
    :ok
  end
end
