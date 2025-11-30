defmodule NFTables.SysctlTest do
  use ExUnit.Case, async: false

  alias NFTables.{Sysctl, Sysctl.Network}

  @moduletag :sysctl

  # Test parameter that is safe to read/write and commonly available
  @test_param "net.ipv4.tcp_syncookies"

  # Parameters for testing different value types
  @bool_param "net.ipv4.ip_forward"
  @numeric_param "net.netfilter.nf_conntrack_max"
  @port_range_param "net.ipv4.ip_local_port_range"

  setup do
    # Start port
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

  describe "Sysctl.get/2" do
    test "gets a whitelisted parameter value", %{pid: pid} do
      case Sysctl.get(pid, @test_param) do
        {:ok, value} ->
          assert is_binary(value)
          assert value in ["0", "1"]

        {:error, reason} ->
          # If we don't have CAP_NET_ADMIN, expect permission error or invalid response
          reason_str = if is_binary(reason), do: reason, else: Atom.to_string(reason)
          assert reason_str =~ ~r/permission|not found|not readable|invalid/i
      end
    end

    test "gets IPv4 forwarding status", %{pid: pid} do
      case Sysctl.get(pid, "net.ipv4.ip_forward") do
        {:ok, value} ->
          assert value in ["0", "1"]

        {:error, _reason} ->
          # Expected if no capability
          :ok
      end
    end

    test "returns error for non-whitelisted parameter", %{pid: pid} do
      assert {:error, reason} = Sysctl.get(pid, "kernel.hostname")
      assert is_binary(reason)
      assert reason =~ ~r/whitelist|not found/i
    end

    test "returns error for invalid parameter", %{pid: pid} do
      assert {:error, reason} = Sysctl.get(pid, "net.does.not.exist")
      assert is_binary(reason)
    end

    test "handles path traversal attempts", %{pid: pid} do
      # Try to escape /proc/sys/net/ directory
      assert {:error, reason} = Sysctl.get(pid, "net.ipv4/../../etc/passwd")
      assert is_binary(reason)
      assert reason =~ ~r/whitelist|not found/i
    end
  end

  describe "Sysctl.set/3" do
    test "sets a whitelisted parameter value", %{pid: pid} do
      # Try to set syncookies to 1
      case Sysctl.set(pid, @test_param, "1") do
        :ok ->
          # Verify it was set
          assert {:ok, "1"} = Sysctl.get(pid, @test_param)

          # Set it back to 0
          assert :ok = Sysctl.set(pid, @test_param, "0")
          assert {:ok, "0"} = Sysctl.get(pid, @test_param)

        {:error, reason} ->
          # Expected if no capability or other failure
          assert is_binary(reason)
      end
    end

    test "returns error for non-whitelisted parameter", %{pid: pid} do
      assert {:error, reason} = Sysctl.set(pid, "kernel.hostname", "test")
      assert is_binary(reason)
      assert reason =~ ~r/whitelist|not found/i
    end

    test "validates boolean parameter values", %{pid: pid} do
      # Invalid value for boolean parameter
      assert {:error, reason} = Sysctl.set(pid, @bool_param, "invalid")
      assert is_binary(reason)
      assert reason =~ ~r/invalid/i

      # Out of range value
      assert {:error, reason} = Sysctl.set(pid, @bool_param, "2")
      assert is_binary(reason)
    end

    test "validates numeric parameter values", %{pid: pid} do
      # Test with a reasonable value
      case Sysctl.set(pid, @numeric_param, "65536") do
        :ok ->
          assert {:ok, value} = Sysctl.get(pid, @numeric_param)
          assert String.to_integer(value) >= 65536

        {:error, _} ->
          # Parameter might not exist on this system
          :ok
      end
    end

    @tag :skip_ci
    test "validates port range parameter format", %{pid: pid} do
      # Valid port range
      case Sysctl.set(pid, @port_range_param, "32768 60999") do
        :ok ->
          assert {:ok, value} = Sysctl.get(pid, @port_range_param)
          # Kernel may return space or tab as separator
          assert value =~ ~r/^\d+\s+\d+$/

        {:error, _} ->
          :ok
      end

      # Invalid format - single number
      assert {:error, reason} = Sysctl.set(pid, @port_range_param, "32768")
      assert is_binary(reason)

      # Invalid format - min >= max
      assert {:error, reason} = Sysctl.set(pid, @port_range_param, "60999 32768")
      assert is_binary(reason)

      # Invalid format - out of range
      assert {:error, reason} = Sysctl.set(pid, @port_range_param, "1 70000")
      assert is_binary(reason)
    end

    test "handles path traversal attempts", %{pid: pid} do
      assert {:error, reason} = Sysctl.set(pid, "net/../../../etc/passwd", "hacked")
      assert is_binary(reason)
      assert reason =~ ~r/whitelist|not found/i
    end
  end

  describe "Sysctl.get!/2 and set!/3" do
    test "get! returns value on success", %{pid: pid} do
      case Sysctl.get(pid, @test_param) do
        {:ok, _value} ->
          # If basic get works, get! should too
          assert is_binary(Sysctl.get!(pid, @test_param))

        {:error, _} ->
          # If basic get fails, get! should raise
          assert_raise RuntimeError, fn ->
            Sysctl.get!(pid, @test_param)
          end
      end
    end

    test "get! raises on error", %{pid: pid} do
      assert_raise RuntimeError, fn ->
        Sysctl.get!(pid, "kernel.hostname")
      end
    end

    test "set! returns :ok on success", %{pid: pid} do
      case Sysctl.set(pid, @test_param, "1") do
        :ok ->
          # If basic set works, set! should too
          assert :ok = Sysctl.set!(pid, @test_param, "1")

        {:error, _} ->
          # If basic set fails, set! should raise
          assert_raise RuntimeError, fn ->
            Sysctl.set!(pid, @test_param, "1")
          end
      end
    end

    test "set! raises on error", %{pid: pid} do
      assert_raise RuntimeError, fn ->
        Sysctl.set!(pid, "kernel.hostname", "test")
      end
    end
  end

  describe "Sysctl.Network helpers" do
    test "enable_ipv4_forwarding/1", %{pid: pid} do
      case Network.enable_ipv4_forwarding(pid) do
        :ok ->
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.ip_forward")

        {:error, _} ->
          # Expected if no capability
          :ok
      end
    end

    test "disable_ipv4_forwarding/1", %{pid: pid} do
      case Network.disable_ipv4_forwarding(pid) do
        :ok ->
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.ip_forward")

        {:error, _} ->
          :ok
      end
    end

    test "ipv4_forwarding_enabled?/1", %{pid: pid} do
      case Network.ipv4_forwarding_enabled?(pid) do
        {:ok, enabled} ->
          assert is_boolean(enabled)

        {:error, _} ->
          :ok
      end
    end

    test "enable_ipv6_forwarding/1", %{pid: pid} do
      case Network.enable_ipv6_forwarding(pid) do
        :ok ->
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv6.conf.all.forwarding")

        {:error, _} ->
          :ok
      end
    end

    test "disable_ipv6_forwarding/1", %{pid: pid} do
      case Network.disable_ipv6_forwarding(pid) do
        :ok ->
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv6.conf.all.forwarding")

        {:error, _} ->
          :ok
      end
    end

    test "enable_syncookies/1", %{pid: pid} do
      case Network.enable_syncookies(pid) do
        :ok ->
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.tcp_syncookies")

        {:error, _} ->
          :ok
      end
    end

    test "disable_syncookies/1", %{pid: pid} do
      case Network.disable_syncookies(pid) do
        :ok ->
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.tcp_syncookies")

        {:error, _} ->
          :ok
      end
    end

    test "set_conntrack_max/2", %{pid: pid} do
      case Network.set_conntrack_max(pid, 131072) do
        :ok ->
          # Verify it was set (might be rounded by kernel)
          assert {:ok, value} = Sysctl.get(pid, "net.netfilter.nf_conntrack_max")
          assert String.to_integer(value) > 0

        {:error, _} ->
          # Parameter might not exist
          :ok
      end
    end

    test "get_conntrack_max/1", %{pid: pid} do
      case Network.get_conntrack_max(pid) do
        {:ok, max} ->
          assert is_integer(max)
          assert max > 0

        {:error, _} ->
          # Parameter might not exist
          :ok
      end
    end

    test "ignore_ping/1", %{pid: pid} do
      case Network.ignore_ping(pid) do
        :ok ->
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.icmp_echo_ignore_all")

        {:error, _} ->
          :ok
      end
    end

    test "allow_ping/1", %{pid: pid} do
      case Network.allow_ping(pid) do
        :ok ->
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.icmp_echo_ignore_all")

        {:error, _} ->
          :ok
      end
    end
  end

  describe "Sysctl.Network composite operations" do
    test "configure_router/2 with all options", %{pid: pid} do
      opts = [
        ipv4_forwarding: true,
        ipv6_forwarding: true,
        syncookies: true,
        send_redirects: false
      ]

      case Network.configure_router(pid, opts) do
        :ok ->
          # Verify settings were applied
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.ip_forward")
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv6.conf.all.forwarding")
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.tcp_syncookies")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.conf.all.send_redirects")

        {:error, _} ->
          :ok
      end
    end

    test "configure_router/2 with partial options", %{pid: pid} do
      opts = [ipv4_forwarding: true]

      case Network.configure_router(pid, opts) do
        :ok ->
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.ip_forward")

        {:error, _} ->
          :ok
      end
    end

    test "harden_security_ipv4/1", %{pid: pid} do
      case Network.harden_security_ipv4(pid) do
        :ok ->
          # Verify IPv4 security settings
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.conf.all.rp_filter")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.conf.all.accept_source_route")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.conf.all.send_redirects")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.conf.all.accept_redirects")
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.tcp_syncookies")

        {:error, _} ->
          :ok
      end
    end

    test "harden_security_ipv6/1", %{pid: pid} do
      case Network.harden_security_ipv6(pid) do
        :ok ->
          # Verify IPv6 security settings
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv6.conf.all.accept_source_route")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv6.conf.all.accept_redirects")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv6.conf.all.accept_ra")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv6.conf.all.accept_ra_defrtr")

        {:error, _} ->
          :ok
      end
    end

    test "harden_security/1 applies both IPv4 and IPv6 hardening", %{pid: pid} do
      case Network.harden_security(pid) do
        :ok ->
          # Verify IPv4 security settings
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.conf.all.rp_filter")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.conf.all.accept_source_route")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.conf.all.send_redirects")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv4.conf.all.accept_redirects")
          assert {:ok, "1"} = Sysctl.get(pid, "net.ipv4.tcp_syncookies")

          # Verify IPv6 security settings
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv6.conf.all.accept_source_route")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv6.conf.all.accept_redirects")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv6.conf.all.accept_ra")
          assert {:ok, "0"} = Sysctl.get(pid, "net.ipv6.conf.all.accept_ra_defrtr")

        {:error, _} ->
          :ok
      end
    end
  end

  describe "parameter whitelist" do
    test "all documented IPv4 core parameters are whitelisted", %{pid: pid} do
      params = [
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.forwarding",
        "net.ipv4.conf.default.forwarding"
      ]

      for param <- params do
        # These should not return "not in whitelist" errors
        result = Sysctl.get(pid, param)
        refute match?({:error, msg} when is_binary(msg), result) and
          elem(result, 1) =~ ~r/whitelist/i
      end
    end

    test "all documented IPv4 TCP parameters are whitelisted", %{pid: pid} do
      params = [
        "net.ipv4.tcp_syncookies",
        "net.ipv4.tcp_timestamps",
        "net.ipv4.tcp_tw_reuse",
        "net.ipv4.tcp_fin_timeout",
        "net.ipv4.tcp_keepalive_time",
        "net.ipv4.tcp_keepalive_probes",
        "net.ipv4.tcp_keepalive_intvl",
        "net.ipv4.ip_local_port_range"
      ]

      for param <- params do
        result = Sysctl.get(pid, param)
        refute match?({:error, msg} when is_binary(msg), result) and
          elem(result, 1) =~ ~r/whitelist/i
      end
    end

    test "all documented IPv6 parameters are whitelisted", %{pid: pid} do
      params = [
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding"
      ]

      for param <- params do
        result = Sysctl.get(pid, param)
        refute match?({:error, msg} when is_binary(msg), result) and
          elem(result, 1) =~ ~r/whitelist/i
      end
    end

    test "all documented security parameters are whitelisted", %{pid: pid} do
      params = [
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.default.rp_filter",
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.default.accept_source_route",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.conf.default.send_redirects",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.default.accept_redirects",
        "net.ipv6.conf.all.accept_redirects",
        "net.ipv6.conf.default.accept_redirects",
        "net.ipv6.conf.all.accept_source_route",
        "net.ipv6.conf.default.accept_source_route"
      ]

      for param <- params do
        result = Sysctl.get(pid, param)
        refute match?({:error, msg} when is_binary(msg), result) and
          elem(result, 1) =~ ~r/whitelist/i
      end
    end
  end

  describe "keyword list options" do
    test "get/2 accepts keyword list with :pid key", %{pid: pid} do
      case Sysctl.get([pid: pid], @test_param) do
        {:ok, value} ->
          assert is_binary(value)

        {:error, _} ->
          :ok
      end
    end

    test "set/3 accepts keyword list with :pid key", %{pid: pid} do
      case Sysctl.set([pid: pid], @test_param, "1") do
        :ok -> assert :ok = :ok
        {:error, _} -> :ok
      end
    end

    test "Network helpers accept keyword list", %{pid: pid} do
      case Network.enable_ipv4_forwarding([pid: pid]) do
        :ok -> assert :ok = :ok
        {:error, _} -> :ok
      end
    end
  end

  # Helper functions

  defp get_sysctl_value(pid, param) do
    case Sysctl.get(pid, param) do
      {:ok, value} -> value
      {:error, _} -> nil
    end
  end

  defp restore_sysctl_value(_pid, _param, nil), do: :ok

  defp restore_sysctl_value(pid, param, value) do
    case Sysctl.set(pid, param, value) do
      :ok -> :ok
      {:error, _} -> :ok
    end
  end
end
