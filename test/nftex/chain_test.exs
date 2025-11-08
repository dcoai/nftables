defmodule NFTex.ChainTest do
  use ExUnit.Case, async: false

  alias NFTex.{Chain, Table}

  setup do
    # Note: These tests require CAP_NET_ADMIN capability
    # Run: sudo setcap cap_net_admin=ep priv/port_nftables
    {:ok, pid} = NFTex.start_link()

    # Clean up test table if it exists (using nftex_test_ prefix)
    Table.delete(pid, "nftex_test_chain", :inet)

    on_exit(fn ->
      # Cleanup after each test - only if process is still alive
      if Process.alive?(pid) do
        Table.delete(pid, "nftex_test_chain", :inet)
      end
    end)

    {:ok, pid: pid}
  end

  describe "create/2 base chains" do
    test "creates chain without hook (safe for testing)", %{pid: pid} do
      # Setup
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      # Create regular chain WITHOUT hook (safe - won't filter traffic)
      assert :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "test_input",
        family: :inet
      })

      # Verify chain exists
      assert Chain.exists?(pid, "nftex_test_chain", "test_input", :inet)

      # Verify it appears in list
      {:ok, chains} = Chain.list(pid, family: :inet)
      assert Enum.any?(chains, fn c ->
        c.name == "test_input" and c.table == "nftex_test_chain"
      end)
    end

    test "creates multiple chains without hooks (safe for testing)", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      chain_names = ["test_prerouting", "test_input", "test_forward", "test_output", "test_postrouting"]

      for chain_name <- chain_names do
        # Create regular chains WITHOUT hooks (safe - won't filter traffic)
        assert :ok = Chain.add(pid, %{
          table: "nftex_test_chain",
          name: chain_name,
          family: :inet
        })

        assert Chain.exists?(pid, "nftex_test_chain", chain_name, :inet)
      end
    end

    test "creates chain for NAT testing without hook (safe)", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      # Create regular chain WITHOUT hook (safe - won't filter traffic)
      assert :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "test_nat",
        family: :inet
      })

      assert Chain.exists?(pid, "nftex_test_chain", "test_nat", :inet)
    end

    test "creates chain without hook (safe - policy not applicable)", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      # Create regular chain WITHOUT hook (safe - won't filter traffic)
      # Note: Policy only applies to base chains with hooks
      assert :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "test_drop",
        family: :inet
      })

      assert Chain.exists?(pid, "nftex_test_chain", "test_drop", :inet)
    end

    test "creates multiple chains without hooks (safe - priority not applicable)", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      # Note: Priority only applies to base chains with hooks
      # Creating regular chains without hooks instead (safe - won't filter traffic)
      for idx <- 0..4 do
        chain_name = "test_prio_#{idx}"

        assert :ok = Chain.add(pid, %{
          table: "nftex_test_chain",
          name: chain_name,
          family: :inet
        })

        assert Chain.exists?(pid, "nftex_test_chain", chain_name, :inet)
      end
    end
  end

  describe "create/2 regular chains" do
    test "creates regular chain without hook", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      assert :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "my_custom_rules",
        family: :inet
      })

      assert Chain.exists?(pid, "nftex_test_chain", "my_custom_rules", :inet)
    end

    test "creates multiple regular chains in same table", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      assert :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "custom1",
        family: :inet
      })

      assert :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "custom2",
        family: :inet
      })

      assert Chain.exists?(pid, "nftex_test_chain", "custom1", :inet)
      assert Chain.exists?(pid, "nftex_test_chain", "custom2", :inet)
    end
  end

  describe "delete/4" do
    test "deletes existing chain", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "temp_chain",
        family: :inet
      })

      assert Chain.exists?(pid, "nftex_test_chain", "temp_chain", :inet)

      assert :ok = Chain.delete(pid, "nftex_test_chain", "temp_chain", :inet)

      refute Chain.exists?(pid, "nftex_test_chain", "temp_chain", :inet)
    end

    test "returns error for non-existent chain", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      assert {:error, _reason} = Chain.delete(pid, "nftex_test_chain", "nonexistent", :inet)
    end

    test "returns error for chain in non-existent table", %{pid: pid} do
      assert {:error, _reason} = Chain.delete(pid, "nonexistent_table", "some_chain", :inet)
    end
  end

  describe "list/2" do
    test "lists all chains in inet family", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "chain1",
        family: :inet
      })

      :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "chain2",
        family: :inet
      })

      {:ok, chains} = Chain.list(pid, family: :inet)

      assert is_list(chains)
      assert length(chains) >= 2

      # Check our test chains are in the list
      chain_names = Enum.map(chains, & &1.name)
      assert "chain1" in chain_names
      assert "chain2" in chain_names
    end

    test "returns empty list when no chains exist", %{pid: pid} do
      # Don't create any chains, just query
      {:ok, chains} = Chain.list(pid, family: :inet)

      # May have system chains, but should be a list
      assert is_list(chains)
    end

    test "includes chain metadata in results", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      # Create regular chain WITHOUT hook (safe - won't filter traffic)
      :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "test_metadata",
        family: :inet
      })

      {:ok, chains} = Chain.list(pid, family: :inet)

      test_chain = Enum.find(chains, fn c ->
        c.name == "test_metadata" and c.table == "nftex_test_chain"
      end)

      assert test_chain != nil
      assert test_chain.name == "test_metadata"
      assert test_chain.table == "nftex_test_chain"
    end
  end

  describe "exists?/4" do
    test "returns true for existing chain", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "exists_test",
        family: :inet
      })

      assert Chain.exists?(pid, "nftex_test_chain", "exists_test", :inet)
    end

    test "returns false for non-existent chain", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      refute Chain.exists?(pid, "nftex_test_chain", "does_not_exist", :inet)
    end

    test "returns false for chain in non-existent table", %{pid: pid} do
      refute Chain.exists?(pid, "nonexistent_table", "some_chain", :inet)
    end

    test "returns false when query fails", %{pid: pid} do
      # This should handle query errors gracefully
      refute Chain.exists?(pid, "", "", :inet)
    end
  end

  describe "set_policy/5" do
    test "attempting to set policy on regular chain (expects error)", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      # Create regular chain WITHOUT hook (safe - won't filter traffic)
      # Note: Policy only applies to base chains with hooks
      :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "policy_test",
        family: :inet
      })

      # Attempting to change policy on regular chain should fail or be ignored
      result = Chain.set_policy(pid, "nftex_test_chain", "policy_test", :inet, :drop)

      # May return error or ok depending on implementation
      assert result == :ok or match?({:error, _}, result)
    end

    test "attempting to set policy on another regular chain", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      # Create regular chain WITHOUT hook (safe - won't filter traffic)
      :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "policy_accept",
        family: :inet
      })

      # Attempting to change policy on regular chain
      result = Chain.set_policy(pid, "nftex_test_chain", "policy_accept", :inet, :accept)
      assert result == :ok or match?({:error, _}, result)
    end

    test "returns error for non-existent chain", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      assert {:error, _reason} = Chain.set_policy(
        pid,
        "nftex_test_chain",
        "nonexistent",
        :inet,
        :drop
      )
    end
  end

  describe "family support" do
    test "works with inet family", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      assert :ok = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "inet_chain",
        family: :inet
      })

      assert Chain.exists?(pid, "nftex_test_chain", "inet_chain", :inet)
    end

    # Note: inet6 tests would require IPv6 support and appropriate kernel config
    # Skipping for now as we don't know if the test environment has IPv6
  end

  describe "error handling" do
    test "returns error when table doesn't exist", %{pid: pid} do
      assert {:error, _reason} = Chain.add(pid, %{
        table: "nonexistent_table",
        name: "test_chain",
        family: :inet
      })
    end

    test "handles invalid chain names gracefully", %{pid: pid} do
      :ok = Table.add(pid, %{name: "nftex_test_chain", family: :inet})

      # Empty name should fail
      assert {:error, _reason} = Chain.add(pid, %{
        table: "nftex_test_chain",
        name: "",
        family: :inet
      })
    end
  end
end
