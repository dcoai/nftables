defmodule NFTex.ChainTest do
  use ExUnit.Case, async: false

  alias NFTex.{Chain, Table}

  setup do
    # Note: These tests require CAP_NET_ADMIN capability
    # Run: sudo setcap cap_net_admin=ep priv/libnf_ex
    {:ok, pid} = NFTex.start_link()

    # Clean up test table if it exists
    Table.delete(pid, "test_chain_table", :inet)

    on_exit(fn ->
      # Cleanup after each test - only if process is still alive
      if Process.alive?(pid) do
        Table.delete(pid, "test_chain_table", :inet)
      end
    end)

    {:ok, pid: pid}
  end

  describe "create/2 base chains" do
    test "creates base chain with filter type and input hook", %{pid: pid} do
      # Setup
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      # Create base chain
      assert :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "test_input",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      })

      # Verify chain exists
      assert Chain.exists?(pid, "test_chain_table", "test_input", :inet)

      # Verify it appears in list
      {:ok, chains} = Chain.list(pid, family: :inet)
      assert Enum.any?(chains, fn c ->
        c.name == "test_input" and c.table == "test_chain_table"
      end)
    end

    test "creates base chain with all hook types", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      hooks = [:prerouting, :input, :forward, :output, :postrouting]

      for hook <- hooks do
        chain_name = "test_#{hook}"

        assert :ok = Chain.create(pid, %{
          table: "test_chain_table",
          name: chain_name,
          family: :inet,
          type: :filter,
          hook: hook,
          priority: 0,
          policy: :accept
        })

        assert Chain.exists?(pid, "test_chain_table", chain_name, :inet)
      end
    end

    test "creates base chain with nat type", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      assert :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "test_nat",
        family: :inet,
        type: :nat,
        hook: :postrouting,
        priority: 100,
        policy: :accept
      })

      assert Chain.exists?(pid, "test_chain_table", "test_nat", :inet)
    end

    test "creates base chain with drop policy", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      assert :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "test_drop",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      })

      assert Chain.exists?(pid, "test_chain_table", "test_drop", :inet)
    end

    test "creates base chain with different priorities", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      priorities = [-300, -100, 0, 100, 300]

      for {priority, idx} <- Enum.with_index(priorities) do
        chain_name = "test_prio_#{idx}"

        assert :ok = Chain.create(pid, %{
          table: "test_chain_table",
          name: chain_name,
          family: :inet,
          type: :filter,
          hook: :input,
          priority: priority,
          policy: :accept
        })

        assert Chain.exists?(pid, "test_chain_table", chain_name, :inet)
      end
    end
  end

  describe "create/2 regular chains" do
    test "creates regular chain without hook", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      assert :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "my_custom_rules",
        family: :inet
      })

      assert Chain.exists?(pid, "test_chain_table", "my_custom_rules", :inet)
    end

    test "creates multiple regular chains in same table", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      assert :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "custom1",
        family: :inet
      })

      assert :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "custom2",
        family: :inet
      })

      assert Chain.exists?(pid, "test_chain_table", "custom1", :inet)
      assert Chain.exists?(pid, "test_chain_table", "custom2", :inet)
    end
  end

  describe "delete/4" do
    test "deletes existing chain", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "temp_chain",
        family: :inet
      })

      assert Chain.exists?(pid, "test_chain_table", "temp_chain", :inet)

      assert :ok = Chain.delete(pid, "test_chain_table", "temp_chain", :inet)

      refute Chain.exists?(pid, "test_chain_table", "temp_chain", :inet)
    end

    test "returns error for non-existent chain", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      assert {:error, _reason} = Chain.delete(pid, "test_chain_table", "nonexistent", :inet)
    end

    test "returns error for chain in non-existent table", %{pid: pid} do
      assert {:error, _reason} = Chain.delete(pid, "nonexistent_table", "some_chain", :inet)
    end
  end

  describe "list/2" do
    test "lists all chains in inet family", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "chain1",
        family: :inet
      })

      :ok = Chain.create(pid, %{
        table: "test_chain_table",
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
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "test_metadata",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      })

      {:ok, chains} = Chain.list(pid, family: :inet)

      test_chain = Enum.find(chains, fn c ->
        c.name == "test_metadata" and c.table == "test_chain_table"
      end)

      assert test_chain != nil
      assert test_chain.name == "test_metadata"
      assert test_chain.table == "test_chain_table"
    end
  end

  describe "exists?/4" do
    test "returns true for existing chain", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "exists_test",
        family: :inet
      })

      assert Chain.exists?(pid, "test_chain_table", "exists_test", :inet)
    end

    test "returns false for non-existent chain", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      refute Chain.exists?(pid, "test_chain_table", "does_not_exist", :inet)
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
    test "sets policy to drop on base chain", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "policy_test",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      })

      # Change policy to drop
      assert :ok = Chain.set_policy(pid, "test_chain_table", "policy_test", :inet, :drop)

      # Note: Verifying the policy would require querying chain details
      # which we can check via list
      {:ok, chains} = Chain.list(pid, family: :inet)
      test_chain = Enum.find(chains, fn c ->
        c.name == "policy_test" and c.table == "test_chain_table"
      end)

      # Policy should be updated (if parser includes it)
      assert test_chain != nil
    end

    test "sets policy to accept on base chain", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "policy_accept",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      })

      # Change policy to accept
      assert :ok = Chain.set_policy(pid, "test_chain_table", "policy_accept", :inet, :accept)
    end

    test "returns error for non-existent chain", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      assert {:error, _reason} = Chain.set_policy(
        pid,
        "test_chain_table",
        "nonexistent",
        :inet,
        :drop
      )
    end
  end

  describe "family support" do
    test "works with inet family", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      assert :ok = Chain.create(pid, %{
        table: "test_chain_table",
        name: "inet_chain",
        family: :inet
      })

      assert Chain.exists?(pid, "test_chain_table", "inet_chain", :inet)
    end

    # Note: inet6 tests would require IPv6 support and appropriate kernel config
    # Skipping for now as we don't know if the test environment has IPv6
  end

  describe "error handling" do
    test "returns error when table doesn't exist", %{pid: pid} do
      assert {:error, _reason} = Chain.create(pid, %{
        table: "nonexistent_table",
        name: "test_chain",
        family: :inet
      })
    end

    test "handles invalid chain names gracefully", %{pid: pid} do
      :ok = Table.create(pid, %{name: "test_chain_table", family: :inet})

      # Empty name should fail
      assert {:error, _reason} = Chain.create(pid, %{
        table: "test_chain_table",
        name: "",
        family: :inet
      })
    end
  end
end
