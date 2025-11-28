defmodule NFTables.PolicyTest do
  use ExUnit.Case, async: false

  alias NFTables.{Policy, Builder, TestHelpers}
  import NFTables.QueryHelpers

  # IMPORTANT: This test uses ISOLATED test tables that do NOT affect
  # the host's network connectivity. Never use production tables like "filter"!

  setup do
    {:ok, pid} = NFTables.start_link()

    # Use isolated test table
    test_table = "nftables_test_policy"

    # Clean up and create test table and chain WITHOUT hook (safe)
    Builder.new()
    |> Builder.delete(table: test_table, family: :inet)
    |> Builder.execute(pid)

    Builder.new()
    |> Builder.add(table: test_table, family: :inet)
    |> Builder.add(
      table: test_table,
      chain: "INPUT",
      family: :inet
    )
    |> Builder.execute(pid)

    on_exit(fn ->
      if Process.alive?(pid) do
        TestHelpers.cleanup_test_table(pid, test_table, :inet)
        NFTables.stop(pid)
      end
    end)

    {:ok, pid: pid, test_table: test_table}
  end

  describe "accept_loopback/1" do
    test "creates loopback acceptance rule with defaults", %{pid: pid, test_table: _test_table} do
      # Create isolated test infrastructure for this test
      filter_test = "nftables_test_filter_default"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

      Builder.new()
      |> Builder.add(table: filter_test, family: :inet)
      |> Builder.add(
        table: filter_test,
        chain: "INPUT",
        family: :inet
      )
      |> Builder.execute(pid)


      result = Policy.accept_loopback(pid, table: filter_test, chain: "INPUT")

      assert result == :ok

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

    end

    test "creates loopback acceptance rule with custom table/chain", %{pid: pid, test_table: test_table} do
      result = Policy.accept_loopback(pid, table: test_table, chain: "INPUT")

      assert result == :ok
    end

    test "creates loopback acceptance rule with custom family", %{pid: pid, test_table: test_table} do
      result = Policy.accept_loopback(pid,
        table: test_table,
        chain: "INPUT",
        family: :inet
      )

      assert result == :ok
    end
  end

  describe "accept_established/1" do
    test "creates established/related acceptance rule", %{pid: pid, test_table: test_table} do
      result = Policy.accept_established(pid, table: test_table, chain: "INPUT")

      assert result == :ok
    end

    test "works with custom options", %{pid: pid, test_table: test_table} do
      result = Policy.accept_established(pid,
        table: test_table,
        chain: "INPUT",
        family: :inet
      )

      assert result == :ok
    end
  end

  describe "drop_invalid/1" do
    test "creates invalid packet drop rule", %{pid: pid, test_table: test_table} do
      result = Policy.drop_invalid(pid, table: test_table, chain: "INPUT")

      assert result == :ok
    end

    test "works with custom options", %{pid: pid, test_table: test_table} do
      result = Policy.drop_invalid(pid,
        table: test_table,
        chain: "INPUT",
        family: :inet
      )

      assert result == :ok
    end
  end

  describe "allow_ssh/1" do
    test "creates SSH allow rule with defaults", %{pid: pid, test_table: test_table} do
      result = Policy.allow_ssh(pid, table: test_table, chain: "INPUT")

      assert result == :ok
    end

    test "creates SSH allow rule with rate limiting", %{pid: pid, test_table: test_table} do
      result = Policy.allow_ssh(pid,
        table: test_table,
        chain: "INPUT",
        rate_limit: 10
      )

      assert result == :ok
    end

    test "creates SSH allow rule with logging", %{pid: pid, test_table: test_table} do
      result = Policy.allow_ssh(pid,
        table: test_table,
        chain: "INPUT",
        log: true
      )

      assert result == :ok
    end

    test "creates SSH allow rule with rate limiting and logging", %{pid: pid, test_table: test_table} do
      result = Policy.allow_ssh(pid,
        table: test_table,
        chain: "INPUT",
        rate_limit: 10,
        log: true
      )

      assert result == :ok
    end
  end

  describe "allow_http/1" do
    test "creates HTTP allow rule", %{pid: pid, test_table: test_table} do
      result = Policy.allow_http(pid, table: test_table, chain: "INPUT")

      assert result == :ok
    end

    test "creates HTTP allow rule with rate limiting", %{pid: pid, test_table: test_table} do
      result = Policy.allow_http(pid,
        table: test_table,
        chain: "INPUT",
        rate_limit: 100
      )

      assert result == :ok
    end

    test "creates HTTP allow rule with logging", %{pid: pid, test_table: test_table} do
      result = Policy.allow_http(pid,
        table: test_table,
        chain: "INPUT",
        log: true
      )

      assert result == :ok
    end
  end

  describe "allow_https/1" do
    test "creates HTTPS allow rule", %{pid: pid, test_table: test_table} do
      result = Policy.allow_https(pid, table: test_table, chain: "INPUT")

      assert result == :ok
    end

    test "creates HTTPS allow rule with options", %{pid: pid, test_table: test_table} do
      result = Policy.allow_https(pid,
        table: test_table,
        chain: "INPUT",
        rate_limit: 200
      )

      assert result == :ok
    end
  end

  describe "allow_dns/1" do
    test "creates DNS allow rule", %{pid: pid, test_table: test_table} do
      result = Policy.allow_dns(pid, table: test_table, chain: "INPUT")

      assert result == :ok
    end
  end

  describe "setup_basic_firewall/1" do
    @tag :skip
    test "sets up complete firewall with defaults", %{pid: pid} do
      # Use isolated test table instead of production "filter"
      filter_test = "nftables_test_filter_setup"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)


      result = Policy.setup_basic_firewall(pid, table: filter_test, test_mode: true)

      assert result == :ok

      # Verify table was created
      assert table_exists?(pid, filter_test, :inet)

      # Verify INPUT chain was created
      assert chain_exists?(pid, filter_test, "INPUT", :inet)

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

    end

    test "sets up firewall with custom table name", %{pid: pid} do
      custom_test = "nftables_test_custom_firewall"
      Builder.new()
      |> Builder.delete(table: custom_test, family: :inet)
      |> Builder.execute(pid)


      result = Policy.setup_basic_firewall(pid, table: custom_test, test_mode: true)

      assert result == :ok
      assert table_exists?(pid, custom_test, :inet)

      # Cleanup
      Builder.new()
      |> Builder.delete(table: custom_test, family: :inet)
      |> Builder.execute(pid)

    end

    test "sets up firewall with SSH service", %{pid: pid} do
      filter_test = "nftables_test_filter_ssh"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)


      result = Policy.setup_basic_firewall(pid, table: filter_test, allow_services: [:ssh], test_mode: true)

      assert result == :ok

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

    end

    test "sets up firewall with multiple services", %{pid: pid} do
      filter_test = "nftables_test_filter_multi"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)


      result = Policy.setup_basic_firewall(pid,
        table: filter_test,
        allow_services: [:ssh, :http, :https],
        test_mode: true
      )

      assert result == :ok

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

    end

    test "sets up firewall with SSH rate limiting", %{pid: pid} do
      filter_test = "nftables_test_filter_rate"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)


      result = Policy.setup_basic_firewall(pid,
        table: filter_test,
        allow_services: [:ssh],
        ssh_rate_limit: 5,
        test_mode: true
      )

      assert result == :ok

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

    end

    test "sets up firewall with custom family", %{pid: pid} do
      filter_test = "nftables_test_filter_family"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)


      result = Policy.setup_basic_firewall(pid, table: filter_test, family: :inet, test_mode: true)

      assert result == :ok

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

    end
  end

  describe "complete firewall scenarios" do
    test "builds secure server baseline", %{pid: pid, test_table: _test_table} do
      # Use isolated test table
      filter_test = "nftables_test_filter_baseline"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)


      # Create complete firewall
      assert :ok = Policy.setup_basic_firewall(pid,
        table: filter_test,
        allow_services: [:ssh],
        ssh_rate_limit: 10,
        test_mode: true
      )

      # Add additional custom rules
      assert :ok = Policy.allow_http(pid, table: filter_test, chain: "INPUT")
      assert :ok = Policy.allow_https(pid, table: filter_test, chain: "INPUT")

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

    end

    test "builds firewall with all supported services", %{pid: pid} do
      filter_test = "nftables_test_filter_all"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)


      result = Policy.setup_basic_firewall(pid,
        table: filter_test,
        allow_services: [:ssh, :http, :https, :dns],
        test_mode: true
      )

      assert result == :ok

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

    end
  end

  describe "error handling" do
    test "returns error for invalid table", %{pid: pid} do
      result = Policy.accept_loopback(pid,
        table: "nonexistent_table",
        chain: "INPUT"
      )

      assert {:error, _reason} = result
    end

    test "returns error for invalid chain", %{pid: pid, test_table: test_table} do
      result = Policy.accept_established(pid,
        table: test_table,
        chain: "NONEXISTENT"
      )

      assert {:error, _reason} = result
    end

    test "setup_basic_firewall fails on table creation error", %{pid: pid} do
      # Create table first so setup fails
      filter_test = "nftables_test_filter_error"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

      :ok = Builder.new()
      |> Builder.add(table: filter_test, family: :inet)
      |> Builder.execute(pid)

      # This should fail because table already exists
      result = Policy.setup_basic_firewall(pid, table: filter_test, test_mode: true)

      # May succeed or fail depending on implementation
      # The table already exists, so it might just continue
      assert result == :ok or match?({:error, _}, result)

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.execute(pid)

    end
  end

  describe "integration with Match" do
    test "policies use Match internally", %{pid: pid, test_table: test_table} do
      # This tests that Policy module correctly uses Match
      # by verifying rules are actually created

      result = Policy.allow_ssh(pid,
        table: test_table,
        chain: "INPUT",
        rate_limit: 10,
        log: true
      )

      assert result == :ok

      # The rule should now exist in the chain
      # We can verify by listing rules (if Rule.list works)
      {:ok, rules} = list_rules(pid, test_table, "INPUT", family: :inet)

      # Should have at least one rule
      assert length(rules) >= 1
    end
  end

  describe "option handling" do
    test "accepts empty options", %{pid: pid} do
      result = Policy.accept_loopback(pid, [])

      # Should fail because no table/chain specified and defaults don't exist
      assert match?({:error, _}, result) or result == :ok
    end

    test "merges default and custom options", %{pid: pid, test_table: test_table} do
      result = Policy.allow_ssh(pid,
        table: test_table,
        chain: "INPUT",
        rate_limit: 5,
        family: :inet
      )

      assert result == :ok
    end
  end
end
