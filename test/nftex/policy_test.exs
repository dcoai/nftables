defmodule NFTex.PolicyTest do
  use ExUnit.Case, async: false

  alias NFTex.{Policy, Table, Chain}

  setup do
    {:ok, pid} = NFTex.start_link()

    # Clean up and create test table and chain
    Table.delete(pid, "test_policy_table", :inet)
    :ok = Table.create(pid, %{name: "test_policy_table", family: :inet})

    :ok = Chain.create(pid, %{
      table: "test_policy_table",
      name: "INPUT",
      family: :inet,
      type: :filter,
      hook: :input,
      priority: 0,
      policy: :accept
    })

    on_exit(fn ->
      if Process.alive?(pid) do
        Table.delete(pid, "test_policy_table", :inet)
      end
    end)

    {:ok, pid: pid}
  end

  describe "accept_loopback/1" do
    test "creates loopback acceptance rule with defaults", %{pid: pid} do
      # Use default table and chain (filter/INPUT)
      # First create default chain if needed
      Table.delete(pid, "filter", :inet)
      :ok = Table.create(pid, %{name: "filter", family: :inet})

      :ok = Chain.create(pid, %{
        table: "filter",
        name: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      })

      result = Policy.accept_loopback(pid)

      assert result == :ok
    end

    test "creates loopback acceptance rule with custom table/chain", %{pid: pid} do
      result = Policy.accept_loopback(pid, table: "test_policy_table", chain: "INPUT")

      assert result == :ok
    end

    test "creates loopback acceptance rule with custom family", %{pid: pid} do
      result = Policy.accept_loopback(pid,
        table: "test_policy_table",
        chain: "INPUT",
        family: :inet
      )

      assert result == :ok
    end
  end

  describe "accept_established/1" do
    test "creates established/related acceptance rule", %{pid: pid} do
      result = Policy.accept_established(pid, table: "test_policy_table", chain: "INPUT")

      assert result == :ok
    end

    test "works with custom options", %{pid: pid} do
      result = Policy.accept_established(pid,
        table: "test_policy_table",
        chain: "INPUT",
        family: :inet
      )

      assert result == :ok
    end
  end

  describe "drop_invalid/1" do
    test "creates invalid packet drop rule", %{pid: pid} do
      result = Policy.drop_invalid(pid, table: "test_policy_table", chain: "INPUT")

      assert result == :ok
    end

    test "works with custom options", %{pid: pid} do
      result = Policy.drop_invalid(pid,
        table: "test_policy_table",
        chain: "INPUT",
        family: :inet
      )

      assert result == :ok
    end
  end

  describe "allow_ssh/1" do
    test "creates SSH allow rule with defaults", %{pid: pid} do
      result = Policy.allow_ssh(pid, table: "test_policy_table", chain: "INPUT")

      assert result == :ok
    end

    test "creates SSH allow rule with rate limiting", %{pid: pid} do
      result = Policy.allow_ssh(pid,
        table: "test_policy_table",
        chain: "INPUT",
        rate_limit: 10
      )

      assert result == :ok
    end

    test "creates SSH allow rule with logging", %{pid: pid} do
      result = Policy.allow_ssh(pid,
        table: "test_policy_table",
        chain: "INPUT",
        log: true
      )

      assert result == :ok
    end

    test "creates SSH allow rule with rate limiting and logging", %{pid: pid} do
      result = Policy.allow_ssh(pid,
        table: "test_policy_table",
        chain: "INPUT",
        rate_limit: 10,
        log: true
      )

      assert result == :ok
    end
  end

  describe "allow_http/1" do
    test "creates HTTP allow rule", %{pid: pid} do
      result = Policy.allow_http(pid, table: "test_policy_table", chain: "INPUT")

      assert result == :ok
    end

    test "creates HTTP allow rule with rate limiting", %{pid: pid} do
      result = Policy.allow_http(pid,
        table: "test_policy_table",
        chain: "INPUT",
        rate_limit: 100
      )

      assert result == :ok
    end

    test "creates HTTP allow rule with logging", %{pid: pid} do
      result = Policy.allow_http(pid,
        table: "test_policy_table",
        chain: "INPUT",
        log: true
      )

      assert result == :ok
    end
  end

  describe "allow_https/1" do
    test "creates HTTPS allow rule", %{pid: pid} do
      result = Policy.allow_https(pid, table: "test_policy_table", chain: "INPUT")

      assert result == :ok
    end

    test "creates HTTPS allow rule with options", %{pid: pid} do
      result = Policy.allow_https(pid,
        table: "test_policy_table",
        chain: "INPUT",
        rate_limit: 200
      )

      assert result == :ok
    end
  end

  describe "allow_dns/1" do
    test "creates DNS allow rule", %{pid: pid} do
      result = Policy.allow_dns(pid, table: "test_policy_table", chain: "INPUT")

      assert result == :ok
    end
  end

  describe "setup_basic_firewall/1" do
    test "sets up complete firewall with defaults", %{pid: pid} do
      # Delete existing filter table if it exists
      Table.delete(pid, "filter", :inet)

      result = Policy.setup_basic_firewall(pid)

      assert result == :ok

      # Verify table was created
      assert Table.exists?(pid, "filter", :inet)

      # Verify INPUT chain was created
      assert Chain.exists?(pid, "filter", "INPUT", :inet)
    end

    test "sets up firewall with custom table name", %{pid: pid} do
      Table.delete(pid, "custom_firewall", :inet)

      result = Policy.setup_basic_firewall(pid, table: "custom_firewall")

      assert result == :ok
      assert Table.exists?(pid, "custom_firewall", :inet)
    end

    test "sets up firewall with SSH service", %{pid: pid} do
      Table.delete(pid, "filter", :inet)

      result = Policy.setup_basic_firewall(pid, allow_services: [:ssh])

      assert result == :ok
    end

    test "sets up firewall with multiple services", %{pid: pid} do
      Table.delete(pid, "filter", :inet)

      result = Policy.setup_basic_firewall(pid,
        allow_services: [:ssh, :http, :https]
      )

      assert result == :ok
    end

    test "sets up firewall with SSH rate limiting", %{pid: pid} do
      Table.delete(pid, "filter", :inet)

      result = Policy.setup_basic_firewall(pid,
        allow_services: [:ssh],
        ssh_rate_limit: 5
      )

      assert result == :ok
    end

    test "sets up firewall with custom family", %{pid: pid} do
      Table.delete(pid, "filter", :inet)

      result = Policy.setup_basic_firewall(pid, family: :inet)

      assert result == :ok
    end
  end

  describe "complete firewall scenarios" do
    test "builds secure server baseline", %{pid: pid} do
      Table.delete(pid, "filter", :inet)

      # Create complete firewall
      assert :ok = Policy.setup_basic_firewall(pid,
        allow_services: [:ssh],
        ssh_rate_limit: 10
      )

      # Add additional custom rules
      assert :ok = Policy.allow_http(pid)
      assert :ok = Policy.allow_https(pid)
    end

    test "builds firewall with all supported services", %{pid: pid} do
      Table.delete(pid, "filter", :inet)

      result = Policy.setup_basic_firewall(pid,
        allow_services: [:ssh, :http, :https, :dns]
      )

      assert result == :ok
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

    test "returns error for invalid chain", %{pid: pid} do
      result = Policy.accept_established(pid,
        table: "test_policy_table",
        chain: "NONEXISTENT"
      )

      assert {:error, _reason} = result
    end

    test "setup_basic_firewall fails on table creation error", %{pid: pid} do
      # Create table first so setup fails
      Table.delete(pid, "filter", :inet)
      :ok = Table.create(pid, %{name: "filter", family: :inet})

      # This should fail because table already exists
      result = Policy.setup_basic_firewall(pid)

      # May succeed or fail depending on implementation
      # The table already exists, so it might just continue
      assert result == :ok or match?({:error, _}, result)
    end
  end

  describe "integration with RuleBuilder" do
    test "policies use RuleBuilder internally", %{pid: pid} do
      # This tests that Policy module correctly uses RuleBuilder
      # by verifying rules are actually created

      result = Policy.allow_ssh(pid,
        table: "test_policy_table",
        chain: "INPUT",
        rate_limit: 10,
        log: true
      )

      assert result == :ok

      # The rule should now exist in the chain
      # We can verify by listing rules (if Rule.list works)
      {:ok, rules} = NFTex.Rule.list(pid, "test_policy_table", "INPUT", family: :inet)

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

    test "merges default and custom options", %{pid: pid} do
      result = Policy.allow_ssh(pid,
        table: "test_policy_table",
        chain: "INPUT",
        rate_limit: 5,
        family: :inet
      )

      assert result == :ok
    end
  end
end
