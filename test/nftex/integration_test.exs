defmodule NFTex.IntegrationTest do
  use ExUnit.Case, async: false

  alias NFTex.{Table, Chain, RuleBuilder, Policy, TestHelpers}

  # IMPORTANT: This test uses ISOLATED test tables that do NOT affect
  # the host's network connectivity. All tables are prefixed with "nftex_test_"
  # and chains without hooks are used when possible to prevent traffic filtering.

  setup do
    {:ok, pid} = NFTex.start_link()

    # Use isolated test tables
    test_table = "nftex_test_integration"
    filter_test_table = "nftex_test_filter"
    nat_test_table = "nftex_test_nat"

    # Cleanup any leftover tables from previous test runs
    Table.delete(pid, test_table, :inet)
    Table.delete(pid, filter_test_table, :inet)
    Table.delete(pid, nat_test_table, :inet)

    on_exit(fn ->
      if Process.alive?(pid) do
        TestHelpers.cleanup_test_table(pid, test_table, :inet)
        TestHelpers.cleanup_test_table(pid, filter_test_table, :inet)
        TestHelpers.cleanup_test_table(pid, nat_test_table, :inet)
        NFTex.stop(pid)
      end
    end)

    {:ok, pid: pid, test_table: test_table, filter_test_table: filter_test_table, nat_test_table: nat_test_table}
  end

  describe "complete firewall setup" do
    test "builds secure server with Chain + RuleBuilder + Policy", %{pid: pid, test_table: test_table} do
      # Step 1: Create table
      assert :ok = Table.create(pid, %{name: test_table, family: :inet})

      # Step 2: Create INPUT chain WITHOUT hook (safe - won't filter real traffic)
      # Using a regular chain instead of hooked chain for safety
      assert :ok = Chain.create(pid, %{
        table: test_table,
        name: "INPUT",
        family: :inet
      })

      # Step 3: Apply common policies
      assert :ok = Policy.accept_loopback(pid,
        table: test_table,
        chain: "INPUT"
      )

      assert :ok = Policy.accept_established(pid,
        table: test_table,
        chain: "INPUT"
      )

      assert :ok = Policy.drop_invalid(pid,
        table: test_table,
        chain: "INPUT"
      )

      # Step 4: Add service-specific rules
      assert :ok = Policy.allow_ssh(pid,
        table: test_table,
        chain: "INPUT",
        rate_limit: 10
      )

      # Step 5: Add custom rule with RuleBuilder
      assert :ok =
        RuleBuilder.new(pid, test_table, "INPUT")
        |> RuleBuilder.match_dest_port(8080)
        |> RuleBuilder.rate_limit(100, :second)
        |> RuleBuilder.counter()
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      # Verify chain exists and has rules
      assert Chain.exists?(pid, test_table, "INPUT", :inet)

      {:ok, rules} = NFTex.Rule.list(pid, test_table, "INPUT", family: :inet)
      assert length(rules) >= 5
    end

    test "uses Policy.setup_basic_firewall for quick setup", %{pid: pid, filter_test_table: filter_test_table} do
      # Use isolated test table instead of production "filter" table
      Table.delete(pid, filter_test_table, :inet)

      # One-line complete firewall using test table (test_mode prevents hooks)
      assert :ok = Policy.setup_basic_firewall(pid,
        table: filter_test_table,
        allow_services: [:ssh, :http, :https],
        ssh_rate_limit: 10,
        test_mode: true
      )

      # Verify it's all set up
      assert Table.exists?(pid, filter_test_table, :inet)
      assert Chain.exists?(pid, filter_test_table, "INPUT", :inet)

      {:ok, rules} = NFTex.Rule.list(pid, filter_test_table, "INPUT", family: :inet)
      # Should have loopback, established, invalid drop, and 3 services
      assert length(rules) >= 6
    end
  end

  describe "NAT gateway scenario" do
    test "sets up masquerading and port forwarding", %{pid: pid, nat_test_table: nat_test_table} do
      # Use isolated test NAT table
      Table.delete(pid, nat_test_table, :inet)

      # Step 1: Create NAT table (isolated test table)
      assert :ok = Table.create(pid, %{name: nat_test_table, family: :inet})

      # Step 2: Create POSTROUTING chain WITHOUT hook (safe)
      # Using regular chains instead of hooked chains for safety
      assert :ok = Chain.create(pid, %{
        table: nat_test_table,
        name: "POSTROUTING",
        family: :inet
      })

      # Step 3: Create PREROUTING chain WITHOUT hook (safe)
      assert :ok = Chain.create(pid, %{
        table: nat_test_table,
        name: "PREROUTING",
        family: :inet
      })

      # Step 4: Add masquerade rule for outgoing interface
      assert :ok =
        RuleBuilder.new(pid, nat_test_table, "POSTROUTING")
        |> RuleBuilder.match_oif("eth0")
        |> RuleBuilder.commit()
      # Note: Would add masquerade expression if it was exposed in RuleBuilder

      # Step 5: Add port forwarding rule (DNAT)
      # This would use NAT expressions which we have in ExpressionBuilder
      # but not yet in RuleBuilder

      # Verify setup
      assert Chain.exists?(pid, nat_test_table, "POSTROUTING", :inet)
      assert Chain.exists?(pid, nat_test_table, "PREROUTING", :inet)
    end
  end

  describe "rate limiting scenario" do
    test "applies rate limits to multiple services", %{pid: pid, test_table: test_table} do
      :ok = Table.create(pid, %{name: test_table, family: :inet})

      # Create regular chain WITHOUT hook (safe)
      :ok = Chain.create(pid, %{
        table: test_table,
        name: "INPUT",
        family: :inet
      })

      # SSH with strict rate limit
      assert :ok = Policy.allow_ssh(pid,
        table: test_table,
        chain: "INPUT",
        rate_limit: 5
      )

      # HTTP with higher rate limit
      assert :ok = Policy.allow_http(pid,
        table: test_table,
        chain: "INPUT",
        rate_limit: 100
      )

      # Custom service with burst
      assert :ok =
        RuleBuilder.new(pid, test_table, "INPUT")
        |> RuleBuilder.match_dest_port(9000)
        |> RuleBuilder.rate_limit(50, :second, burst: 100)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      {:ok, rules} = NFTex.Rule.list(pid, test_table, "INPUT", family: :inet)
      assert length(rules) >= 3
    end
  end

  describe "logging scenario" do
    test "adds logging to multiple rules", %{pid: pid, test_table: test_table} do
      :ok = Table.create(pid, %{name: test_table, family: :inet})

      # Create regular chain WITHOUT hook (safe)
      :ok = Chain.create(pid, %{
        table: test_table,
        name: "INPUT",
        family: :inet
      })

      # SSH with logging
      assert :ok = Policy.allow_ssh(pid,
        table: test_table,
        chain: "INPUT",
        log: true
      )

      # Block specific IP with logging
      assert :ok =
        RuleBuilder.new(pid, test_table, "INPUT")
        |> RuleBuilder.match_source_ip(<<192, 168, 1, 100>>)
        |> RuleBuilder.log("BLOCKED-IP: ")
        |> RuleBuilder.drop()
        |> RuleBuilder.commit()

      # Log all dropped packets (at end of chain)
      assert :ok =
        RuleBuilder.new(pid, test_table, "INPUT")
        |> RuleBuilder.log("DROP-DEFAULT: ")
        |> RuleBuilder.commit()

      {:ok, rules} = NFTex.Rule.list(pid, test_table, "INPUT", family: :inet)
      assert length(rules) >= 3
    end
  end

  describe "multiple chains in same table" do
    test "creates and uses multiple chains", %{pid: pid, test_table: test_table} do
      :ok = Table.create(pid, %{name: test_table, family: :inet})

      # Create INPUT chain WITHOUT hook (safe)
      assert :ok = Chain.create(pid, %{
        table: test_table,
        name: "INPUT",
        family: :inet
      })

      # Create FORWARD chain WITHOUT hook (safe)
      assert :ok = Chain.create(pid, %{
        table: test_table,
        name: "FORWARD",
        family: :inet
      })

      # Create custom chain (no hook)
      assert :ok = Chain.create(pid, %{
        table: test_table,
        name: "custom_rules",
        family: :inet
      })

      # Add rules to each chain
      assert :ok =
        RuleBuilder.new(pid, test_table, "INPUT")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert :ok =
        RuleBuilder.new(pid, test_table, "FORWARD")
        |> RuleBuilder.match_ct_state([:established, :related])
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert :ok =
        RuleBuilder.new(pid, test_table, "custom_rules")
        |> RuleBuilder.match_dest_port(443)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      # Verify all chains exist
      assert Chain.exists?(pid, test_table, "INPUT", :inet)
      assert Chain.exists?(pid, test_table, "FORWARD", :inet)
      assert Chain.exists?(pid, test_table, "custom_rules", :inet)
    end
  end

  describe "resource cleanup" do
    test "cleans up table and all chains", %{pid: pid, test_table: test_table} do
      :ok = Table.create(pid, %{name: test_table, family: :inet})

      # Create multiple chains WITHOUT hooks (safe)
      :ok = Chain.create(pid, %{
        table: test_table,
        name: "INPUT",
        family: :inet
      })

      :ok = Chain.create(pid, %{
        table: test_table,
        name: "custom",
        family: :inet
      })

      # Add rules
      :ok =
        RuleBuilder.new(pid, test_table, "INPUT")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      # Verify everything exists
      assert Table.exists?(pid, test_table, :inet)
      assert Chain.exists?(pid, test_table, "INPUT", :inet)

      # Delete table (should clean up chains and rules)
      assert :ok = Table.delete(pid, test_table, :inet)

      # Verify cleanup
      refute Table.exists?(pid, test_table, :inet)
      refute Chain.exists?(pid, test_table, "INPUT", :inet)
    end
  end

  describe "complex rule combinations" do
    test "combines multiple match criteria", %{pid: pid, test_table: test_table} do
      :ok = Table.create(pid, %{name: test_table, family: :inet})

      # Create regular chain WITHOUT hook (safe)
      :ok = Chain.create(pid, %{
        table: test_table,
        name: "INPUT",
        family: :inet
      })

      # Complex rule: specific IP + specific port + rate limit + logging
      assert :ok =
        RuleBuilder.new(pid, test_table, "INPUT")
        |> RuleBuilder.match_source_ip(<<10, 0, 0, 100>>)
        |> RuleBuilder.match_dest_port(8080)
        |> RuleBuilder.match_ct_state([:new])
        |> RuleBuilder.rate_limit(10, :minute)
        |> RuleBuilder.log("SPECIAL: ")
        |> RuleBuilder.counter()
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      {:ok, rules} = NFTex.Rule.list(pid, test_table, "INPUT", family: :inet)
      assert length(rules) >= 1
    end

    test "creates firewall with interface-specific rules", %{pid: pid, test_table: test_table} do
      :ok = Table.create(pid, %{name: test_table, family: :inet})

      # Create regular chain WITHOUT hook (safe)
      :ok = Chain.create(pid, %{
        table: test_table,
        name: "INPUT",
        family: :inet
      })

      # Accept from loopback
      assert :ok =
        RuleBuilder.new(pid, test_table, "INPUT")
        |> RuleBuilder.match_iif("lo")
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      # Strict rules for external interface
      assert :ok =
        RuleBuilder.new(pid, test_table, "INPUT")
        |> RuleBuilder.match_iif("eth0")
        |> RuleBuilder.match_dest_port(22)
        |> RuleBuilder.rate_limit(5, :minute)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      {:ok, rules} = NFTex.Rule.list(pid, test_table, "INPUT", family: :inet)
      assert length(rules) >= 2
    end
  end

  describe "error propagation" do
    test "propagates errors from Chain operations", %{pid: pid} do
      # Try to create rule in non-existent chain
      result =
        RuleBuilder.new(pid, "nonexistent_table", "INPUT")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert {:error, _reason} = result
    end

    test "propagates errors from Policy operations", %{pid: pid} do
      # Try to apply policy to non-existent table/chain
      result = Policy.accept_loopback(pid,
        table: "nonexistent",
        chain: "INPUT"
      )

      assert {:error, _reason} = result
    end
  end
end
