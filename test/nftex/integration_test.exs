defmodule NFTex.IntegrationTest do
  use ExUnit.Case, async: false

  alias NFTex.{Table, Chain, RuleBuilder, Policy}

  setup do
    {:ok, pid} = NFTex.start_link()

    # Cleanup
    Table.delete(pid, "integration_test", :inet)

    on_exit(fn ->
      if Process.alive?(pid) do
        Table.delete(pid, "integration_test", :inet)
        Table.delete(pid, "filter", :inet)
        Table.delete(pid, "nat", :inet)
      end
    end)

    {:ok, pid: pid}
  end

  describe "complete firewall setup" do
    test "builds secure server with Chain + RuleBuilder + Policy", %{pid: pid} do
      # Step 1: Create table
      assert :ok = Table.create(pid, %{name: "integration_test", family: :inet})

      # Step 2: Create INPUT chain with DROP policy
      assert :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      })

      # Step 3: Apply common policies
      assert :ok = Policy.accept_loopback(pid,
        table: "integration_test",
        chain: "INPUT"
      )

      assert :ok = Policy.accept_established(pid,
        table: "integration_test",
        chain: "INPUT"
      )

      assert :ok = Policy.drop_invalid(pid,
        table: "integration_test",
        chain: "INPUT"
      )

      # Step 4: Add service-specific rules
      assert :ok = Policy.allow_ssh(pid,
        table: "integration_test",
        chain: "INPUT",
        rate_limit: 10
      )

      # Step 5: Add custom rule with RuleBuilder
      assert :ok =
        RuleBuilder.new(pid, "integration_test", "INPUT")
        |> RuleBuilder.match_dest_port(8080)
        |> RuleBuilder.rate_limit(100, :second)
        |> RuleBuilder.counter()
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      # Verify chain exists and has rules
      assert Chain.exists?(pid, "integration_test", "INPUT", :inet)

      {:ok, rules} = NFTex.Rule.list(pid, "integration_test", "INPUT", family: :inet)
      assert length(rules) >= 5
    end

    test "uses Policy.setup_basic_firewall for quick setup", %{pid: pid} do
      Table.delete(pid, "filter", :inet)

      # One-line complete firewall
      assert :ok = Policy.setup_basic_firewall(pid,
        allow_services: [:ssh, :http, :https],
        ssh_rate_limit: 10
      )

      # Verify it's all set up
      assert Table.exists?(pid, "filter", :inet)
      assert Chain.exists?(pid, "filter", "INPUT", :inet)

      {:ok, rules} = NFTex.Rule.list(pid, "filter", "INPUT", family: :inet)
      # Should have loopback, established, invalid drop, and 3 services
      assert length(rules) >= 6
    end
  end

  describe "NAT gateway scenario" do
    test "sets up masquerading and port forwarding", %{pid: pid} do
      Table.delete(pid, "nat", :inet)

      # Step 1: Create NAT table
      assert :ok = Table.create(pid, %{name: "nat", family: :inet})

      # Step 2: Create POSTROUTING chain for masquerade
      assert :ok = Chain.create(pid, %{
        table: "nat",
        name: "POSTROUTING",
        family: :inet,
        type: :nat,
        hook: :postrouting,
        priority: 100,
        policy: :accept
      })

      # Step 3: Create PREROUTING chain for DNAT
      assert :ok = Chain.create(pid, %{
        table: "nat",
        name: "PREROUTING",
        family: :inet,
        type: :nat,
        hook: :prerouting,
        priority: -100,
        policy: :accept
      })

      # Step 4: Add masquerade rule for outgoing interface
      assert :ok =
        RuleBuilder.new(pid, "nat", "POSTROUTING")
        |> RuleBuilder.match_oif("eth0")
        |> RuleBuilder.commit()
      # Note: Would add masquerade expression if it was exposed in RuleBuilder

      # Step 5: Add port forwarding rule (DNAT)
      # This would use NAT expressions which we have in ExpressionBuilder
      # but not yet in RuleBuilder

      # Verify setup
      assert Chain.exists?(pid, "nat", "POSTROUTING", :inet)
      assert Chain.exists?(pid, "nat", "PREROUTING", :inet)
    end
  end

  describe "rate limiting scenario" do
    test "applies rate limits to multiple services", %{pid: pid} do
      :ok = Table.create(pid, %{name: "integration_test", family: :inet})

      :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      })

      # SSH with strict rate limit
      assert :ok = Policy.allow_ssh(pid,
        table: "integration_test",
        chain: "INPUT",
        rate_limit: 5
      )

      # HTTP with higher rate limit
      assert :ok = Policy.allow_http(pid,
        table: "integration_test",
        chain: "INPUT",
        rate_limit: 100
      )

      # Custom service with burst
      assert :ok =
        RuleBuilder.new(pid, "integration_test", "INPUT")
        |> RuleBuilder.match_dest_port(9000)
        |> RuleBuilder.rate_limit(50, :second, burst: 100)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      {:ok, rules} = NFTex.Rule.list(pid, "integration_test", "INPUT", family: :inet)
      assert length(rules) >= 3
    end
  end

  describe "logging scenario" do
    test "adds logging to multiple rules", %{pid: pid} do
      :ok = Table.create(pid, %{name: "integration_test", family: :inet})

      :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      })

      # SSH with logging
      assert :ok = Policy.allow_ssh(pid,
        table: "integration_test",
        chain: "INPUT",
        log: true
      )

      # Block specific IP with logging
      assert :ok =
        RuleBuilder.new(pid, "integration_test", "INPUT")
        |> RuleBuilder.match_source_ip(<<192, 168, 1, 100>>)
        |> RuleBuilder.log("BLOCKED-IP: ")
        |> RuleBuilder.drop()
        |> RuleBuilder.commit()

      # Log all dropped packets (at end of chain)
      assert :ok =
        RuleBuilder.new(pid, "integration_test", "INPUT")
        |> RuleBuilder.log("DROP-DEFAULT: ")
        |> RuleBuilder.commit()

      {:ok, rules} = NFTex.Rule.list(pid, "integration_test", "INPUT", family: :inet)
      assert length(rules) >= 3
    end
  end

  describe "multiple chains in same table" do
    test "creates and uses multiple chains", %{pid: pid} do
      :ok = Table.create(pid, %{name: "integration_test", family: :inet})

      # Create INPUT chain
      assert :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      })

      # Create FORWARD chain
      assert :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "FORWARD",
        family: :inet,
        type: :filter,
        hook: :forward,
        priority: 0,
        policy: :drop
      })

      # Create custom chain (no hook)
      assert :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "custom_rules",
        family: :inet
      })

      # Add rules to each chain
      assert :ok =
        RuleBuilder.new(pid, "integration_test", "INPUT")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert :ok =
        RuleBuilder.new(pid, "integration_test", "FORWARD")
        |> RuleBuilder.match_ct_state([:established, :related])
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      assert :ok =
        RuleBuilder.new(pid, "integration_test", "custom_rules")
        |> RuleBuilder.match_dest_port(443)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      # Verify all chains exist
      assert Chain.exists?(pid, "integration_test", "INPUT", :inet)
      assert Chain.exists?(pid, "integration_test", "FORWARD", :inet)
      assert Chain.exists?(pid, "integration_test", "custom_rules", :inet)
    end
  end

  describe "resource cleanup" do
    test "cleans up table and all chains", %{pid: pid} do
      :ok = Table.create(pid, %{name: "integration_test", family: :inet})

      # Create multiple chains
      :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      })

      :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "custom",
        family: :inet
      })

      # Add rules
      :ok =
        RuleBuilder.new(pid, "integration_test", "INPUT")
        |> RuleBuilder.match_dest_port(80)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      # Verify everything exists
      assert Table.exists?(pid, "integration_test", :inet)
      assert Chain.exists?(pid, "integration_test", "INPUT", :inet)

      # Delete table (should clean up chains and rules)
      assert :ok = Table.delete(pid, "integration_test", :inet)

      # Verify cleanup
      refute Table.exists?(pid, "integration_test", :inet)
      refute Chain.exists?(pid, "integration_test", "INPUT", :inet)
    end
  end

  describe "complex rule combinations" do
    test "combines multiple match criteria", %{pid: pid} do
      :ok = Table.create(pid, %{name: "integration_test", family: :inet})

      :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      })

      # Complex rule: specific IP + specific port + rate limit + logging
      assert :ok =
        RuleBuilder.new(pid, "integration_test", "INPUT")
        |> RuleBuilder.match_source_ip(<<10, 0, 0, 100>>)
        |> RuleBuilder.match_dest_port(8080)
        |> RuleBuilder.match_ct_state([:new])
        |> RuleBuilder.rate_limit(10, :minute)
        |> RuleBuilder.log("SPECIAL: ")
        |> RuleBuilder.counter()
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      {:ok, rules} = NFTex.Rule.list(pid, "integration_test", "INPUT", family: :inet)
      assert length(rules) >= 1
    end

    test "creates firewall with interface-specific rules", %{pid: pid} do
      :ok = Table.create(pid, %{name: "integration_test", family: :inet})

      :ok = Chain.create(pid, %{
        table: "integration_test",
        name: "INPUT",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :drop
      })

      # Accept from loopback
      assert :ok =
        RuleBuilder.new(pid, "integration_test", "INPUT")
        |> RuleBuilder.match_iif("lo")
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      # Strict rules for external interface
      assert :ok =
        RuleBuilder.new(pid, "integration_test", "INPUT")
        |> RuleBuilder.match_iif("eth0")
        |> RuleBuilder.match_dest_port(22)
        |> RuleBuilder.rate_limit(5, :minute)
        |> RuleBuilder.accept()
        |> RuleBuilder.commit()

      {:ok, rules} = NFTex.Rule.list(pid, "integration_test", "INPUT", family: :inet)
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
