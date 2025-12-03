defmodule NFTables.PolicyIntegrationTest do
  use ExUnit.Case, async: false

  alias NFTables.{Policy, Builder}
  import NFTables.QueryHelpers

  @moduletag :integration
  @moduletag :slow

  # IMPORTANT: These tests verify the full Elixir → JSON → Port → nftables execution path.
  # Most policy functionality is tested via unit tests in policy_unit_test.exs

  setup do
    {:ok, pid} = NFTables.Port.start_link()

    # Use isolated test table
    test_table = "nftables_test_policy_integration"

    # Clean up and create test table and chain WITHOUT hook (safe)
    Builder.new()
    |> Builder.delete(table: test_table, family: :inet)
    |> Builder.submit(pid: pid)

    Builder.new()
    |> Builder.add(table: test_table, family: :inet)
    |> Builder.add(
      table: test_table,
      chain: "INPUT",
      family: :inet
    )
    |> Builder.submit(pid: pid)

    on_exit(fn ->
      if Process.alive?(pid) do
        Builder.new()
        |> Builder.delete(table: test_table, family: :inet)
        |> Builder.submit(pid: pid)

        NFTables.Port.stop(pid)
      end
    end)

    {:ok, pid: pid, test_table: test_table}
  end

  describe "policy execution integration" do
    test "accept_loopback executes successfully", %{pid: pid, test_table: test_table} do
      result =
        Builder.new()
        |> Policy.accept_loopback(table: test_table, chain: "INPUT")
        |> Builder.submit(pid: pid)

      assert result == :ok

      # Verify rule was created
      {:ok, rules} = list_rules(pid, test_table, "INPUT", family: :inet)
      assert length(rules) >= 1
    end

    test "accept_established executes successfully", %{pid: pid, test_table: test_table} do
      result =
        Builder.new()
        |> Policy.accept_established(table: test_table, chain: "INPUT")
        |> Builder.submit(pid: pid)

      assert result == :ok
    end

    test "allow_ssh executes with rate limiting", %{pid: pid, test_table: test_table} do
      result =
        Builder.new()
        |> Policy.allow_ssh(
          table: test_table,
          chain: "INPUT",
          rate_limit: 10,
          log: true
        )
        |> Builder.submit(pid: pid)

      assert result == :ok

      {:ok, rules} = list_rules(pid, test_table, "INPUT", family: :inet)
      assert length(rules) >= 1
    end

    test "setup_basic_firewall executes in test mode", %{pid: pid} do
      filter_test = "nftables_test_filter_setup"
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.submit(pid: pid)

      result = Policy.setup_basic_firewall(pid, table: filter_test, test_mode: true)

      assert result == :ok
      assert table_exists?(pid, filter_test, :inet)
      assert chain_exists?(pid, filter_test, "INPUT", :inet)

      # Cleanup
      Builder.new()
      |> Builder.delete(table: filter_test, family: :inet)
      |> Builder.submit(pid: pid)
    end
  end

  describe "error handling integration" do
    test "returns error for invalid table", %{pid: pid} do
      result =
        Builder.new()
        |> Policy.accept_loopback(
          table: "nonexistent_table",
          chain: "INPUT"
        )
        |> Builder.submit(pid: pid)

      assert {:error, _reason} = result
    end

    test "returns error for invalid chain", %{pid: pid, test_table: test_table} do
      result =
        Builder.new()
        |> Policy.accept_established(
          table: test_table,
          chain: "NONEXISTENT"
        )
        |> Builder.submit(pid: pid)

      assert {:error, _reason} = result
    end
  end
end
