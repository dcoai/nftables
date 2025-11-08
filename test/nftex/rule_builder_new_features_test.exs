defmodule NFTex.RuleBuilderNewFeaturesTest do
  use ExUnit.Case, async: false
  require Logger

  @moduletag :integration
  @moduletag :new_features

  alias NFTex.{Table, Chain, RuleBuilder, Query}

  setup do
    {:ok, pid} = NFTex.start_link(port: NFTex.Port, check_capabilities: false)

    cleanup_tables(pid)

    :ok = Table.add(pid, %{name: "nftex_test_features", family: :inet})

    :ok =
      Chain.add(pid, %{
        table: "nftex_test_features",
        name: "INPUT",
        family: :inet
      })

    on_exit(fn ->
      if Process.alive?(pid) do
        cleanup_tables(pid)
        NFTex.stop(pid)
      end
    end)

    {:ok, pid: pid}
  end

  describe "port range matching" do
    test "match_port_range/3 creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_port_range(1024, 65535)
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end

    test "match_udp_port_range/3 creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_udp_port_range(10000, 20000)
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "ICMP matching" do
    test "match_icmp_type/2 with atom creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_icmp_type(:echo_request)
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end

    test "match_icmp_type/2 with integer creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_icmp_type(8)
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end

    test "match_icmp_code/2 creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_icmp_type(:dest_unreachable)
               |> RuleBuilder.match_icmp_code(3)
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "ICMPv6 matching" do
    test "match_icmpv6_type/2 creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_icmpv6_type(:echo_request)
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "packet type matching" do
    test "match_pkttype/2 creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_pkttype(:broadcast)
               |> RuleBuilder.drop()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end

    test "match_pkttype/2 with multicast creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_pkttype(:multicast)
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "log levels" do
    test "log/3 with level creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_dest_port(22)
               |> RuleBuilder.log("SSH: ", level: :warning)
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end

    test "log/3 without level creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.log("TEST: ")
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "mark save/restore" do
    test "restore_mark/1 creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_ct_state([:established, :related])
               |> RuleBuilder.restore_mark()
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end

    test "save_mark/1 creates valid rule", %{pid: pid} do
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_ct_state([:new])
               |> RuleBuilder.set_mark(100)
               |> RuleBuilder.save_mark()
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end
  end

  describe "combined features" do
    test "complex rule with new features", %{pid: pid} do
      # Port range + ICMP + log level + mark operations
      assert :ok =
               RuleBuilder.new(pid, "nftex_test_features", "INPUT")
               |> RuleBuilder.match_port_range(8000, 9000)
               |> RuleBuilder.match_ct_state([:new])
               |> RuleBuilder.set_mark(10)
               |> RuleBuilder.save_mark()
               |> RuleBuilder.log("WEB-RANGE: ", level: :info)
               |> RuleBuilder.accept()
               |> RuleBuilder.commit()

      {:ok, rules} = Query.list_rules(pid, "nftex_test_features", "INPUT", family: :inet)
      assert length(rules) > 0
    end
  end

  defp cleanup_tables(pid) do
    try do
      Table.delete(pid, "nftex_test_features", :inet)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end
end
