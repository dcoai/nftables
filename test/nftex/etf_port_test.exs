defmodule NFTex.ETFPortTest do
  use ExUnit.Case, async: false

  @moduletag :etf_port

  setup do
    # Start ETF port
    {:ok, pid} = NFTex.ETFPort.start_link(check_capabilities: false)

    # Clean up any existing test tables (best effort)
    cleanup_tables(pid)

    on_exit(fn ->
      if Process.alive?(pid) do
        cleanup_tables(pid)
        NFTex.ETFPort.stop(pid)
      end
    end)

    {:ok, port: pid}
  end

  describe "basic operations" do
    test "list tables", %{port: pid} do
      cmd = %{
        "nftables" => [
          %{"list" => %{"tables" => %{}}}
        ]
      }

      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      assert is_binary(response)
      assert {:ok, %{"nftables" => items}} = Jason.decode(response)
      assert is_list(items)
    end

    test "list tables with family filter", %{port: pid} do
      cmd = %{
        "nftables" => [
          %{"list" => %{"tables" => %{"family" => "inet"}}}
        ]
      }

      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      assert {:ok, decoded} = Jason.decode(response)
      assert %{"nftables" => items} = decoded
      assert is_list(items)
    end

    test "add table", %{port: pid} do
      cmd = %{
        "nftables" => [
          %{"add" => %{"table" => %{"family" => "inet", "name" => "etf_test_add"}}}
        ]
      }

      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      # Empty response means success
      assert response == "" or is_binary(response)

      # Verify table was created
      tables = list_tables(pid, "inet")
      assert "etf_test_add" in tables
    end

    test "delete table", %{port: pid} do
      # First create a table
      create_table(pid, "inet", "etf_test_delete")

      # Verify it exists
      tables = list_tables(pid, "inet")
      assert "etf_test_delete" in tables

      # Delete it
      cmd = %{
        "nftables" => [
          %{"delete" => %{"table" => %{"family" => "inet", "name" => "etf_test_delete"}}}
        ]
      }

      assert {:ok, _response} = NFTex.ETFPort.call(pid, cmd)

      # Verify it's gone
      tables = list_tables(pid, "inet")
      refute "etf_test_delete" in tables
    end
  end

  describe "chain operations" do
    setup %{port: pid} do
      create_table(pid, "inet", "etf_test_chains")

      on_exit(fn ->
        if Process.alive?(pid) do
          try do
            delete_table(pid, "inet", "etf_test_chains")
          rescue
            _ -> :ok
          catch
            :exit, _ -> :ok
          end
        end
      end)

      :ok
    end

    test "add chain", %{port: pid} do
      cmd = %{
        "nftables" => [
          %{
            "add" => %{
              "chain" => %{
                "family" => "inet",
                "table" => "etf_test_chains",
                "name" => "input"
              }
            }
          }
        ]
      }

      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      assert response == "" or is_binary(response)
    end

    test "add base chain", %{port: pid} do
      cmd = %{
        "nftables" => [
          %{
            "add" => %{
              "chain" => %{
                "family" => "inet",
                "table" => "etf_test_chains",
                "name" => "filter",
                "type" => "filter",
                "hook" => "input",
                "prio" => 0,
                "policy" => "accept"
              }
            }
          }
        ]
      }

      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      assert response == "" or is_binary(response)
    end
  end

  describe "rule operations" do
    setup %{port: pid} do
      create_table(pid, "inet", "etf_test_rules")

      # Create chain
      cmd = %{
        "nftables" => [
          %{
            "add" => %{
              "chain" => %{
                "family" => "inet",
                "table" => "etf_test_rules",
                "name" => "input",
                "type" => "filter",
                "hook" => "input",
                "prio" => 0,
                "policy" => "accept"
              }
            }
          }
        ]
      }

      {:ok, _} = NFTex.ETFPort.call(pid, cmd)

      on_exit(fn ->
        if Process.alive?(pid) do
          try do
            delete_table(pid, "inet", "etf_test_rules")
          rescue
            _ -> :ok
          catch
            :exit, _ -> :ok
          end
        end
      end)

      :ok
    end

    test "add rule", %{port: pid} do
      cmd = %{
        "nftables" => [
          %{
            "add" => %{
              "rule" => %{
                "family" => "inet",
                "table" => "etf_test_rules",
                "chain" => "input",
                "expr" => [
                  %{"match" => %{"left" => %{"meta" => %{"key" => "iifname"}}, "op" => "==", "right" => "lo"}},
                  %{"accept" => nil}
                ]
              }
            }
          }
        ]
      }

      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      assert response == "" or is_binary(response)
    end
  end

  describe "data type handling" do
    test "handles string values", %{port: pid} do
      cmd = %{
        "nftables" => [
          %{"list" => %{"tables" => %{"family" => "inet"}}}
        ]
      }

      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      assert is_binary(response)
    end

    test "handles integer values", %{port: pid} do
      create_table(pid, "inet", "etf_test_integers")

      cmd = %{
        "nftables" => [
          %{
            "add" => %{
              "chain" => %{
                "family" => "inet",
                "table" => "etf_test_integers",
                "name" => "test",
                "type" => "filter",
                "hook" => "input",
                "prio" => 100,
                "policy" => "accept"
              }
            }
          }
        ]
      }

      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      assert response == "" or is_binary(response)

      delete_table(pid, "inet", "etf_test_integers")
    end

    test "handles nested maps and lists", %{port: pid} do
      create_table(pid, "inet", "etf_test_nested")

      cmd = %{
        "nftables" => [
          %{
            "add" => %{
              "set" => %{
                "family" => "inet",
                "table" => "etf_test_nested",
                "name" => "test_set",
                "type" => "ipv4_addr",
                "elem" => ["192.168.1.1", "10.0.0.1"]
              }
            }
          }
        ]
      }

      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      assert response == "" or is_binary(response)

      delete_table(pid, "inet", "etf_test_nested")
    end
  end

  describe "error handling" do
    test "handles invalid table name", %{port: pid} do
      cmd = %{
        "nftables" => [
          %{"list" => %{"chains" => %{"family" => "inet", "table" => "nonexistent"}}}
        ]
      }

      # Should complete without crashing, even if error
      assert {:ok, response} = NFTex.ETFPort.call(pid, cmd)
      assert is_binary(response)
      # Error responses can be empty or contain error info
      # Just verify we get a response and don't crash
    end
  end

  # Helper functions

  defp cleanup_tables(pid) do
    test_tables = [
      "etf_test_add",
      "etf_test_delete",
      "etf_test_chains",
      "etf_test_rules",
      "etf_test_integers",
      "etf_test_nested"
    ]

    for table <- test_tables do
      # Ignore errors - table might not exist
      try do
        delete_table(pid, "inet", table)
      rescue
        _ -> :ok
      catch
        :exit, _ -> :ok
      end
    end
  end

  defp create_table(pid, family, name) do
    cmd = %{
      "nftables" => [
        %{"add" => %{"table" => %{"family" => family, "name" => name}}}
      ]
    }

    NFTex.ETFPort.call(pid, cmd)
  end

  defp delete_table(pid, family, name) do
    cmd = %{
      "nftables" => [
        %{"delete" => %{"table" => %{"family" => family, "name" => name}}}
      ]
    }

    NFTex.ETFPort.call(pid, cmd)
  end

  defp list_tables(pid, family) do
    cmd = %{
      "nftables" => [
        %{"list" => %{"tables" => %{"family" => family}}}
      ]
    }

    {:ok, response} = NFTex.ETFPort.call(pid, cmd)
    {:ok, %{"nftables" => items}} = Jason.decode(response)

    items
    |> Enum.filter(&Map.has_key?(&1, "table"))
    |> Enum.map(fn %{"table" => t} -> t["name"] end)
  end
end
