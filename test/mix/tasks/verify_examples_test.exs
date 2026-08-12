defmodule Mix.Tasks.Nftables.VerifyExamplesTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Nftables.VerifyExamples

  @fixtures "test/fixtures/examples"

  defp check(name), do: VerifyExamples.check_file(Path.join(@fixtures, name))

  describe "resolving references" do
    test "a file whose references all resolve reports nothing" do
      assert check("clean.exs") == []
    end

    test "a call to a removed module is reported" do
      assert [{"NFTables.Table", :delete, 3}] = check("missing_module.exs")
    end

    test "an existing module called at a non-existent arity is reported" do
      assert [{"NFTables.Query", :list_tables, 2}] = check("wrong_arity.exs")
    end
  end

  describe "arity accounting" do
    test "piped calls count the piped value (REQ-TEST-008)" do
      # `x |> Local.submit(pid: ...)` is submit/2, not submit/1. Without
      # pipe handling every piped call is reported at one arity too few.
      assert check("piped.exs") == []
    end

    test "a function with default arguments resolves at each valid arity" do
      # Query.list_tables/0 and /1 are both exported from one definition.
      assert check("default_args.exs") == []
    end
  end

  describe "references that are not library calls" do
    test "a module defined in the same file is not reported" do
      assert check("local_module.exs") == []
    end

    test "alias Mod.{A, B} is not mistaken for a call, and its names resolve" do
      # The multi-alias form parses as a call to `Mod.{}`; it must be
      # skipped, and both short names must still resolve for later calls.
      assert check("multi_alias.exs") == []
    end
  end

  describe "the real example suite" do
    # Examples known to reference only functions that exist. This list is a
    # ratchet: each rewrite work item adds its files, and nothing may leave.
    #
    # It deliberately does not pin a total. An earlier version asserted "11
    # broken", which made every rewrite fail a test that was measuring the
    # bug rather than the fix. Asserting that fixed files stay fixed catches
    # regressions without rotting as the work proceeds. When the last
    # rewrite lands (#25) this becomes the whole suite.
    @verified [
      # was already clean
      "01_sysctl_management.exs",
      # rewritten in #17
      "02_basic_firewall.exs",
      "03_firewall_rules.exs",
      "04_ip_blocklist.exs",
      # rewritten in #18
      "06_query_tables.exs",
      "distributed_query.exs"
    ]

    test "every example already rewritten resolves cleanly (REQ-TEST-008)" do
      for name <- @verified do
        assert VerifyExamples.check_file(Path.join("examples", name)) == [],
               "#{name} was verified previously and has regressed"
      end
    end

    test "the checker still finds breakage in the examples not yet rewritten" do
      # Guards against the checker silently becoming a no-op — a bug that
      # would make every remaining work item look finished.
      remaining =
        "examples/*.exs"
        |> Path.wildcard()
        |> Enum.reject(&(Path.basename(&1) in @verified))

      if remaining != [] do
        assert Enum.any?(remaining, &(VerifyExamples.check_file(&1) != []))
      end
    end
  end
end
