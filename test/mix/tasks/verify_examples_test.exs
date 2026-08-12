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

  describe "baseline against the real example suite" do
    @tag :baseline
    test "reports exactly the 11 known-broken examples" do
      results =
        "examples/*.exs"
        |> Path.wildcard()
        |> Enum.map(&{Path.basename(&1), VerifyExamples.check_file(&1)})

      {clean, broken} = Enum.split_with(results, fn {_, findings} -> findings == [] end)

      assert Enum.map(clean, &elem(&1, 0)) == ["01_sysctl_management.exs"]
      assert length(broken) == 11
    end
  end
end
