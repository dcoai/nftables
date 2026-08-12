defmodule Mix.Tasks.Nftables.VerifyExamples do
  @shortdoc "Verify examples reference only functions the library exports"

  @moduledoc """
  Verifies that every file in `examples/` references only modules and
  functions the library actually exports.

  ## Why static analysis

  The examples apply firewall rules and call `NFTables.Port.start_link/0`,
  so they cannot be executed to check them. This task parses each file
  and resolves every `Module.function/arity` reference against the
  compiled application without running any of it.

  That catches the failure mode this project has actually hit: an API
  refactor lands, the examples keep referring to modules and arities that
  no longer exist, and nothing notices because no tooling reads them.

  ## What it does not catch

  Reference resolution proves an example *would compile*. It cannot prove
  the rule it builds is correct — for that an example has to run against a
  live kernel. Treat a clean run as necessary, not sufficient.

  ## Usage

      mix nftables.verify_examples
      mix nftables.verify_examples --dir examples
      mix nftables.verify_examples --quiet

  Exits non-zero when any reference is unresolved.
  """

  use Mix.Task

  @default_dir "examples"

  @impl Mix.Task
  def run(argv) do
    {opts, _, _} = OptionParser.parse(argv, strict: [dir: :string, quiet: :boolean])
    Mix.Task.run("compile")

    dir = opts[:dir] || @default_dir
    quiet = opts[:quiet] || false

    unless File.dir?(dir) do
      Mix.raise("no #{dir}/ directory found")
    end

    results =
      dir
      |> Path.join("*.exs")
      |> Path.wildcard()
      |> Enum.sort()
      |> Enum.map(&{&1, check_file(&1)})

    report(results, quiet)

    broken = Enum.filter(results, fn {_, findings} -> findings != [] end)

    if broken != [] do
      Mix.raise(
        "#{length(broken)} of #{length(results)} example(s) reference functions that do not exist"
      )
    end
  end

  @doc """
  Check one file, returning a sorted list of `{module, function, arity}`
  references that cannot be resolved.

  Returns `[]` when every reference resolves.
  """
  @spec check_file(Path.t()) :: [{String.t(), atom(), non_neg_integer()}]
  def check_file(path) do
    ast = path |> File.read!() |> Code.string_to_quoted!()

    aliases = collect_aliases(ast)
    local = collect_local_modules(ast)

    ast
    |> expand_pipes()
    |> collect_calls()
    |> Enum.map(fn {mod, fun, arity} -> {resolve(mod, aliases), fun, arity} end)
    |> Enum.uniq()
    |> Enum.reject(fn {mod, _, _} -> mod in local end)
    |> Enum.reject(&exported?/1)
    |> Enum.sort()
  end

  # A piped call `x |> M.f(a)` invokes M.f/2, not M.f/1. Insert a
  # placeholder argument so arity is counted correctly.
  defp expand_pipes(ast) do
    Macro.prewalk(ast, fn
      {:|>, meta, [lhs, {{:., dot_meta, [mod, fun]}, call_meta, args}]} ->
        {:|>, meta, [lhs, {{:., dot_meta, [mod, fun]}, call_meta, [:__piped__ | args]}]}

      node ->
        node
    end)
  end

  # `alias Mod.{A, B}` and `alias Mod.A, as: X` map a short name to a full one.
  defp collect_aliases(ast) do
    {_, aliases} =
      Macro.prewalk(ast, %{}, fn
        {:alias, _, [{{:., _, [base, :{}]}, _, mods}]} = node, acc ->
          base_name = module_name(base)

          acc =
            Enum.reduce(mods, acc, fn mod, inner ->
              name = module_name(mod)
              Map.put(inner, last_segment(name), base_name <> "." <> name)
            end)

          {node, acc}

        {:alias, _, [mod, opts]} = node, acc when is_list(opts) ->
          name = module_name(mod)

          case Keyword.get(opts, :as) do
            nil -> {node, Map.put(acc, last_segment(name), name)}
            as -> {node, Map.put(acc, module_name(as), name)}
          end

        {:alias, _, [mod]} = node, acc ->
          name = module_name(mod)
          {node, Map.put(acc, last_segment(name), name)}

        node, acc ->
          {node, acc}
      end)

    aliases
  end

  # Examples define their own modules; calls to those are not library refs.
  defp collect_local_modules(ast) do
    {_, mods} =
      Macro.prewalk(ast, [], fn
        {:defmodule, _, [mod | _]} = node, acc -> {node, [module_name(mod) | acc]}
        node, acc -> {node, acc}
      end)

    mods
  end

  defp collect_calls(ast) do
    {_, calls} =
      Macro.prewalk(ast, [], fn
        {{:., _, [{:__aliases__, _, segments}, fun]}, _, args} = node, acc
        when is_atom(fun) and is_list(args) ->
          # `alias Mod.{A, B}` parses as a call to `Mod.{}` — not a real call.
          if fun != :{} and Enum.all?(segments, &is_atom/1) do
            {node, [{Enum.join(segments, "."), fun, length(args)} | acc]}
          else
            {node, acc}
          end

        node, acc ->
          {node, acc}
      end)

    calls
  end

  defp resolve(module, aliases) do
    [head | rest] = String.split(module, ".")

    case Map.get(aliases, head) do
      nil -> module
      full -> Enum.join([full | rest], ".")
    end
  end

  # A function with default arguments exports several arities, so check
  # against the full exported set rather than a single arity.
  defp exported?({module, fun, arity}) do
    concat = Module.concat([module])

    Code.ensure_loaded?(concat) and
      Enum.any?(concat.__info__(:functions) ++ concat.__info__(:macros), fn {f, a} ->
        f == fun and a == arity
      end)
  rescue
    # Module.concat/1 on something that is not a valid module reference.
    ArgumentError -> false
  end

  defp module_name({:__aliases__, _, segments}), do: Enum.join(segments, ".")
  defp module_name(atom) when is_atom(atom), do: atom |> Atom.to_string()
  defp module_name(other), do: Macro.to_string(other)

  defp last_segment(name), do: name |> String.split(".") |> List.last()

  ## Reporting

  defp report(results, quiet) do
    Enum.each(results, fn {path, findings} ->
      base = Path.basename(path)

      cond do
        findings == [] and not quiet ->
          Mix.shell().info("  ok      #{base}")

        findings != [] ->
          Mix.shell().error("  BROKEN  #{base} (#{length(findings)})")
          Enum.each(findings, fn {m, f, a} -> Mix.shell().error("            #{m}.#{f}/#{a}") end)

        true ->
          :ok
      end
    end)

    ok = Enum.count(results, fn {_, f} -> f == [] end)
    Mix.shell().info("\n#{ok}/#{length(results)} examples verified")
  end
end
