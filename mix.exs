defmodule Nftables.MixProject do
  use Mix.Project

  def project do
    [
      app: :nftables,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: Mix.compilers() ++ [:zig],
      aliases: aliases()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:usage_rules, "~> 0.1.25"}
    ]
  end

  defp aliases do
    [
      "compile.zig": &run_zig_compile/1,
      clean: ["clean", &run_zig_clean/1]
    ]
  end

  defp run_zig_compile(_args) do
    Mix.Tasks.Compile.Zig.run([])
  end

  defp run_zig_clean(_args) do
    Mix.Tasks.Compile.Zig.clean()
  end
end
