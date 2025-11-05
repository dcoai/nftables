defmodule Mix.Tasks.Compile.Zig do
  @moduledoc """
  Compiles the Zig port executable.

  This task is automatically run by Mix when compiling the project.
  It invokes `zig build` in the native/ directory and copies the
  resulting binary to priv/.
  """

  use Mix.Task.Compiler

  @impl true
  def run(_args) do
    config = Mix.Project.config()
    app = config[:app]

    source = "native/zig-out/bin/libnf_ex"
    dest = "priv/libnf_ex"

    # Check if compilation is needed
    if needs_compilation?(source, dest) do
      Mix.shell().info("Compiling Zig port for #{app}...")

      case System.cmd("zig", ["build"], cd: "native", stderr_to_stdout: true) do
        {output, 0} ->
          if output != "" do
            IO.puts(output)
          end

          # Ensure priv directory exists
          File.mkdir_p!("priv")

          # Copy the compiled binary
          case File.cp(source, dest) do
            :ok ->
              # Set executable permissions
              File.chmod!(dest, 0o755)
              Mix.shell().info("Compiled libnf_ex port successfully")
              check_capabilities(dest)
              {:ok, []}

            {:error, reason} ->
              Mix.shell().error("Failed to copy libnf_ex binary: #{inspect(reason)}")
              {:error, []}
          end

        {output, status} ->
          Mix.shell().error("Zig build failed with status #{status}")
          IO.puts(output)
          {:error, []}
      end
    else
      # Check capabilities even when not recompiling
      check_capabilities(dest)
      {:noop, []}
    end
  end

  defp needs_compilation?(source, dest) do
    # If destination doesn't exist, we need to compile
    if not File.exists?(dest) do
      true
    else
      # Get all Zig source files
      zig_sources = Path.wildcard("native/src/**/*.zig") ++ ["native/build.zig"]

      # Get destination timestamp
      dest_mtime = File.stat!(dest).mtime

      # Check if any source file is newer than the destination
      Enum.any?(zig_sources, fn source_file ->
        File.exists?(source_file) and File.stat!(source_file).mtime > dest_mtime
      end)
    end
  end

  defp check_capabilities(binary_path) do
    getcap_path = System.find_executable("getcap") || "/usr/sbin/getcap"

    case System.cmd(getcap_path, [binary_path], stderr_to_stdout: true) do
      {output, 0} ->
        if String.contains?(output, "cap_net_admin") do
          Mix.shell().info("✓ CAP_NET_ADMIN capability is set on #{binary_path}")
        else
          warn_missing_capabilities(binary_path)
        end

      _ ->
        warn_missing_capabilities(binary_path)
    end
  rescue
    # Handle case where getcap is not available
    _ -> warn_missing_capabilities(binary_path)
  end

  defp warn_missing_capabilities(binary_path) do
    Mix.shell().error("""
    ⚠ WARNING: CAP_NET_ADMIN capability is not set on #{binary_path}

    Netlink operations will fail without this capability.
    To fix, run:

        sudo setcap cap_net_admin=ep #{binary_path}

    """)
  end

  @impl true
  def clean do
    Mix.shell().info("Cleaning Zig build artifacts...")
    File.rm_rf("native/zig-cache")
    File.rm_rf("native/zig-out")
    File.rm_rf("priv/libnf_ex")
    :ok
  end
end
