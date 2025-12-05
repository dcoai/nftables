defmodule NFTables.Expr.OSF do
  @moduledoc """
  OS Fingerprinting (OSF) functions for passive operating system detection.

  This module provides functions to match operating systems using passive fingerprinting.
  OSF analyzes TCP SYN packet characteristics such as window size, TTL, TCP options,
  and other parameters to identify the operating system without active probing.

  ## Requirements

  Before using OSF, you must load the pf.os fingerprint database:

      nfnl_osf -f /usr/share/pf.os

  The database contains signatures for various operating systems and versions.

  ## TTL Matching Modes

  - `:loose` (default) - Allows small TTL differences
  - `:skip` - Ignores TTL in matching
  - `:strict` - Requires exact TTL match

  ## Common Use Cases

  - OS-based rate limiting
  - Security policies per OS
  - Network analytics
  - OS-specific QoS

  ## Limitations

  - Only works on TCP SYN packets
  - Requires connection tracking
  - May not detect all systems accurately
  - Can be evaded by OS fingerprint spoofing

  ## Import

      import NFTables.Expr.OSF

  For more information, see the [nftables OSF wiki](https://wiki.nftables.org/wiki-nftables/index.php/Osf).
  """

  alias NFTables.Expr

  @doc """
  Match operating system by passive fingerprinting.

  Performs passive OS detection by analyzing TCP SYN packet characteristics.
  Requires the pf.os database to be loaded.

  ## Parameters

  - `builder` - Expression builder
  - `os_name` - OS name to match (e.g., "Linux", "Windows", "MacOS")
  - `opts` - Options keyword list:
    - `:ttl` - TTL matching mode: `:loose` (default), `:skip`, or `:strict`

  ## Common OS Names

  - "Linux" - Linux kernel
  - "Windows" - Microsoft Windows
  - "MacOS" - Apple macOS
  - "FreeBSD" - FreeBSD
  - "OpenBSD" - OpenBSD
  - "unknown" - Unknown/unmatched OS

  ## Examples

      # Match Linux systems
      osf_name("Linux") |> log("Linux detected") |> accept()

      # Match Windows with strict TTL checking
      osf_name("Windows", ttl: :strict)
      |> set_mark(2)
      |> accept()

      # Block unknown OS
      osf_name("unknown") |> drop()

      # OS-based rate limiting
      osf_name("Windows")
      |> limit(10, :second)
      |> accept()

      # Security: Only allow Linux to access SSH
      tcp()
      |> dport(22)
      |> osf_name("Linux")
      |> accept()

  ## Use Cases

  ### 1. OS-based Marking

      osf_name("Linux") |> set_mark(1)
      osf_name("Windows") |> set_mark(2)
      osf_name("MacOS") |> set_mark(3)

  ### 2. OS-based QoS

      osf_name("Linux") |> set_priority(1)
      osf_name("Windows") |> set_priority(2)

  ### 3. Security Policies

      # Only allow specific OS to critical services
      tcp()
      |> dport(22)
      |> osf_name("Linux")
      |> accept()
  """
  @spec osf_name(Expr.t(), String.t(), keyword()) :: Expr.t()
  def osf_name(builder \\ Expr.expr(), os_name, opts \\ []) when is_binary(os_name) do
    ttl = opts |> Keyword.get(:ttl, :loose) |> ttl_to_string()
    expr = Expr.Structs.osf_match_value("name", os_name, ttl)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match operating system version by passive fingerprinting.

  Similar to `osf_name/3` but matches the OS version instead of the OS name.
  This allows for more granular matching based on specific OS versions.

  ## Parameters

  - `builder` - Expression builder
  - `version` - OS version to match (e.g., "3.x", "10", "11", "XP")
  - `opts` - Options keyword list:
    - `:ttl` - TTL matching mode: `:loose` (default), `:skip`, or `:strict`

  ## Examples

      # Match Linux 3.x kernels
      osf_version("3.x") |> counter()

      # Match Windows 10
      osf_name("Windows")
      |> osf_version("10")
      |> log("Windows 10")
      |> accept()

      # Block old OS versions (security policy)
      osf_name("Windows")
      |> osf_version("XP")
      |> reject()

      # Version-based QoS
      osf_version("3.x") |> set_priority(1)

  ## Use Cases

  ### 1. Version-specific Security

      # Block outdated/vulnerable versions
      osf_name("Windows")
      |> osf_version("XP")
      |> log("Old Windows version")
      |> reject()

  ### 2. Version-based Rate Limiting

      osf_name("Linux")
      |> osf_version("2.6")
      |> limit(5, :second)
      |> accept()

  ### 3. Compliance Enforcement

      # Only allow recent OS versions
      osf_name("Windows")
      |> osf_version("10")
      |> accept()

      osf_name("Windows")
      |> osf_version("11")
      |> accept()
  """
  @spec osf_version(Expr.t(), String.t(), keyword()) :: Expr.t()
  def osf_version(builder \\ Expr.expr(), version, opts \\ []) when is_binary(version) do
    ttl = opts |> Keyword.get(:ttl, :loose) |> ttl_to_string()
    expr = Expr.Structs.osf_match_value("version", version, ttl)
    Expr.add_expr(builder, expr)
  end

  # Private: Convert TTL atom to string
  defp ttl_to_string(:loose), do: "loose"
  defp ttl_to_string(:skip), do: "skip"
  defp ttl_to_string(:strict), do: "strict"
  defp ttl_to_string(other) when is_binary(other), do: other
end
