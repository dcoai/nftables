defmodule NFTables.Expr.Socket do
  @moduledoc """
  Socket and process filtering functions for firewall rules.

  This module provides functions to match packets based on socket owner (UID/GID),
  control groups (cgroups) for container filtering, and transparent socket detection
  for transparent proxy setups.

  ## Common Use Cases

  - Block specific users from internet access
  - Allow only certain users to access services
  - Container-specific firewall rules
  - Transparent proxy (TPROXY) setups
  - Process-based access control

  ## Important Notes

  - Socket owner matching (skuid/skgid) only works for **locally-generated** traffic
  - These functions are only effective in the OUTPUT chain
  - Cgroup matching is useful for container/cgroup-based filtering

  ## Import

      import NFTables.Expr.Socket

  For more information, see the [nftables socket expressions wiki](https://wiki.nftables.org/wiki-nftables/index.php/Socket_matching).
  """

  alias NFTables.Expr

  @doc """
  Match packets by socket owner user ID.

  Matches packets based on the UID of the process that created the socket.
  Only works for locally-generated traffic in the OUTPUT chain.

  ## Example

      # Block specific user from internet access
      skuid(1001)
      |> oif("wan0")
      |> reject()

      # Allow only root to access management port
      skuid(0)
      |> tcp()
      |> dport(9000)
      |> accept()

      # Per-user bandwidth limiting
      skuid(1001) |> limit(1000, :second) |> accept()
  """
  @spec skuid(Expr.t(), non_neg_integer()) :: Expr.t()
  def skuid(builder \\ Expr.expr(), uid) when is_integer(uid) and uid >= 0 do
    expr = Expr.Structs.meta_match("skuid", uid)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match packets by socket owner group ID.

  Matches packets based on the GID of the process that created the socket.
  Only works for locally-generated traffic in the OUTPUT chain.

  ## Example

      # Block specific group from internet access
      skgid(1002)
      |> oif("wan0")
      |> reject()

      # Allow admin group to access admin port
      skgid(100)
      |> tcp()
      |> dport(8443)
      |> accept()

      # Log traffic from development group
      skgid(1000) |> log("dev-group") |> accept()
  """
  @spec skgid(Expr.t(), non_neg_integer()) :: Expr.t()
  def skgid(builder \\ Expr.expr(), gid) when is_integer(gid) and gid >= 0 do
    expr = Expr.Structs.meta_match("skgid", gid)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match cgroup (control group) ID.

  Used for container-specific filtering. Cgroups are used by Docker, Kubernetes,
  and other container systems to isolate processes.

  ## Example

      # Route specific cgroup to custom chain
      cgroup(1001) |> jump("container_rules")

      # Block specific container
      cgroup(2000) |> drop()

      # Apply rate limiting per container
      cgroup(1001) |> limit(1000, :second) |> accept()

      # Mark traffic from specific cgroup
      cgroup(1001) |> set_mark(100) |> accept()
  """
  @spec cgroup(Expr.t(), non_neg_integer()) :: Expr.t()
  def cgroup(builder \\ Expr.expr(), cgroup_id) when is_integer(cgroup_id) and cgroup_id >= 0 do
    expr = Expr.Structs.meta_match("cgroup", cgroup_id)
    Expr.add_expr(builder, expr)
  end

  @doc """
  Match packets with transparent socket.

  Used in transparent proxy setups to identify packets that belong to an existing
  transparent socket. This prevents loops where proxied packets are re-proxied.

  ## Examples

      # Mark packets with existing transparent socket
      socket_transparent()
      |> set_mark(1)
      |> accept()

      # Skip TPROXY for packets already handled
      socket_transparent() |> accept()

  ## Use Cases

  - Transparent proxy setups (TPROXY)
  - Avoiding proxy loops
  - Identifying proxy-handled traffic

  ## Typical TPROXY Setup

      # Chain 1: Mark existing transparent connections
      socket_transparent()
      |> set_mark(1)
      |> accept()

      # Chain 2: TPROXY unmarked traffic
      tcp()
      |> dport(80)
      |> mark(0)
      |> tproxy(to: 8080)

      # Chain 3: Accept marked traffic
      mark(1) |> accept()

  For more information, see the [TPROXY documentation](https://www.kernel.org/doc/Documentation/networking/tproxy.txt).
  """
  @spec socket_transparent(Expr.t()) :: Expr.t()
  def socket_transparent(builder \\ Expr.expr()) do
    expr = Expr.Structs.socket_match_value("transparent", 1)
    Expr.add_expr(builder, expr)
  end
end
