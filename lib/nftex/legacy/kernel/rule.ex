defmodule NFTex.Kernel.Rule do
  @moduledoc """
  Low-level rule operations - direct libnftnl bindings.

  Rules contain expressions that match packets and perform actions.
  This module provides direct access with manual resource management.

  ## Example

      {:ok, rule_id} = NFTex.Kernel.Rule.alloc(pid)
      :ok = NFTex.Kernel.Rule.set_str(pid, rule_id, :table, "filter")
      :ok = NFTex.Kernel.Rule.set_str(pid, rule_id, :chain, "input")
      :ok = NFTex.Kernel.Rule.set_u32(pid, rule_id, :family, 2)

      # Add expressions to rule
      {:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "counter")
      :ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)

      # ... send to kernel ...
      :ok = NFTex.Kernel.Rule.free(pid, rule_id)
  """

  alias NFTex.Port

  @type resource_id :: non_neg_integer()

  @doc "Allocates a new rule resource."
  @spec alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def alloc(pid), do: Port.call(pid, {:rule_alloc})

  @doc "Frees a rule resource."
  @spec free(pid(), resource_id()) :: :ok | {:error, term()}
  def free(pid, resource_id), do: Port.call(pid, {:rule_free, resource_id})

  @doc """
  Sets a string attribute on a rule.

  Supported attributes: `:table`, `:chain`, `:user_data`
  """
  @spec set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def set_str(pid, resource_id, attr, value) do
    Port.call(pid, {:rule_set_str, resource_id, attr, value})
  end

  @doc """
  Sets a u32 attribute on a rule.

  Supported attributes: `:family`
  """
  @spec set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u32(pid, resource_id, attr, value) do
    Port.call(pid, {:rule_set_u32, resource_id, attr, value})
  end

  @doc """
  Sets a u64 attribute on a rule.

  Supported attributes: `:position`, `:handle`
  """
  @spec set_u64(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u64(pid, resource_id, attr, value) do
    Port.call(pid, {:rule_set_u64, resource_id, attr, value})
  end

  @doc """
  Adds an expression to a rule.

  The expression is transferred to the rule and should not be freed separately.
  """
  @spec add_expr(pid(), resource_id(), resource_id()) :: :ok | {:error, term()}
  def add_expr(pid, rule_id, expr_id) do
    Port.call(pid, {:rule_add_expr, rule_id, expr_id})
  end

  @doc "Gets a string attribute from a rule."
  @spec get_str(pid(), resource_id(), atom()) :: {:ok, String.t()} | {:error, term()}
  def get_str(pid, resource_id, attr) do
    Port.call(pid, {:rule_get_str, resource_id, attr})
  end

  @doc "Gets a u32 attribute from a rule."
  @spec get_u32(pid(), resource_id(), atom()) :: {:ok, non_neg_integer()} | {:error, term()}
  def get_u32(pid, resource_id, attr) do
    Port.call(pid, {:rule_get_u32, resource_id, attr})
  end

  @doc "Gets a u64 attribute from a rule."
  @spec get_u64(pid(), resource_id(), atom()) :: {:ok, non_neg_integer()} | {:error, term()}
  def get_u64(pid, resource_id, attr) do
    Port.call(pid, {:rule_get_u64, resource_id, attr})
  end

  @doc """
  Sends a rule to the kernel via netlink.

  This function communicates with the kernel's nftables subsystem via netlink
  to add or delete a rule. Requires `CAP_NET_ADMIN` capability.

  ## Arguments

  - `pid` - The NFTex port process
  - `resource_id` - The rule resource ID (from `alloc/1`)
  - `cmd` - The command to perform:
    - `:add` - Create the rule in the kernel
    - `:delete` - Remove the rule from the kernel

  ## Returns

  - `:ok` - Operation succeeded
  - `{:error, reason}` - Operation failed

  ## Example

      # Create rule with expressions
      {:ok, rule_id} = NFTex.Kernel.Rule.alloc(pid)
      :ok = NFTex.Kernel.Rule.set_str(pid, rule_id, :table, "filter")
      :ok = NFTex.Kernel.Rule.set_str(pid, rule_id, :chain, "input")
      :ok = NFTex.Kernel.Rule.set_u32(pid, rule_id, :family, 2)

      # Add expressions to rule
      {:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "counter")
      :ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)

      :ok = NFTex.Kernel.Rule.send_to_kernel(pid, rule_id, :add)

      # Delete rule
      :ok = NFTex.Kernel.Rule.send_to_kernel(pid, rule_id, :delete)
      :ok = NFTex.Kernel.Rule.free(pid, rule_id)

  ## Errors

  Common error reasons include:

  - `"Permission denied (EACCES)"` - Missing CAP_NET_ADMIN capability
  - `"File exists (EEXIST)"` - Rule already exists (when using `:add`)
  - `"No such file or directory (ENOENT)"` - Rule doesn't exist (when using `:delete`)

  """
  @spec send_to_kernel(pid(), resource_id(), :add | :delete) :: :ok | {:error, term()}
  def send_to_kernel(pid, resource_id, cmd) when cmd in [:add, :delete] do
    Port.call(pid, {:rule_send_to_kernel, resource_id, cmd})
  end
end
