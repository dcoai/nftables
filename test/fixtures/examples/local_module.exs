# Calls a module defined in this same file.
defmodule LocalHelper do
  def helper(x), do: x
end

LocalHelper.helper(:ok)
