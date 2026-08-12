# Every reference resolves.
alias NFTables.Query

defmodule CleanExample do
  def run(pid) do
    Query.list_tables(family: :inet)
    |> NFTables.Local.submit(pid: pid)
    |> NFTables.Decoder.decode()
  end
end
