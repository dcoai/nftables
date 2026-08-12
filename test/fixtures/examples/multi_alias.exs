# alias Mod.{A, B} parses as a call to Mod.{} — must not be reported,
# and both short names must resolve for later calls.
alias NFTables.{Query, Local}

Query.list_tables(family: :inet) |> Local.submit(pid: self())
