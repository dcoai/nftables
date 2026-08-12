# Piped: this is Local.submit/2 and Decoder.decode/1, not /1 and /0.
NFTables.Query.list_tables()
|> NFTables.Local.submit(pid: self())
|> NFTables.Decoder.decode()
