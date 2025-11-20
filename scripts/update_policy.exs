#!/usr/bin/env elixir

# Script to update Policy module from old Match API to new API

file_path = "/home/dco/Projects/nftables_ex/lib/nftables/policy.ex"
content = File.read!(file_path)

# Replace Match.new pattern with rule() and extract expr building
content = Regex.replace(
  ~r/Match\.new\(pid, table, chain, family: family\)\s*\n(\s*)\|> Match\./,
  content,
  "expr_list =\n\\1  rule(family: family)\n\\1  |> "
)

# Replace remaining Match. function calls (except in the pattern above)
# Remove "Match." prefix since we're using import
content = String.replace(content, "|> Match.", "|> ")

# Replace Match.commit() with to_expr() and add Builder/Executor pattern
content = Regex.replace(
  ~r/\|> commit\(\)\s*\n(\s*)end/,
  content,
  "|> to_expr()\n\n\\1  Builder.new()\n\\1  |> Builder.add_rule(expr_list, table: table, chain: chain, family: family)\n\\1  |> Executor.execute(pid)\n\\1end"
)

File.write!(file_path, content)
IO.puts "✓ Updated Policy module"
