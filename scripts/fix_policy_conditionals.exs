#!/usr/bin/env elixir

# Fix remaining conditional functions in Policy module

file_path = "/home/dco/Projects/nftables_ex/lib/nftables/policy.ex"
content = File.read!(file_path)

# Fix allow_any function pattern
content = String.replace(content, """
    expr_list =
      rule(family: family)

    builder = if log_enabled do
      log(builder, "ALLOW ANY: ")
    else
      builder
    end

    builder
    |> accept()
    |> to_expr()
""", """
    builder = rule(family: family)

    builder = if log_enabled do
      log(builder, "ALLOW ANY: ")
    else
      builder
    end

    expr_list =
      builder
      |> accept()
      |> to_expr()
""")

# Fix deny_all function pattern
content = String.replace(content, """
    expr_list =
      rule(family: family)

    builder = if log_enabled do
      log(builder, "DENY ALL: ")
    else
      builder
    end

    builder
    |> drop()
    |> to_expr()
""", """
    builder = rule(family: family)

    builder = if log_enabled do
      log(builder, "DENY ALL: ")
    else
      builder
    end

    expr_list =
      builder
      |> drop()
      |> to_expr()
""")

# Fix allow_port function pattern (similar to allow_ssh)
content = Regex.replace(
  ~r/defp allow_port\(pid, port, opts\) do\s+table = Keyword\.get\(opts, :table, "filter"\)\s+chain = Keyword\.get\(opts, :chain, "INPUT"\)\s+family = Keyword\.get\(opts, :family, :inet\)\s+rate_limit = Keyword\.get\(opts, :rate_limit\)\s+log_enabled = Keyword\.get\(opts, :log, false\)\s+service = Keyword\.get\(opts, :service, "PORT #{port}"\)\s+expr_list =\s+rule\(family: family\)\s+\|> dest_port\(port\)\s+builder = if rate_limit do\s+rate_limit\(builder, rate_limit, :minute\)\s+else\s+builder\s+end\s+builder = if log_enabled do\s+log\(builder, "#{service}: "\)\s+else\s+builder\s+end\s+builder\s+\|> accept\(\)\s+\|> to_expr\(\)/s,
  content,
  """
  defp allow_port(pid, port, opts) do
      table = Keyword.get(opts, :table, "filter")
      chain = Keyword.get(opts, :chain, "INPUT")
      family = Keyword.get(opts, :family, :inet)
      rate_limit_val = Keyword.get(opts, :rate_limit)
      log_enabled = Keyword.get(opts, :log, false)
      service = Keyword.get(opts, :service, "PORT \#{port}")

      builder =
        rule(family: family)
        |> dest_port(port)

      builder = if rate_limit_val do
        limit(builder, rate_limit_val, :minute)
      else
        builder
      end

      builder = if log_enabled do
        log(builder, "\#{service}: ")
      else
        builder
      end

      expr_list =
        builder
        |> accept()
        |> to_expr()
  """
)

File.write!(file_path, content)
IO.puts "✓ Fixed conditional functions"
