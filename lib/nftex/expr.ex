defmodule NFTablesEx.Expr do
  @moduledoc """
  Helper functions for building nftables expression structures.

  This module provides a clean API for constructing the expression data structures
  used by nftables. These helpers make it easier to build complex firewall rules
  without manually constructing nested maps.

  **NOTE**: All functions return maps with **atom keys** (not string keys).
  The JSON encoding happens later in the Builder/Executor pipeline.

  ## Expression Format

  nftables uses expressions that consist of:
  - **Matches**: Compare packet fields against values
  - **Statements**: Perform actions (counter, log, limit, mark, etc.)
  - **Verdicts**: Terminal decisions (accept, drop, reject, etc.)

  ## Examples

      # Simple IP match
      Expr.payload_match("ip", "saddr", "192.168.1.1")
      #=> %{match: %{
      #     left: %{payload: %{protocol: "ip", field: "saddr"}},
      #     right: "192.168.1.1",
      #     op: "=="
      #   }}

      # Connection tracking match
      Expr.ct_match("state", ["established", "related"])
      #=> %{match: %{
      #     left: %{ct: %{key: "state"}},
      #     right: ["established", "related"],
      #     op: "in"
      #   }}

      # Verdict
      Expr.verdict("drop")
      #=> %{drop: nil}

  ## Reference

  Official nftables documentation:
  https://wiki.nftables.org/wiki-nftables/index.php/JSON_API
  """

  ## Payload Matches

  @doc """
  Build a payload match expression.

  Matches a protocol field against a value.

  ## Parameters

  - `protocol` - Protocol name ("ip", "ip6", "tcp", "udp", "icmp", etc.)
  - `field` - Field name ("saddr", "daddr", "sport", "dport", etc.)
  - `value` - Value to match (string, integer, or list)
  - `op` - Comparison operator (default: "==")

  ## Examples

      # IPv4 source address
      payload_match("ip", "saddr", "192.168.1.1")

      # TCP destination port
      payload_match("tcp", "dport", 80)

      # Port range
      payload_match("tcp", "dport", %{range: [1024, 65535]})

      # Not equal
      payload_match("ip", "saddr", "10.0.0.0/8", "!=")
  """
  @spec payload_match(String.t(), String.t(), term(), String.t()) :: map()
  def payload_match(protocol, field, value, op \\ "==") do
    %{
      match: %{
        left: %{payload: %{protocol: protocol, field: field}},
        right: normalize_value(value),
        op: op
      }
    }
  end

  @doc """
  Build a payload match with prefix (CIDR notation).

  ## Examples

      payload_match_prefix("ip", "saddr", "192.168.1.0", 24)
      #=> Matches 192.168.1.0/24
  """
  @spec payload_match_prefix(String.t(), String.t(), String.t(), integer()) :: map()
  def payload_match_prefix(protocol, field, addr, prefix_len) do
    %{
      match: %{
        left: %{payload: %{protocol: protocol, field: field}},
        right: %{
          prefix: %{
            addr: addr,
            len: prefix_len
          }
        },
        op: "=="
      }
    }
  end

  @doc """
  Build a payload range match.

  ## Examples

      payload_match_range("tcp", "dport", 1024, 65535)
      #=> Matches ports 1024-65535
  """
  @spec payload_match_range(String.t(), String.t(), term(), term()) :: map()
  def payload_match_range(protocol, field, min_val, max_val) do
    %{
      match: %{
        left: %{payload: %{protocol: protocol, field: field}},
        right: %{range: [normalize_value(min_val), normalize_value(max_val)]},
        op: "=="
      }
    }
  end

  ## Connection Tracking Matches

  @doc """
  Build a connection tracking match expression.

  ## Parameters

  - `key` - CT key ("state", "status", "mark", "bytes", "packets", etc.)
  - `value` - Value to match
  - `op` - Comparison operator (default: "in" for lists, "==" for single values)

  ## Examples

      # Match established/related connections
      ct_match("state", ["established", "related"])

      # Match connection mark
      ct_match("mark", 42, "==")

      # Match connection bytes
      ct_match("bytes", 1000000, ">")
  """
  @spec ct_match(String.t(), term(), String.t() | nil) :: map()
  def ct_match(key, value, op \\ nil) do
    # Auto-determine operator if not specified
    op = op || (if is_list(value), do: "in", else: "==")

    %{
      match: %{
        left: %{ct: %{key: key}},
        right: normalize_value(value),
        op: op
      }
    }
  end

  @doc """
  Build a connection tracking original direction match.

  ## Examples

      ct_original_match("saddr", "192.168.1.1")
      #=> Match original source address
  """
  @spec ct_original_match(String.t(), String.t()) :: map()
  def ct_original_match(field, value) do
    %{
      match: %{
        left: %{ct: %{key: field, dir: "original"}},
        right: value,
        op: "=="
      }
    }
  end

  ## Meta Matches

  @doc """
  Build a meta expression match.

  Meta expressions match packet metadata (not packet contents).

  ## Parameters

  - `key` - Meta key ("mark", "iif", "oif", "length", "protocol", etc.)
  - `value` - Value to match
  - `op` - Comparison operator (default: "==")

  ## Examples

      # Match packet mark
      meta_match("mark", 100)

      # Match input interface
      meta_match("iifname", "eth0")

      # Match packet length
      meta_match("length", 1000, ">")
  """
  @spec meta_match(String.t(), term(), String.t()) :: map()
  def meta_match(key, value, op \\ "==") do
    %{
      match: %{
        left: %{meta: %{key: key}},
        right: normalize_value(value),
        op: op
      }
    }
  end

  ## Set Matches

  @doc """
  Build a set membership match.

  Checks if a value is in a named set.

  ## Examples

      # Check if source IP is in blocklist
      set_match("ip", "saddr", "@blocklist")

      # Check if destination port is in allowed_ports set
      set_match("tcp", "dport", "@allowed_ports")
  """
  @spec set_match(String.t(), String.t(), String.t()) :: map()
  def set_match(protocol, field, set_name) do
    %{
      match: %{
        left: %{payload: %{protocol: protocol, field: field}},
        right: set_name,
        op: "in"
      }
    }
  end

  ## Bitwise Operations

  @doc """
  Build a bitwise AND match.

  Used for TCP flags, fragmentation checks, etc.

  ## Examples

      # TCP flags: Check if SYN is set (mask includes SYN, ACK, RST, FIN)
      bitwise_and_match(
        %{payload: %{protocol: "tcp", field: "flags"}},
        ["syn", "ack", "rst", "fin"],
        ["syn"]
      )
  """
  @spec bitwise_and_match(map(), term(), term()) :: map()
  def bitwise_and_match(left_expr, mask, value) do
    %{
      match: %{
        left: %{"&": [left_expr, normalize_value(mask)]},
        right: normalize_value(value),
        op: "=="
      }
    }
  end

  ## Statements

  @doc """
  Build a counter statement.

  Counts packets and bytes.

  ## Examples

      counter()
      #=> %{counter: nil}
  """
  @spec counter() :: map()
  def counter do
    %{counter: nil}
  end

  @doc """
  Build a log statement.

  ## Options

  - `:prefix` - Log prefix string (required)
  - `:level` - Syslog level ("emerg", "alert", "crit", "err", "warn", "notice", "info", "debug")
  - `:flags` - Log flags list (["tcp sequence", "tcp options", "ip options", "skuid", "ether", "all"])

  ## Examples

      log("SSH_ATTEMPT: ")
      log("DROPPED: ", level: "warn")
      log("AUDIT: ", level: "info", flags: ["all"])
  """
  @spec log(String.t(), keyword()) :: map()
  def log(prefix, opts \\ []) do
    log_expr = %{prefix: prefix}
    log_expr = maybe_put(log_expr, :level, opts[:level])
    log_expr = maybe_put(log_expr, :flags, opts[:flags])

    %{log: log_expr}
  end

  @doc """
  Build a limit statement (rate limiting).

  ## Options

  - `:rate` - Rate number (required)
  - `:per` - Time unit ("second", "minute", "hour", "day") (required)
  - `:burst` - Burst packets (optional)
  - `:inv` - Invert match (rate over) (optional)

  ## Examples

      limit(10, "minute")
      limit(100, "second", burst: 200)
      limit(5, "minute", burst: 10, inv: true)  # Rate over 5/min
  """
  @spec limit(integer(), String.t(), keyword()) :: map()
  def limit(rate, per, opts \\ []) do
    limit_expr = %{
      rate: rate,
      per: per
    }

    limit_expr = maybe_put(limit_expr, :burst, opts[:burst])
    limit_expr = maybe_put(limit_expr, :inv, opts[:inv])

    %{limit: limit_expr}
  end

  ## Verdict Expressions

  @doc """
  Build a verdict expression.

  ## Supported Verdicts

  - "accept" - Accept the packet
  - "drop" - Drop the packet
  - "continue" - Continue to next rule
  - "return" - Return from chain

  ## Examples

      verdict("accept")
      #=> %{accept: nil}

      verdict("drop")
      #=> %{drop: nil}
  """
  @spec verdict(String.t()) :: map()
  def verdict(verdict_name) when verdict_name in ["accept", "drop", "continue", "return"] do
    %{String.to_existing_atom(verdict_name) => nil}
  end

  @doc """
  Build a reject verdict with optional type.

  ## Examples

      reject()
      reject("tcp reset")
      reject("icmpx port-unreachable")
  """
  @spec reject(String.t() | nil) :: map()
  def reject(type \\ nil) do
    if type do
      %{reject: %{type: type}}
    else
      %{reject: nil}
    end
  end

  @doc """
  Build a jump verdict (jump to another chain).

  ## Examples

      jump("custom_chain")
      #=> %{jump: %{target: "custom_chain"}}
  """
  @spec jump(String.t()) :: map()
  def jump(chain_name) do
    %{jump: %{target: chain_name}}
  end

  @doc """
  Build a goto verdict (goto another chain, no return).

  ## Examples

      goto("custom_chain")
      #=> %{goto: %{target: "custom_chain"}}
  """
  @spec goto(String.t()) :: map()
  def goto(chain_name) do
    %{goto: %{target: chain_name}}
  end

  ## NAT Statements

  @doc """
  Build a SNAT (Source NAT) statement.

  ## Options

  - `:port` - Port or port range
  - `:family` - Address family ("ip" or "ip6", default: "ip")

  ## Examples

      snat("203.0.113.1")
      snat("203.0.113.1", port: 1024)
      snat("203.0.113.1", port: [1024, 65535])
      snat("2001:db8::1", family: "ip6")
  """
  @spec snat(String.t(), keyword()) :: map()
  def snat(addr, opts \\ []) do
    family = Keyword.get(opts, :family, "ip")
    snat_expr = %{addr: addr, family: family}
    snat_expr = maybe_put(snat_expr, :port, opts[:port])

    %{snat: snat_expr}
  end

  @doc """
  Build a DNAT (Destination NAT) statement.

  ## Options

  - `:port` - Port or port range
  - `:family` - Address family ("ip" or "ip6", default: "ip")

  ## Examples

      dnat("192.168.1.10")
      dnat("192.168.1.10", port: 8080)
      dnat("192.168.1.10", port: [8080, 8090])
      dnat("2001:db8::10", family: "ip6")
  """
  @spec dnat(String.t(), keyword()) :: map()
  def dnat(addr, opts \\ []) do
    family = Keyword.get(opts, :family, "ip")
    dnat_expr = %{addr: addr, family: family}
    dnat_expr = maybe_put(dnat_expr, :port, opts[:port])

    %{dnat: dnat_expr}
  end

  @doc """
  Build a masquerade statement.

  ## Examples

      masquerade()
      masquerade(port: [1024, 65535])
  """
  @spec masquerade(keyword()) :: map()
  def masquerade(opts \\ []) do
    if opts[:port] do
      %{masquerade: %{port: opts[:port]}}
    else
      %{masquerade: nil}
    end
  end

  ## Packet Modification Statements

  @doc """
  Build a meta set statement (set packet mark, priority, etc.).

  ## Examples

      meta_set("mark", 100)
      meta_set("priority", 1)
  """
  @spec meta_set(String.t(), term()) :: map()
  def meta_set(key, value) do
    %{
      mangle: %{
        key: %{meta: %{key: key}},
        value: normalize_value(value)
      }
    }
  end

  @doc """
  Build a CT set statement (set connection tracking value).

  ## Examples

      ct_set("mark", 42)
      ct_set("helper", "ftp")
  """
  @spec ct_set(String.t(), term()) :: map()
  def ct_set(key, value) do
    %{
      ct: %{
        key: key,
        value: normalize_value(value)
      }
    }
  end

  ## Helper Functions

  # Normalize values for expression structures
  defp normalize_value(value) when is_binary(value), do: value
  defp normalize_value(value) when is_integer(value), do: value
  defp normalize_value(value) when is_list(value), do: value
  defp normalize_value(value) when is_map(value), do: value
  defp normalize_value({:range, min, max}), do: [min, max]
  defp normalize_value(value), do: to_string(value)

  # Conditionally add key to map if value is not nil
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
