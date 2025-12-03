defmodule NFTables.RequestorTest do
  use ExUnit.Case, async: true

  alias NFTables.Builder

  # Test requestor that captures calls
  defmodule CaptureRequestor do
    @behaviour NFTables.Requestor

    @impl true
    def submit(builder, opts) do
      # Send to test process
      test_pid = Keyword.fetch!(opts, :test_pid)
      send(test_pid, {:submit_called, builder, opts})

      # Return configured response or default :ok
      Keyword.get(opts, :return, :ok)
    end
  end

  # Test requestor that returns errors
  defmodule ErrorRequestor do
    @behaviour NFTables.Requestor

    @impl true
    def submit(_builder, opts) do
      reason = Keyword.get(opts, :reason, "generic error")
      {:error, reason}
    end
  end

  # Test requestor that returns results
  defmodule ResultRequestor do
    @behaviour NFTables.Requestor

    @impl true
    def submit(builder, _opts) do
      {:ok, %{commands_count: length(builder.commands)}}
    end
  end

  # Module without submit/2 (for validation tests)
  defmodule NotARequestor do
    def some_other_function(_arg), do: :ok
  end

  describe "NFTables.Requestor behaviour" do
    test "CaptureRequestor implements behaviour correctly" do
      assert function_exported?(CaptureRequestor, :submit, 2)
    end

    test "ErrorRequestor implements behaviour correctly" do
      assert function_exported?(ErrorRequestor, :submit, 2)
    end

    test "ResultRequestor implements behaviour correctly" do
      assert function_exported?(ResultRequestor, :submit, 2)
    end
  end

  describe "Builder.new/1 with requestor" do
    test "creates builder with requestor option" do
      builder = Builder.new(requestor: CaptureRequestor)
      assert builder.requestor == CaptureRequestor
    end

    test "creates builder with default requestor (NFTables.Local)" do
      builder = Builder.new()
      assert builder.requestor == NFTables.Local
    end

    test "creates builder with nil requestor when explicitly set" do
      builder = Builder.new(requestor: nil)
      assert builder.requestor == nil
    end

    test "creates builder with both family and requestor" do
      builder = Builder.new(family: :ip6, requestor: CaptureRequestor)
      assert builder.family == :ip6
      assert builder.requestor == CaptureRequestor
    end
  end

  describe "Builder.set_requestor/2" do
    test "sets requestor on existing builder" do
      builder = Builder.new()
      |> Builder.set_requestor(CaptureRequestor)

      assert builder.requestor == CaptureRequestor
    end

    test "changes requestor on builder" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> Builder.set_requestor(ErrorRequestor)

      assert builder.requestor == ErrorRequestor
    end

    test "clears requestor with nil" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> Builder.set_requestor(nil)

      assert builder.requestor == nil
    end

    test "chains with other builder operations" do
      builder = Builder.new()
      |> NFTables.add(table: "filter")
      |> Builder.set_requestor(CaptureRequestor)
      |> NFTables.add(chain: "INPUT")

      assert builder.requestor == CaptureRequestor
      assert length(builder.commands) == 2
    end
  end

  describe "Builder.submit/1" do
    test "submits with configured requestor" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> NFTables.add(table: "filter")

      result = Builder.submit(builder, test_pid: self())

      assert result == :ok
      assert_received {:submit_called, ^builder, _opts}
    end

    test "submits with default requestor (NFTables.Local) when not explicitly set" do
      builder = Builder.new()
      |> NFTables.add(table: "filter")

      # Should not raise - uses NFTables.Local by default
      # We can't actually test the submit here without a running NFTables.Port,
      # but we can verify the requestor is set
      assert builder.requestor == NFTables.Local
    end

    test "returns error from requestor" do
      builder = Builder.new(requestor: ErrorRequestor)
      |> NFTables.add(table: "filter")

      result = Builder.submit(builder, reason: "custom error")

      assert result == {:error, "custom error"}
    end

    test "returns result from requestor" do
      builder = Builder.new(requestor: ResultRequestor)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")

      result = Builder.submit(builder)

      assert result == {:ok, %{commands_count: 2}}
    end
  end

  describe "Builder.submit/2" do
    test "passes options to requestor" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> NFTables.add(table: "filter")

      Builder.submit(builder, test_pid: self(), custom_opt: "value")

      assert_received {:submit_called, _builder, opts}
      assert opts[:custom_opt] == "value"
    end

    test "overrides builder requestor with opts[:requestor]" do
      builder = Builder.new(requestor: ErrorRequestor)
      |> NFTables.add(table: "filter")

      result = Builder.submit(builder,
        requestor: CaptureRequestor,
        test_pid: self()
      )

      assert result == :ok
      assert_received {:submit_called, _builder, _opts}
    end

    test "uses builder requestor when not overridden" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> NFTables.add(table: "filter")

      Builder.submit(builder, test_pid: self(), other_opt: 123)

      assert_received {:submit_called, _builder, opts}
      assert opts[:other_opt] == 123
    end

    test "uses default requestor (NFTables.Local) when no override provided" do
      builder = Builder.new()
      |> NFTables.add(table: "filter")

      # Builder has NFTables.Local as default, so no error should be raised
      # We can't actually test the submit here without a running NFTables.Port,
      # but we can verify the requestor is set
      assert builder.requestor == NFTables.Local
    end

    test "validates requestor implements submit/2" do
      builder = Builder.new()
      |> NFTables.add(table: "filter")

      assert_raise ArgumentError, ~r/does not implement NFTables.Requestor/, fn ->
        Builder.submit(builder, requestor: NotARequestor)
      end
    end

    test "allows requestor override without pre-configured requestor" do
      builder = Builder.new()
      |> NFTables.add(table: "filter")

      result = Builder.submit(builder,
        requestor: CaptureRequestor,
        test_pid: self()
      )

      assert result == :ok
      assert_received {:submit_called, _builder, _opts}
    end
  end

  describe "integration with Builder operations" do
    test "submit works with full builder chain" do
      builder = Builder.new(family: :inet, requestor: CaptureRequestor)
      |> NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT", type: :filter, hook: :input)
      |> NFTables.add(set: "blocklist", type: :ipv4_addr)

      Builder.submit(builder, test_pid: self())

      assert_received {:submit_called, received_builder, _opts}
      assert length(received_builder.commands) == 3
      assert received_builder.family == :inet
    end

    test "submit preserves builder state" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> NFTables.add(table: "filter")

      # Submit doesn't modify the builder
      Builder.submit(builder, test_pid: self())

      assert_received {:submit_called, _builder, _opts}

      # Builder still has same commands
      assert length(builder.commands) == 1
    end

    test "can submit same builder multiple times" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> NFTables.add(table: "filter")

      Builder.submit(builder, test_pid: self(), attempt: 1)
      Builder.submit(builder, test_pid: self(), attempt: 2)

      assert_received {:submit_called, _builder, opts1}
      assert_received {:submit_called, _builder, opts2}
      assert opts1[:attempt] == 1
      assert opts2[:attempt] == 2
    end
  end

  describe "requestor return values" do
    test "handles :ok return" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> NFTables.add(table: "filter")

      result = Builder.submit(builder, test_pid: self(), return: :ok)
      assert result == :ok
    end

    test "handles {:ok, result} return" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> NFTables.add(table: "filter")

      result = Builder.submit(builder, test_pid: self(), return: {:ok, "success"})
      assert result == {:ok, "success"}
    end

    test "handles {:error, reason} return" do
      builder = Builder.new(requestor: CaptureRequestor)
      |> NFTables.add(table: "filter")

      result = Builder.submit(builder, test_pid: self(), return: {:error, "failed"})
      assert result == {:error, "failed"}
    end
  end
end
