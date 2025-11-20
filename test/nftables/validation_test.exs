defmodule NFTables.ValidationTest do
  use ExUnit.Case, async: true

  alias NFTables.Validation

  describe "validate_ipv4/1" do
    test "accepts valid IPv4 address" do
      assert :ok = Validation.validate_ipv4(<<192, 168, 1, 1>>)
    end

    test "rejects IPv4 address with wrong byte size" do
      assert {:error, msg} = Validation.validate_ipv4(<<192, 168, 1>>)
      assert msg =~ "expected 4 bytes, got 3 bytes"
    end

    test "rejects string IPv4 address" do
      assert {:error, msg} = Validation.validate_ipv4("192.168.1.1")
      assert msg =~ "got string"
      assert msg =~ "Use binary format"
      assert msg =~ "dot-decimal notation"
    end
  end

  describe "validate_ipv6/1" do
    test "accepts valid IPv6 address" do
      ipv6 = <<0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>
      assert :ok = Validation.validate_ipv6(ipv6)
    end

    test "rejects IPv6 address with wrong byte size" do
      assert {:error, msg} = Validation.validate_ipv6(<<1, 2, 3, 4>>)
      assert msg =~ "expected 16 bytes, got 4 bytes"
    end

    test "rejects string IPv6 address" do
      assert {:error, msg} = Validation.validate_ipv6("2001:db8::1")
      assert msg =~ "got string"
      assert msg =~ "Use binary format"
      assert msg =~ "colon-hex notation"
    end
  end

  describe "validate_family/1" do
    test "accepts :inet family" do
      assert {:ok, 2} = Validation.validate_family(:inet)
    end

    test "accepts :ip family" do
      assert {:ok, 2} = Validation.validate_family(:ip)
    end

    test "accepts :ip6 family" do
      assert {:ok, 10} = Validation.validate_family(:ip6)
    end

    test "accepts :inet6 family" do
      assert {:ok, 10} = Validation.validate_family(:inet6)
    end

    test "accepts :arp family" do
      assert {:ok, 3} = Validation.validate_family(:arp)
    end

    test "rejects invalid family" do
      assert {:error, msg} = Validation.validate_family(:invalid)
      assert msg =~ "Invalid family: :invalid"
      assert msg =~ "Valid families are"
    end
  end

  describe "enhance_netlink_error/2" do
    test "enhances ENOENT error with table/chain context" do
      result =
        Validation.enhance_netlink_error("No such file or directory (ENOENT)", %{
          operation: :rule_add,
          table: "filter",
          chain: "INPUT"
        })

      assert result =~ "Failed to add rule to filter/INPUT"
      assert result =~ "Table or chain not found"
      assert result =~ "nft add table"
    end

    test "enhances EPERM error with capability instructions" do
      result = Validation.enhance_netlink_error("Operation not permitted (EPERM)", %{operation: :rule_add})

      assert result =~ "Failed to add rule"
      assert result =~ "CAP_NET_ADMIN"
      assert result =~ "setcap"
    end

    test "enhances EEXIST error" do
      result =
        Validation.enhance_netlink_error("File exists (EEXIST)", %{
          operation: :table_add,
          table: "filter"
        })

      assert result =~ "Failed to add table"
      assert result =~ "Already exists"
    end

    test "passes through unknown errors" do
      assert "Unknown error (errno=999)" =
               Validation.enhance_netlink_error("Unknown error (errno=999)", %{})
    end
  end

  describe "errno_to_string/1" do
    test "converts common errno values" do
      assert Validation.errno_to_string(0) == "Success"
      assert Validation.errno_to_string(1) == "Operation not permitted (EPERM)"
      assert Validation.errno_to_string(2) == "No such file or directory (ENOENT)"
      assert Validation.errno_to_string(13) == "Permission denied (EACCES)"
      assert Validation.errno_to_string(17) == "File exists (EEXIST)"
      assert Validation.errno_to_string(22) == "Invalid argument (EINVAL)"
      assert Validation.errno_to_string(105) == "No buffer space available (ENOBUFS)"
    end

    test "handles negative errno values" do
      assert Validation.errno_to_string(-2) == "No such file or directory (ENOENT)"
      assert Validation.errno_to_string(-1) == "Operation not permitted (EPERM)"
    end

    test "handles unknown errno values" do
      assert Validation.errno_to_string(999) == "Unknown error (errno=999)"
      assert Validation.errno_to_string(12345) == "Unknown error (errno=12345)"
    end
  end

  describe "enhance_netlink_error/2 with errno integers" do
    test "enhances ENOENT (errno 2) with context" do
      result = Validation.enhance_netlink_error(2, %{
        operation: :rule_add,
        table: "filter",
        chain: "INPUT"
      })

      assert result =~ "Failed to add rule to filter/INPUT"
      assert result =~ "Table or chain not found"
      assert result =~ "nft add table"
    end

    test "enhances EPERM (errno 1) with capability instructions" do
      result = Validation.enhance_netlink_error(1, %{operation: :rule_add})

      assert result =~ "Failed to add rule"
      assert result =~ "CAP_NET_ADMIN"
      assert result =~ "setcap"
    end

    test "enhances EEXIST (errno 17)" do
      result = Validation.enhance_netlink_error(17, %{
        operation: :table_add,
        table: "filter"
      })

      assert result =~ "Failed to add table"
      assert result =~ "Already exists"
    end

    test "enhances EINVAL (errno 22)" do
      result = Validation.enhance_netlink_error(22, %{operation: :rule_add})

      assert result =~ "Failed to add rule"
      assert result =~ "Invalid argument"
    end

    test "handles negative errno values" do
      result = Validation.enhance_netlink_error(-2, %{
        operation: :rule_add,
        table: "filter",
        chain: "INPUT"
      })

      assert result =~ "Failed to add rule to filter/INPUT"
      assert result =~ "Table or chain not found"
    end

    test "handles unknown errno values" do
      result = Validation.enhance_netlink_error(999, %{operation: :rule_add})
      assert result == "Unknown error (errno=999)"
    end
  end
end
