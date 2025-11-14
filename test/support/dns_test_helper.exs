defmodule DNSTestHelper do
  @moduledoc """
  Shared test helper functions for DNS module tests.
  Extracts common test assertions to avoid code duplication.
  """

  @doc """
  Asserts that DNS.type/1 returns correct atoms for common type codes.
  """
  def assert_common_types do
    import ExUnit.Assertions

    assert DNS.type(1) == :a
    assert DNS.type(2) == :ns
    assert DNS.type(5) == :cname
    assert DNS.type(15) == :mx
    assert DNS.type(16) == :txt
    assert DNS.type(28) == :aaaa
    assert DNS.type(41) == :opt
    assert DNS.type(255) == :any
  end

  @doc """
  Asserts that DNS.type_code/1 returns correct codes for common type atoms.
  """
  def assert_common_type_codes do
    import ExUnit.Assertions

    assert DNS.type_code(:a) == 1
    assert DNS.type_code(:ns) == 2
    assert DNS.type_code(:cname) == 5
    assert DNS.type_code(:mx) == 15
    assert DNS.type_code(:txt) == 16
    assert DNS.type_code(:aaaa) == 28
    assert DNS.type_code(:opt) == 41
    assert DNS.type_code(:any) == 255
  end
end
