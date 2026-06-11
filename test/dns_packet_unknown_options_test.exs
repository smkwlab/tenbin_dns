defmodule DNSpacketUnknownOptionsTest do
  @moduledoc """
  Regression tests for issue #91: packets whose edns_info carries a
  non-empty unknown_options map must survive create/1 and round-trip
  through parse/1 with their numeric option codes intact.
  """
  use ExUnit.Case, async: true

  alias DNSpacket.EDNS

  @packet %DNSpacket{
    id: 0x1234,
    rd: 1,
    question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
  }

  test "create/1 encodes a packet with a single unknown EDNS option" do
    packet = %{
      @packet
      | edns_info: %{payload_size: 1232, unknown_options: %{65_001 => <<1, 2, 3>>}}
    }

    binary = DNSpacket.create(packet)

    # The unknown option must appear on the wire with its original code
    assert is_binary(binary)
    assert :binary.match(binary, <<65_001::16, 3::16, 1, 2, 3>>) != :nomatch
  end

  test "unknown options round-trip through create/1 and parse/1" do
    unknown = %{65_001 => <<1, 2, 3>>, 65_002 => <<0xFF>>}
    packet = %{@packet | edns_info: %{payload_size: 1232, unknown_options: unknown}}

    parsed = packet |> DNSpacket.create() |> DNSpacket.parse()

    assert parsed.edns_info.unknown_options == unknown
  end

  test "unknown options round-trip alongside known options" do
    unknown = %{65_010 => <<9, 9>>}

    packet = %{
      @packet
      | edns_info: %{
          payload_size: 1232,
          ecs_family: 1,
          ecs_subnet: {192, 168, 1, 0},
          ecs_source_prefix: 24,
          ecs_scope_prefix: 0,
          unknown_options: unknown
        }
    }

    parsed = packet |> DNSpacket.create() |> DNSpacket.parse()

    assert parsed.edns_info.unknown_options == unknown
    assert parsed.edns_info.ecs_family == 1
    assert parsed.edns_info.ecs_subnet == {192, 168, 1, 0}
  end

  test "parse_opt_rr preserves the numeric code of unrecognized options" do
    assert %{unknown: [%{code: 65_001, data: <<1, 2, 3>>}]} =
             DNSpacket.parse_opt_rr(%{}, <<65_001::16, 3::16, 1, 2, 3>>)
  end

  test "create_edns_options accepts atom-named codes in the unknown list" do
    # The public create_edns_options/1 input shape allows atom option names
    # in the unknown list; they resolve through DNS.option_code/1 (:nsid => 3)
    assert DNSpacket.create_edns_options(%{unknown: [%{code: :nsid, data: <<1>>}]}) ==
             <<3::16, 1::16, 1>>
  end

  test "encode_option rejects unknown option codes outside the 16-bit range" do
    # Out-of-range integer codes must fail fast instead of being silently
    # truncated into the 16-bit wire field
    assert_raise FunctionClauseError, fn ->
      EDNS.encode_option({:unknown, %{code: 65_536, data: <<1>>}})
    end

    assert_raise FunctionClauseError, fn ->
      EDNS.encode_option({:unknown, %{code: -1, data: <<1>>}})
    end
  end

  test "unflatten emits unknown options as encodable tagged tuples" do
    [option] = EDNS.unflatten(%{unknown_options: %{65_001 => <<1, 2, 3>>}})

    assert {:unknown, %{code: 65_001, data: <<1, 2, 3>>}} = option
    assert EDNS.encode_option(option) == <<65_001::16, 3::16, 1, 2, 3>>
  end
end
