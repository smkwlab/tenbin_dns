defmodule DNSpacketEDNSConsistencyTest do
  @moduledoc """
  Guards the consistency between EDNS.known_options/0 and the per-option
  clauses of encode_option/1, decode_option/2, flatten/1 and unflatten/1.

  When adding a new EDNS option, add it to @known_options and register a
  sample flattened representation in @flat_samples below; these tests then
  verify that every codec direction has a clause for it, so a forgotten
  clause fails the suite instead of surfacing as a runtime mismatch.
  """
  use ExUnit.Case, async: true

  alias DNSpacket.EDNS

  # One representative flattened (hybrid edns_info) form per known option.
  @flat_samples %{
    edns_client_subnet: %{
      ecs_family: 1,
      ecs_subnet: {192, 168, 1, 0},
      ecs_source_prefix: 24,
      ecs_scope_prefix: 0
    },
    cookie: %{cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>, cookie_server: nil},
    nsid: %{nsid: "ns1.example.com"},
    extended_dns_error: %{
      extended_dns_error_info_code: 23,
      extended_dns_error_extra_text: "blocked"
    },
    edns_tcp_keepalive: %{
      edns_tcp_keepalive_timeout: 100,
      edns_tcp_keepalive_raw_data: nil
    },
    padding: %{padding_length: 4},
    dau: %{dau_algorithms: [8, 13]},
    dhu: %{dhu_algorithms: [1, 2]},
    n3u: %{n3u_algorithms: [1]},
    edns_expire: %{edns_expire_expire: 3600},
    chain: %{chain_closest_encloser: <<7, "example", 3, "com", 0>>},
    edns_key_tag: %{edns_key_tag_key_tags: [12_345, 54_321]},
    edns_client_tag: %{edns_client_tag_tag: 1},
    edns_server_tag: %{edns_server_tag_tag: 2},
    report_channel: %{report_channel_agent_domain: <<5, "agent", 7, "example", 0>>},
    zoneversion: %{zoneversion_version: 1},
    update_lease: %{update_lease_lease: 3600},
    llq: %{
      llq_version: 1,
      llq_llq_opcode: 1,
      llq_error_code: 0,
      llq_llq_id: 123,
      llq_lease_life: 3600
    },
    umbrella_ident: %{umbrella_ident_ident: 42},
    deviceid: %{deviceid_device_id: <<1, 2, 3, 4, 5, 6>>}
  }

  test "every known option has a sample registered in this test" do
    assert Enum.sort(EDNS.known_options()) == Enum.sort(Map.keys(@flat_samples))
  end

  test "every known option has unflatten and encode clauses" do
    for key <- EDNS.known_options() do
      flat = Map.fetch!(@flat_samples, key)

      assert [{^key, _value} = option] = EDNS.unflatten(flat),
             "unflatten/1 has no clause producing #{inspect(key)}"

      assert <<code::16, len::16, data::binary>> = EDNS.encode_option(option)
      assert code == DNS.option_code(key)
      assert byte_size(data) == len
    end
  end

  test "encode/decode round-trips every known option" do
    for key <- EDNS.known_options() do
      [option] = EDNS.unflatten(Map.fetch!(@flat_samples, key))
      <<_code::16, len::16, data::binary-size(len)>> = EDNS.encode_option(option)

      assert {^key, _value} = EDNS.decode_option(key, data),
             "decode_option/2 has no clause for #{inspect(key)}"
    end
  end

  test "unflatten emits options in the wire-format order when all are present" do
    all_options =
      @flat_samples
      |> Map.values()
      |> Enum.reduce(&Map.merge/2)
      |> Map.put(:unknown_options, %{65_001 => <<1>>, 65_002 => <<2>>})

    emitted = EDNS.unflatten(all_options)

    # Deliberately hard-coded (not derived from known_options/0) so that a
    # reordering of the prepend chain in unflatten/1 fails this test.
    assert Enum.map(emitted, &option_key/1) == [
             :edns_client_subnet,
             :cookie,
             :nsid,
             :extended_dns_error,
             :edns_tcp_keepalive,
             :padding,
             :dau,
             :dhu,
             :n3u,
             :edns_expire,
             :chain,
             :edns_key_tag,
             :edns_client_tag,
             :edns_server_tag,
             :report_channel,
             :zoneversion,
             :update_lease,
             :llq,
             :umbrella_ident,
             :deviceid,
             # unknown options last, in reversed map-enumeration order
             65_002,
             65_001
           ]
  end

  defp option_key({key, _value}), do: key
  defp option_key(%{code: code}), do: code

  test "flatten silently discards known keys with unexpected value shapes" do
    # Matches the original extract_and_flatten_options/1: a known key whose
    # value fails the clause guard is neither flattened nor sent to unknown.
    assert EDNS.flatten([{:cookie, "not-a-map"}, {:nsid, %{not: "a-binary"}}]) == {%{}, %{}}
  end

  test "flatten routes code/data-shaped values under unrecognized keys to unknown" do
    assert EDNS.flatten([{:something_else, %{code: 65_003, data: <<9>>}}]) ==
             {%{}, %{65_003 => <<9>>}}
  end

  test "unflatten/flatten round-trips every known option" do
    for key <- EDNS.known_options() do
      flat = Map.fetch!(@flat_samples, key)
      [option] = EDNS.unflatten(flat)

      {flattened, unknown} = EDNS.flatten([option])

      assert unknown == %{}

      for {field, value} <- flat, not is_nil(value) do
        assert Map.get(flattened, field) == value,
               "flatten/1 lost #{inspect(field)} for option #{inspect(key)}"
      end
    end
  end
end
