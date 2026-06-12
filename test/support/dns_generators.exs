defmodule DNSGenerators do
  @moduledoc """
  StreamData generators for DNS packet property tests (#107).

  Every generator produces values in the canonical form that
  `DNSpacket.parse/1` returns, so generated data must survive
  `create |> parse` unchanged.
  """

  import StreamData

  # --- names ---------------------------------------------------------

  @doc "LDH label, 1..10 chars (letters/digits/hyphen, no edge hyphen)"
  def label do
    string([?a..?z, ?0..?9], min_length: 1, max_length: 10)
  end

  @doc "Absolute domain name with trailing dot, 1..4 labels"
  def domain_name do
    map(list_of(label(), min_length: 1, max_length: 4), fn labels ->
      Enum.join(labels, ".") <> "."
    end)
  end

  @doc "Domain name in DNS wire format (length-prefixed labels, root byte)"
  def wire_domain_name do
    map(list_of(label(), min_length: 1, max_length: 3), fn labels ->
      IO.iodata_to_binary([Enum.map(labels, &[byte_size(&1), &1]), 0])
    end)
  end

  # --- addresses -----------------------------------------------------

  def ipv4 do
    map({integer(0..255), integer(0..255), integer(0..255), integer(0..255)}, & &1)
  end

  def ipv6 do
    map(list_of(integer(0..0xFFFF), length: 8), &List.to_tuple/1)
  end

  # --- per-type rdata ------------------------------------------------

  @doc """
  Generates `{type, rdata}` pairs for every supported record type, with
  rdata in the canonical parsed form.
  """
  def type_and_rdata do
    one_of(address_rdata_gens() ++ name_rdata_gens() ++ structured_rdata_gens())
  end

  defp address_rdata_gens do
    [
      map(ipv4(), &{:a, %{addr: &1}}),
      map(ipv6(), &{:aaaa, %{addr: &1}})
    ]
  end

  defp name_rdata_gens do
    [
      map(domain_name(), &{:ns, %{name: &1}}),
      map(domain_name(), &{:cname, %{name: &1}}),
      map(domain_name(), &{:ptr, %{name: &1}}),
      map(domain_name(), &{:dname, %{target: &1}})
    ]
  end

  defp structured_rdata_gens do
    [
      soa_rdata(),
      mx_rdata(),
      txt_rdata(),
      hinfo_rdata(),
      caa_rdata(),
      srv_rdata(),
      naptr_rdata(),
      dnskey_rdata(),
      ds_rdata(),
      rrsig_rdata(),
      nsec_rdata(),
      svcb_rdata(:svcb),
      svcb_rdata(:https)
    ]
  end

  defp soa_rdata do
    map(
      {domain_name(), domain_name(), uint(32), uint(32), uint(32), uint(32), uint(32)},
      fn {mname, rname, serial, refresh, retry, expire, minimum} ->
        {:soa,
         %{
           mname: mname,
           rname: rname,
           serial: serial,
           refresh: refresh,
           retry: retry,
           expire: expire,
           minimum: minimum
         }}
      end
    )
  end

  defp mx_rdata do
    map({uint(16), domain_name()}, fn {pref, name} ->
      {:mx, %{preference: pref, name: name}}
    end)
  end

  # Arbitrary bytes incl. >255 bytes: create chunks into RFC 1035
  # character-strings, parse concatenates them back
  defp txt_rdata do
    map(binary(max_length: 600), &{:txt, %{txt: &1}})
  end

  # cpu/os are single-byte length-prefixed, so up to 255 bytes each
  defp hinfo_rdata do
    map({binary(max_length: 255), binary(max_length: 255)}, fn {cpu, os} ->
      {:hinfo, %{cpu: cpu, os: os}}
    end)
  end

  defp caa_rdata do
    map(
      {integer(0..255), string([?a..?z], min_length: 1, max_length: 15), binary(max_length: 50)},
      fn {flag, tag, value} -> {:caa, %{flag: flag, tag: tag, value: value}} end
    )
  end

  defp srv_rdata do
    map({uint(16), uint(16), uint(16), domain_name()}, fn {prio, weight, port, target} ->
      {:srv, %{priority: prio, weight: weight, port: port, target: target}}
    end)
  end

  defp naptr_rdata do
    map(
      {uint(16), uint(16), binary(max_length: 30), binary(max_length: 30), binary(max_length: 30),
       domain_name()},
      fn {order, pref, flags, services, regexp, replacement} ->
        {:naptr,
         %{
           order: order,
           preference: pref,
           flags: flags,
           services: services,
           regexp: regexp,
           replacement: replacement
         }}
      end
    )
  end

  defp dnskey_rdata do
    map({uint(16), integer(0..255), integer(0..255), binary(max_length: 64)}, fn
      {flags, protocol, algorithm, key} ->
        {:dnskey, %{flags: flags, protocol: protocol, algorithm: algorithm, public_key: key}}
    end)
  end

  defp ds_rdata do
    map({uint(16), integer(0..255), integer(0..255), binary(max_length: 64)}, fn
      {key_tag, algorithm, digest_type, digest} ->
        {:ds, %{key_tag: key_tag, algorithm: algorithm, digest_type: digest_type, digest: digest}}
    end)
  end

  defp rrsig_rdata do
    map(
      fixed_map(%{
        type_covered: uint(16),
        algorithm: integer(0..255),
        labels: integer(0..255),
        original_ttl: uint(32),
        signature_expiration: uint(32),
        signature_inception: uint(32),
        key_tag: uint(16),
        signer_name: domain_name(),
        signature: binary(max_length: 64)
      }),
      &{:rrsig, &1}
    )
  end

  # Subset of known types, canonically sorted by type code (bitmap order)
  defp nsec_rdata do
    types = [:a, :ns, :cname, :soa, :ptr, :mx, :txt, :aaaa, :srv, :ds, :rrsig, :nsec, :dnskey]

    map({domain_name(), list_of(member_of(types), min_length: 1, max_length: 6)}, fn
      {next, bitmap_types} ->
        canonical = bitmap_types |> Enum.uniq() |> Enum.sort_by(&DNS.type_code/1)
        {:nsec, %{next_domain_name: next, type_bit_maps: canonical}}
    end)
  end

  defp svcb_rdata(type) do
    map({uint(16), domain_name(), svc_params()}, fn {prio, target, params} ->
      {type, %{priority: prio, target: target, svc_params: params}}
    end)
  end

  defp svc_params do
    optional_map(%{
      alpn:
        list_of(string([?a..?z, ?0..?9], min_length: 1, max_length: 8),
          min_length: 1,
          max_length: 3
        ),
      port: uint(16),
      ipv4_hints: list_of(ipv4(), min_length: 1, max_length: 3),
      ipv6_hints: list_of(ipv6(), min_length: 1, max_length: 3)
    })
  end

  # --- EDNS ----------------------------------------------------------

  @doc """
  Generates flat (hybrid) edns_info maps: base fields plus a random
  subset of options, every value in canonical parsed form.
  """
  def edns_info do
    base =
      fixed_map(%{
        payload_size: integer(512..4096),
        dnssec: integer(0..1)
      })

    map({base, list_of(edns_option_flat(), max_length: 4)}, fn {info, options} ->
      Enum.reduce(options, info, &Map.merge(&2, &1))
    end)
  end

  # One generator per option, producing its flattened key set
  defp edns_option_flat do
    one_of(
      [ecs_flat(), cookie_flat(), llq_flat()] ++
        edns_scalar_option_gens() ++ edns_list_option_gens() ++ edns_binary_option_gens()
    )
  end

  defp edns_scalar_option_gens do
    [
      map(integer(0..64), &%{padding_length: &1}),
      map(uint(32), &%{edns_expire_expire: &1}),
      map(uint(16), &%{edns_client_tag_tag: &1}),
      map(uint(16), &%{edns_server_tag_tag: &1}),
      map(uint(32), &%{update_lease_lease: &1}),
      map(uint(32), &%{umbrella_ident_ident: &1}),
      map(uint(16), &%{edns_tcp_keepalive_timeout: &1, edns_tcp_keepalive_raw_data: nil})
    ]
  end

  defp edns_list_option_gens do
    [
      map(algorithm_list(), &%{dau_algorithms: &1}),
      map(algorithm_list(), &%{dhu_algorithms: &1}),
      map(algorithm_list(), &%{n3u_algorithms: &1}),
      map(list_of(uint(16), min_length: 1, max_length: 4), &%{edns_key_tag_key_tags: &1})
    ]
  end

  defp edns_binary_option_gens do
    [
      # NSID round-trips only for valid UTF-8: decode_option/2 hex-encodes
      # non-UTF-8 payloads by design (edns.ex), so generate strings
      map(string(:printable, max_length: 32), &%{nsid: &1}),
      map({uint(16), string(:alphanumeric, max_length: 30)}, fn {code, text} ->
        %{extended_dns_error_info_code: code, extended_dns_error_extra_text: text}
      end),
      map(wire_domain_name(), &%{chain_closest_encloser: &1}),
      map(wire_domain_name(), &%{report_channel_agent_domain: &1}),
      map(binary(min_length: 1, max_length: 16), &%{deviceid_device_id: &1})
    ]
  end

  defp algorithm_list do
    list_of(integer(0..255), min_length: 1, max_length: 4)
  end

  defp llq_flat do
    map({uint(16), uint(16), uint(16), uint(64), uint(32)}, fn
      {version, opcode, error, id, lease} ->
        %{
          llq_version: version,
          llq_llq_opcode: opcode,
          llq_error_code: error,
          llq_llq_id: id,
          llq_lease_life: lease
        }
    end)
  end

  # client_subnet must be pre-masked to source_prefix: the wire format
  # carries only ceil(prefix/8) bytes, so bits beyond the prefix would
  # not survive the round-trip
  defp ecs_flat do
    map({ipv4(), integer(0..32)}, fn {addr, prefix} ->
      %{
        ecs_family: 1,
        ecs_subnet: mask_ipv4(addr, prefix),
        ecs_source_prefix: prefix,
        ecs_scope_prefix: 0
      }
    end)
  end

  defp cookie_flat do
    map({binary(length: 8), one_of([constant(nil), binary(min_length: 8, max_length: 32)])}, fn
      {client, server} -> %{cookie_client: client, cookie_server: server}
    end)
  end

  defp mask_ipv4({a, b, c, d}, prefix) do
    <<keep::bitstring-size(^prefix), _::bitstring>> = <<a, b, c, d>>
    <<m1, m2, m3, m4>> = <<keep::bitstring, 0::size(32 - prefix)>>
    {m1, m2, m3, m4}
  end

  defp uint(bits), do: integer(0..(Integer.pow(2, bits) - 1))
end
