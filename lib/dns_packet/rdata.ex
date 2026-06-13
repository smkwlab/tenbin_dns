defmodule DNSpacket.RData do
  @moduledoc """
  Per-record-type rdata codec for DNS packets (#111).

  All knowledge about how a record type's rdata is laid out on the wire
  lives here: `encode/3` clauses build rdata binaries, `decode/4` clauses
  parse them back into the canonical rdata maps. Clauses are grouped by
  function (compiler requirement) and ordered the same way in both
  directions so a type's encode and decode stay easy to compare.

  Shared name codec (`create_domain_name/1`, `parse_name/3`,
  `create_character_string/1`) intentionally stays in `DNSpacket`: it is
  also used by the question/record framing on the hot parse/create paths,
  where the local calls keep their `@compile :inline` benefit.

  The round-trip contract is pinned by dns_packet_roundtrip_test.exs and
  the property suite (#107).

  ## Record rdata shapes

  Each record type's `rdata` is a map with the fields below. This is the
  shape `DNSpacket.parse/1` returns in every record's `:rdata`, and the
  shape `DNSpacket.create/1` expects, with one asymmetry: NSEC
  `type_bit_maps` is *returned* as a list of type atoms but `create/1`
  *also* accepts a pre-built bitmap binary (see `t:nsec_rdata/0`).

  Integer widths note the wire field size; addresses are `:inet` address
  tuples (4-element for IPv4, 8-element for IPv6). Domain names are dotted
  strings that must carry the trailing root label (`"example.com."`, not
  `"example.com"`) — `create/1` encodes labels verbatim and a missing
  trailing dot produces an unterminated name on the wire.

  | Type | Fields |
  |------|--------|
  | `:a` | `addr` (IPv4 tuple) |
  | `:aaaa` | `addr` (IPv6 tuple) |
  | `:ns` / `:cname` / `:ptr` | `name` |
  | `:dname` | `target` |
  | `:soa` | `mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum` (all 32-bit) |
  | `:mx` | `preference` (16-bit), `name` |
  | `:txt` | `txt` (binary; ≥256 bytes is split into RFC 1035 character-strings on encode and rejoined on decode, see #95) |
  | `:hinfo` | `cpu`, `os` (each ≤255-byte binary) |
  | `:caa` | `flag` (8-bit), `tag`, `value` |
  | `:srv` | `priority`, `weight`, `port` (16-bit), `target` |
  | `:naptr` | `order`, `preference` (16-bit), `flags`, `services`, `regexp`, `replacement` |
  | `:dnskey` | `flags` (16-bit), `protocol`, `algorithm` (8-bit), `public_key` |
  | `:ds` | `key_tag` (16-bit), `algorithm`, `digest_type` (8-bit), `digest` |
  | `:rrsig` | `type_covered` (16-bit), `algorithm`, `labels` (8-bit), `original_ttl`, `signature_expiration`, `signature_inception` (32-bit), `key_tag` (16-bit), `signer_name`, `signature` |
  | `:nsec` | `next_domain_name`, `type_bit_maps` (list of type atoms) |
  | `:svcb` / `:https` | `priority` (16-bit), `target`, `svc_params` (see `t:svc_params/0`) |

  Unknown record types decode to `%{type: type, class: class, rdata: binary}`
  (the raw rdata) and encode by passing a raw binary straight through.
  """

  import Bitwise

  @typedoc "IPv4 address record."
  @type a_rdata :: %{addr: :inet.ip4_address()}

  @typedoc "IPv6 address record."
  @type aaaa_rdata :: %{addr: :inet.ip6_address()}

  @typedoc "Single-name records: NS, CNAME, PTR."
  @type name_rdata :: %{name: String.t()}

  @typedoc "DNAME record (target rather than name)."
  @type dname_rdata :: %{target: String.t()}

  @typedoc "SOA record."
  @type soa_rdata :: %{
          mname: String.t(),
          rname: String.t(),
          serial: non_neg_integer(),
          refresh: non_neg_integer(),
          retry: non_neg_integer(),
          expire: non_neg_integer(),
          minimum: non_neg_integer()
        }

  @typedoc "MX record."
  @type mx_rdata :: %{preference: non_neg_integer(), name: String.t()}

  @typedoc """
  TXT record. The value is the concatenation of one or more RFC 1035
  character-strings; boundaries are not preserved (see #95).
  """
  @type txt_rdata :: %{txt: binary()}

  @typedoc "HINFO record."
  @type hinfo_rdata :: %{cpu: binary(), os: binary()}

  @typedoc "CAA record."
  @type caa_rdata :: %{flag: byte(), tag: binary(), value: binary()}

  @typedoc "SRV record."
  @type srv_rdata :: %{
          priority: non_neg_integer(),
          weight: non_neg_integer(),
          port: non_neg_integer(),
          target: String.t()
        }

  @typedoc "NAPTR record."
  @type naptr_rdata :: %{
          order: non_neg_integer(),
          preference: non_neg_integer(),
          flags: binary(),
          services: binary(),
          regexp: binary(),
          replacement: String.t()
        }

  @typedoc "DNSKEY record."
  @type dnskey_rdata :: %{
          flags: non_neg_integer(),
          protocol: byte(),
          algorithm: byte(),
          public_key: binary()
        }

  @typedoc "DS record."
  @type ds_rdata :: %{
          key_tag: non_neg_integer(),
          algorithm: byte(),
          digest_type: byte(),
          digest: binary()
        }

  @typedoc "RRSIG record."
  @type rrsig_rdata :: %{
          type_covered: non_neg_integer(),
          algorithm: byte(),
          labels: byte(),
          original_ttl: non_neg_integer(),
          signature_expiration: non_neg_integer(),
          signature_inception: non_neg_integer(),
          key_tag: non_neg_integer(),
          signer_name: String.t(),
          signature: binary()
        }

  @typedoc """
  NSEC record. On decode `type_bit_maps` is a list of type atoms (unknown
  codes stay as integers); on encode a raw bitmap binary is also accepted.
  """
  @type nsec_rdata :: %{
          next_domain_name: String.t(),
          type_bit_maps: [atom() | non_neg_integer()] | binary()
        }

  @typedoc """
  SVCB/HTTPS service parameters. Known keys are decoded to atoms; any other
  key stays as its numeric SvcParamKey with the raw value binary.
  """
  @type svc_params :: %{
          optional(:alpn) => [binary()],
          optional(:port) => non_neg_integer(),
          optional(:ipv4_hints) => [:inet.ip4_address()],
          optional(:ipv6_hints) => [:inet.ip6_address()],
          optional(non_neg_integer()) => binary()
        }

  @typedoc "SVCB / HTTPS record."
  @type svcb_rdata :: %{priority: non_neg_integer(), target: String.t(), svc_params: svc_params()}

  @typedoc """
  Fallback shape for record types without a dedicated codec clause: the raw
  rdata is kept verbatim alongside its type/class.
  """
  @type unknown_rdata :: %{type: atom(), class: atom(), rdata: binary()}

  @typedoc "Any record's rdata, in the canonical parsed/created form."
  @type rdata ::
          a_rdata()
          | aaaa_rdata()
          | name_rdata()
          | dname_rdata()
          | soa_rdata()
          | mx_rdata()
          | txt_rdata()
          | hinfo_rdata()
          | caa_rdata()
          | srv_rdata()
          | naptr_rdata()
          | dnskey_rdata()
          | ds_rdata()
          | rrsig_rdata()
          | nsec_rdata()
          | svcb_rdata()
          | unknown_rdata()

  # Fast paths keep their inlining within this module
  @compile {:inline,
            [
              parse_a_fast: 1,
              parse_aaaa_fast: 1
            ]}

  # --- encode --------------------------------------------------------

  @doc false
  def encode(%{addr: {a, b, c, d}}, :a, :in) do
    <<a::8, b::8, c::8, d::8>>
  end

  # :dname is kept separate from this group: its rdata field is .target, not .name
  @doc false
  def encode(rdata, type, _) when type in [:ns, :cname, :ptr] do
    DNSpacket.create_domain_name(rdata.name)
  end

  @doc false
  def encode(rdata, :soa, _) do
    DNSpacket.create_domain_name(rdata.mname) <>
      DNSpacket.create_domain_name(rdata.rname) <>
      <<rdata.serial::32, rdata.refresh::32, rdata.retry::32, rdata.expire::32,
        rdata.minimum::32>>
  end

  @doc false
  def encode(rdata, :mx, _) do
    <<rdata.preference::16>> <> DNSpacket.create_domain_name(rdata.name)
  end

  @doc false
  def encode(rdata, :txt, _) do
    create_character_strings(rdata.txt)
  end

  @doc false
  def encode(rdata, :hinfo, _) do
    <<byte_size(rdata.cpu)::8, rdata.cpu::binary, byte_size(rdata.os)::8, rdata.os::binary>>
  end

  @doc false
  def encode(%{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}, :aaaa, :in) do
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
  end

  @doc false
  def encode(rdata, :caa, _) do
    <<rdata.flag::8, byte_size(rdata.tag)::8, rdata.tag::binary, rdata.value::binary>>
  end

  @doc false
  def encode(rdata, :srv, _) do
    <<rdata.priority::16, rdata.weight::16, rdata.port::16>> <>
      DNSpacket.create_domain_name(rdata.target)
  end

  @doc false
  def encode(rdata, :naptr, _) do
    <<rdata.order::16, rdata.preference::16, byte_size(rdata.flags)::8, rdata.flags::binary,
      byte_size(rdata.services)::8, rdata.services::binary, byte_size(rdata.regexp)::8,
      rdata.regexp::binary>> <>
      DNSpacket.create_domain_name(rdata.replacement)
  end

  @doc false
  def encode(rdata, :dname, _) do
    DNSpacket.create_domain_name(rdata.target)
  end

  @doc false
  def encode(rdata, :dnskey, _) do
    <<rdata.flags::16, rdata.protocol::8, rdata.algorithm::8, rdata.public_key::binary>>
  end

  @doc false
  def encode(rdata, :ds, _) do
    <<rdata.key_tag::16, rdata.algorithm::8, rdata.digest_type::8, rdata.digest::binary>>
  end

  @doc false
  def encode(rdata, :rrsig, _) do
    <<rdata.type_covered::16, rdata.algorithm::8, rdata.labels::8, rdata.original_ttl::32,
      rdata.signature_expiration::32, rdata.signature_inception::32, rdata.key_tag::16>> <>
      DNSpacket.create_domain_name(rdata.signer_name) <>
      <<rdata.signature::binary>>
  end

  @doc false
  def encode(rdata, :nsec, _) do
    DNSpacket.create_domain_name(rdata.next_domain_name) <>
      create_type_bitmap(rdata.type_bit_maps)
  end

  @doc false
  def encode(rdata, type, _) when type in [:svcb, :https] do
    # SVCB/HTTPS support with Service Parameters
    target_name = DNSpacket.create_domain_name(rdata.target)
    svc_params = create_svc_params(Map.get(rdata, :svc_params, %{}))
    <<rdata.priority::16>> <> target_name <> svc_params
  end

  @doc false
  def encode(rdata, _, _) do
    # Fallback for unknown types
    rdata
  end

  # --- decode --------------------------------------------------------

  # Fast paths for A and AAAA records
  # Direct pattern matching with no function call overhead
  @doc false
  def parse_a_fast(<<a::8, b::8, c::8, d::8>>), do: %{addr: {a, b, c, d}}

  @doc false
  def parse_aaaa_fast(<<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>) do
    %{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}
  end

  # Optimized decode using fast paths with fallback to original behavior
  @doc false
  def decode(<<a::8, b::8, c::8, d::8>>, :a, :in, _), do: parse_a_fast(<<a, b, c, d>>)

  @doc false
  def decode(
        <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>,
        :aaaa,
        :in,
        _
      ) do
    parse_aaaa_fast(<<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>)
  end

  # :dname is kept separate from this group: its rdata field is .target, not .name
  @doc false
  def decode(rdata, type, _, orig_body) when type in [:ns, :cname, :ptr] do
    {_, _, name} = DNSpacket.parse_name(rdata, orig_body, "")

    %{
      name: name
    }
  end

  @doc false
  def decode(rdata, :soa, _, orig_body) do
    {rest1, _, mname} = DNSpacket.parse_name(rdata, orig_body, "")
    {rest2, _, rname} = DNSpacket.parse_name(rest1, orig_body, "")

    <<
      serial::unsigned-integer-size(32),
      refresh::unsigned-integer-size(32),
      retry::unsigned-integer-size(32),
      expire::unsigned-integer-size(32),
      minimum::unsigned-integer-size(32)
    >> = rest2

    %{
      mname: mname,
      rname: rname,
      serial: serial,
      refresh: refresh,
      retry: retry,
      expire: expire,
      minimum: minimum
    }
  end

  @doc false
  def decode(
        <<cpu_length::unsigned-integer-size(8), cpu::binary-size(cpu_length),
          os_length::unsigned-integer-size(8), os::binary-size(os_length)>>,
        :hinfo,
        _,
        _
      ) do
    %{
      cpu: cpu,
      os: os
    }
  end

  @doc false
  def decode(<<preference::unsigned-integer-size(16), tmp_body::binary>>, :mx, _, orig_body) do
    {_, _, name} = DNSpacket.parse_name(tmp_body, orig_body, "")

    %{
      preference: preference,
      name: name
    }
  end

  # RFC 1035 allows multiple character-strings per TXT record; the logical
  # value is their concatenation (cf. RFC 7208 §3.3 for SPF). String
  # boundaries are not preserved (see issue #95).
  @doc false
  def decode(rdata, :txt, _, _) do
    %{
      txt: parse_character_strings(rdata, [])
    }
  end

  @doc false
  def decode(
        <<flag::unsigned-integer-size(8), tag_length::unsigned-integer-size(8),
          tag::binary-size(tag_length), value::binary>>,
        :caa,
        _,
        _
      ) do
    %{
      flag: flag,
      tag: tag,
      value: value
    }
  end

  @doc false
  def decode(
        <<priority::unsigned-integer-size(16), weight::unsigned-integer-size(16),
          port::unsigned-integer-size(16), tmp_body::binary>>,
        :srv,
        _,
        orig_body
      ) do
    {_, _, target} = DNSpacket.parse_name(tmp_body, orig_body, "")

    %{
      priority: priority,
      weight: weight,
      port: port,
      target: target
    }
  end

  @doc false
  def decode(
        <<order::unsigned-integer-size(16), preference::unsigned-integer-size(16),
          flags_len::unsigned-integer-size(8), flags::binary-size(flags_len),
          services_len::unsigned-integer-size(8), services::binary-size(services_len),
          regexp_len::unsigned-integer-size(8), regexp::binary-size(regexp_len),
          tmp_body::binary>>,
        :naptr,
        _,
        orig_body
      ) do
    {_, _, replacement} = DNSpacket.parse_name(tmp_body, orig_body, "")

    %{
      order: order,
      preference: preference,
      flags: flags,
      services: services,
      regexp: regexp,
      replacement: replacement
    }
  end

  @doc false
  def decode(rdata, :dname, _, orig_body) do
    {_, _, target} = DNSpacket.parse_name(rdata, orig_body, "")

    %{
      target: target
    }
  end

  @doc false
  def decode(
        <<flags::unsigned-integer-size(16), protocol::unsigned-integer-size(8),
          algorithm::unsigned-integer-size(8), public_key::binary>>,
        :dnskey,
        _,
        _
      ) do
    %{
      flags: flags,
      protocol: protocol,
      algorithm: algorithm,
      public_key: public_key
    }
  end

  @doc false
  def decode(
        <<key_tag::unsigned-integer-size(16), algorithm::unsigned-integer-size(8),
          digest_type::unsigned-integer-size(8), digest::binary>>,
        :ds,
        _,
        _
      ) do
    %{
      key_tag: key_tag,
      algorithm: algorithm,
      digest_type: digest_type,
      digest: digest
    }
  end

  @doc false
  def decode(
        <<type_covered::unsigned-integer-size(16), algorithm::unsigned-integer-size(8),
          labels::unsigned-integer-size(8), original_ttl::unsigned-integer-size(32),
          signature_expiration::unsigned-integer-size(32),
          signature_inception::unsigned-integer-size(32), key_tag::unsigned-integer-size(16),
          tmp_body::binary>>,
        :rrsig,
        _,
        orig_body
      ) do
    {rest, _, signer_name} = DNSpacket.parse_name(tmp_body, orig_body, "")

    %{
      type_covered: type_covered,
      algorithm: algorithm,
      labels: labels,
      original_ttl: original_ttl,
      signature_expiration: signature_expiration,
      signature_inception: signature_inception,
      key_tag: key_tag,
      signer_name: signer_name,
      signature: rest
    }
  end

  @doc false
  def decode(rdata, :nsec, _, orig_body) do
    {rest, _, next_domain_name} = DNSpacket.parse_name(rdata, orig_body, "")
    type_bit_maps = parse_type_bitmap(rest)

    %{
      next_domain_name: next_domain_name,
      type_bit_maps: type_bit_maps
    }
  end

  @doc false
  def decode(<<priority::unsigned-integer-size(16), tmp_body::binary>>, type, _, orig_body)
      when type in [:svcb, :https] do
    # SVCB/HTTPS support with Service Parameters
    {rest, _, target} = DNSpacket.parse_name(tmp_body, orig_body, "")
    svc_params = parse_svc_params(rest)

    %{
      priority: priority,
      target: target,
      svc_params: svc_params
    }
  end

  @doc false
  def decode(rdata, type, class, _) do
    %{type: type, class: class, rdata: rdata}
  end

  # --- character strings (TXT) ---------------------------------------

  # Encode a binary as consecutive character-strings of at most 255 bytes
  # each (RFC 1035 §3.3.14); values up to 255 bytes produce the same single
  # character-string as before. Chunks are collected as iodata to avoid
  # repeated binary copying on long values.
  defp create_character_strings(txt) when byte_size(txt) <= 255 do
    DNSpacket.create_character_string(txt)
  end

  defp create_character_strings(txt) do
    txt |> chunk_character_strings([]) |> IO.iodata_to_binary()
  end

  # The terminal clause receives 1..255 bytes: the caller only enters the
  # loop with > 255 bytes, so the remainder after a 255-byte chunk is >= 1
  defp chunk_character_strings(txt, acc) when byte_size(txt) <= 255 do
    Enum.reverse([DNSpacket.create_character_string(txt) | acc])
  end

  defp chunk_character_strings(<<chunk::binary-size(255), rest::binary>>, acc) do
    chunk_character_strings(rest, [DNSpacket.create_character_string(chunk) | acc])
  end

  # Decode consecutive character-strings into their concatenation. Once a
  # length byte overruns the remaining data, that string and everything after
  # it is discarded — whether it is a truncated trailing string or a bogus
  # mid-stream length (graceful degradation; see "Malformed Input" in the
  # DNSpacket.parse/1 docs)
  defp parse_character_strings(<<length::8, txt::binary-size(length), rest::binary>>, acc) do
    parse_character_strings(rest, [txt | acc])
  end

  defp parse_character_strings(_, acc) do
    acc |> Enum.reverse() |> IO.iodata_to_binary()
  end

  # --- NSEC type bitmap ----------------------------------------------

  @doc false
  def create_type_bitmap(type_list) when is_list(type_list) do
    # Convert type atoms to numbers and create bitmap
    type_numbers = Enum.map(type_list, &DNS.type_code/1)
    create_type_bitmap_from_numbers(type_numbers)
  end

  def create_type_bitmap(bitmap) when is_binary(bitmap), do: bitmap

  defp create_type_bitmap_from_numbers(type_numbers) do
    # Group types by window (each window covers 256 types)
    windows = Enum.group_by(type_numbers, &div(&1, 256))

    # Create bitmap for each window
    Enum.reduce(windows, <<>>, fn {window, types}, acc ->
      bitmap = create_window_bitmap(types, window * 256)
      window_data = <<window::8, byte_size(bitmap)::8, bitmap::binary>>
      acc <> window_data
    end)
  end

  defp create_window_bitmap(types, window_base) do
    # Create bitmap for types within a window
    relative_types = Enum.map(types, &(&1 - window_base))
    max_type = Enum.max(relative_types)
    byte_count = div(max_type, 8) + 1

    # Initialize bitmap with zeros
    bitmap = <<0::size(byte_count * 8)>>

    # Set bits for each type
    Enum.reduce(relative_types, bitmap, fn type, acc ->
      byte_pos = div(type, 8)
      bit_pos = 7 - rem(type, 8)
      set_bit_in_bitmap(acc, byte_pos, bit_pos)
    end)
  end

  defp set_bit_in_bitmap(bitmap, byte_pos, bit_pos) do
    <<prefix::binary-size(^byte_pos), byte::8, suffix::binary>> = bitmap
    new_byte = byte ||| 1 <<< bit_pos
    prefix <> <<new_byte::8>> <> suffix
  end

  @doc false
  def parse_type_bitmap(<<>>), do: []

  def parse_type_bitmap(<<window::8, length::8, bitmap::binary-size(length), rest::binary>>) do
    types = parse_window_bitmap(bitmap, window * 256)
    types ++ parse_type_bitmap(rest)
  end

  # Return raw data if parsing fails
  def parse_type_bitmap(data), do: data

  defp parse_window_bitmap(bitmap, window_base) do
    bitmap
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.flat_map(fn {byte, byte_index} ->
      parse_byte_bitmap(byte, window_base + byte_index * 8)
    end)
  end

  defp parse_byte_bitmap(byte, base_type) do
    0..7
    |> Enum.filter(fn bit_pos ->
      (byte &&& 1 <<< (7 - bit_pos)) != 0
    end)
    |> Enum.map(fn bit_pos ->
      type_code = base_type + bit_pos
      DNS.type(type_code) || type_code
    end)
  end

  # --- SVCB/HTTPS service parameters ---------------------------------

  @doc false
  def create_svc_params(params) when is_map(params) do
    params
    |> Enum.sort_by(fn {key, _} -> svc_param_key_code(key) end)
    |> Enum.map(&create_svc_param/1)
    |> IO.iodata_to_binary()
  end

  def create_svc_params(_), do: <<>>

  defp create_svc_param({:alpn, alpn_list}) when is_list(alpn_list) do
    alpn_data =
      alpn_list
      |> Enum.map(&DNSpacket.create_character_string/1)
      |> IO.iodata_to_binary()

    <<1::16, byte_size(alpn_data)::16, alpn_data::binary>>
  end

  defp create_svc_param({:port, port}) when is_integer(port) do
    <<3::16, 2::16, port::16>>
  end

  defp create_svc_param({:ipv4_hints, ip_list}) when is_list(ip_list) do
    ip_data =
      ip_list
      |> Enum.map(fn {a, b, c, d} -> <<a::8, b::8, c::8, d::8>> end)
      |> IO.iodata_to_binary()

    <<4::16, byte_size(ip_data)::16, ip_data::binary>>
  end

  defp create_svc_param({:ipv6_hints, ip_list}) when is_list(ip_list) do
    ip_data =
      ip_list
      |> Enum.map(fn {a1, a2, a3, a4, a5, a6, a7, a8} ->
        <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
      end)
      |> IO.iodata_to_binary()

    <<6::16, byte_size(ip_data)::16, ip_data::binary>>
  end

  defp create_svc_param({key, value}) when is_integer(key) and is_binary(value) do
    # Generic parameter
    <<key::16, byte_size(value)::16, value::binary>>
  end

  defp create_svc_param(_), do: <<>>

  defp svc_param_key_code(:mandatory), do: 0
  defp svc_param_key_code(:alpn), do: 1
  defp svc_param_key_code(:no_default_alpn), do: 2
  defp svc_param_key_code(:port), do: 3
  defp svc_param_key_code(:ipv4_hints), do: 4
  defp svc_param_key_code(:ech), do: 5
  defp svc_param_key_code(:ipv6_hints), do: 6
  defp svc_param_key_code(key) when is_integer(key), do: key
  defp svc_param_key_code(_), do: 65_535

  @doc false
  def parse_svc_params(<<>>), do: %{}

  def parse_svc_params(<<key::16, length::16, value::binary-size(length), rest::binary>>) do
    param = parse_svc_param(key, value)
    Map.merge(param, parse_svc_params(rest))
  end

  def parse_svc_params(_), do: %{}

  defp parse_svc_param(1, alpn_data) do
    # ALPN parameter
    alpn_list = parse_alpn_list(alpn_data, [])
    %{alpn: alpn_list}
  end

  defp parse_svc_param(3, <<port::16>>) do
    # Port parameter
    %{port: port}
  end

  defp parse_svc_param(4, ip_data) do
    # IPv4 hints
    ipv4_list = parse_ipv4_hints(ip_data, [])
    %{ipv4_hints: ipv4_list}
  end

  defp parse_svc_param(6, ip_data) do
    # IPv6 hints
    ipv6_list = parse_ipv6_hints(ip_data, [])
    %{ipv6_hints: ipv6_list}
  end

  defp parse_svc_param(key, value) do
    # Generic parameter
    %{key => value}
  end

  defp parse_alpn_list(<<>>, acc), do: Enum.reverse(acc)

  defp parse_alpn_list(<<length::8, alpn::binary-size(length), rest::binary>>, acc) do
    parse_alpn_list(rest, [alpn | acc])
  end

  defp parse_alpn_list(_, acc), do: Enum.reverse(acc)

  defp parse_ipv4_hints(<<>>, acc), do: Enum.reverse(acc)

  defp parse_ipv4_hints(<<a::8, b::8, c::8, d::8, rest::binary>>, acc) do
    parse_ipv4_hints(rest, [{a, b, c, d} | acc])
  end

  defp parse_ipv4_hints(_, acc), do: Enum.reverse(acc)

  defp parse_ipv6_hints(<<>>, acc), do: Enum.reverse(acc)

  defp parse_ipv6_hints(
         <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16, rest::binary>>,
         acc
       ) do
    parse_ipv6_hints(rest, [{a1, a2, a3, a4, a5, a6, a7, a8} | acc])
  end

  defp parse_ipv6_hints(_, acc), do: Enum.reverse(acc)
end
