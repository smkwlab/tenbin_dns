defmodule DNSpacket do
  @moduledoc """
  DNS packet parsing and creation module.

  This module provides functionality for creating and parsing DNS packets
  according to RFC 1035 and related specifications. It supports standard
  DNS records (A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA) and EDNS0
  extensions including OPT records.

  The module is optimized for high performance with compile-time optimizations,
  aggressive function inlining, and efficient binary pattern matching.
  """

  import Bitwise

  # Aggressive inlining for maximum speed (over memory efficiency)
  @compile {:inline, [
    create_character_string: 1,
    add_rdlength: 1,
    concat_binary_list: 1,
    parse_name: 3,
    parse_name_acc: 3,
    parse_rdata: 4,
    parse_question_fast: 4,
    parse_answer_fast: 4,
    parse_answer_checkopt_fast: 6
  ]}
  
  # Compile-time optimization for maximum speed
  @compile [:native, {:hipe, [:verbose, :o3]}]

  defstruct id: 0, qr: 0, opcode: 0, aa: 0, tc: 0, rd: 0, ra: 0, z: 0, ad: 0, cd: 0, rcode: 0,
               question: [], answer: [], authority: [], additional: [], edns_info: nil

  @type t :: %__MODULE__{
    id: non_neg_integer(),
    qr: 0 | 1,
    opcode: non_neg_integer(),
    aa: 0 | 1,
    tc: 0 | 1,
    rd: 0 | 1,
    ra: 0 | 1,
    z: 0 | 1,
    ad: 0 | 1,
    cd: 0 | 1,
    rcode: non_neg_integer(),
    question: list(map()),
    answer: list(map()),
    authority: list(map()),
    additional: list(map()),
    edns_info: map() | nil
  }

  @spec create(t()) :: <<_::64, _::_*8>>
  def create(packet) do
    header = <<packet.id                ::16,
               packet.qr                ::1,
               packet.opcode            ::4,
               packet.aa                ::1,
               packet.tc                ::1,
               packet.rd                ::1,
               packet.ra                ::1,
               packet.z                 ::1,
               packet.ad                ::1,
               packet.cd                ::1,
               packet.rcode             ::4,
               length(packet.question)  ::16,
               length(packet.answer)    ::16,
               length(packet.authority) ::16,
               length(packet.additional)::16>>
    
    :erlang.iolist_to_binary([
      header,
      create_question(packet.question),
      create_answer(packet.answer),
      create_answer(packet.authority),
      create_answer(packet.additional)
    ])
  end

  def concat_binary_list(list), do: :erlang.iolist_to_binary(list)


  def create_question(question) do
    question
    |> Enum.map(&create_question_item(&1))
    |> concat_binary_list
  end

  @spec create_question_item(%{
          :qclass => any,
          :qname => binary,
          :qtype => any
        }) :: <<_::32, _::_*8>>
  def create_question_item(%{qname: qname, qtype: qtype, qclass: qclass}) do
    create_domain_name(qname) <> <<DNS.type_code(qtype)::16, DNS.class_code(qclass)::16>>
  end

  def create_answer(answer) do
    answer
    |> Enum.map(&create_rr(&1))
    |> concat_binary_list
  end

  # EDNS0
  def create_rr(%{type: :opt} = rr) do
    <<0, DNS.type_code(:opt)::16, rr.payload_size::16, rr.ex_rcode::8, rr.version::8, rr.dnssec::1, rr.z::15>> <>
      (rr.rdata
      |> Enum.map(&(create_options(&1)))
      |> concat_binary_list
      |> add_rdlength)
  end

  def create_rr(rr) do
    create_domain_name(rr.name) <>
    <<DNS.type_code(rr.type)::16, DNS.class_code(rr.class)::16, rr.ttl::32>> <>
    (rr.rdata |> create_rdata(rr.type, rr.class) |> add_rdlength)
  end

  # FIXME
  def create_options(_) do
    ""
  end

  def create_rdata(%{addr: {a, b, c, d}}, :a, :in) do
    <<a::8, b::8, c::8, d::8>>
  end

  def create_rdata(rdata, :ns, _) do
    create_domain_name(rdata.name)
  end

  def create_rdata(rdata, :cname, _) do
    create_domain_name(rdata.name)
  end

  def create_rdata(rdata, :soa, _) do
    create_domain_name(rdata.mname) <>
    create_domain_name(rdata.rname) <>
    <<rdata.serial ::32,
      rdata.refresh::32,
      rdata.retry  ::32,
      rdata.expire ::32,
      rdata.minimum::32,
    >>
  end

  def create_rdata(rdata, :ptr, _) do
    create_domain_name(rdata.name)
  end

  def create_rdata(rdata, :mx, _) do
    <<rdata.preference::16>> <> create_domain_name(rdata.name)
  end

  def create_rdata(rdata, :txt, _) do
    create_character_string(rdata.txt)
  end

  def create_rdata(%{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}, :aaaa, :in) do
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
  end

  # EDNS0
  def create_opt_rr(option), do: create_opt_rr(option, <<>>)
  def create_opt_rr([], result), do: result

  def create_opt_rr([option| tail], result) do
    # FIXME
    item = option
    create_opt_rr(tail, result <> item)
  end

  defp add_rdlength(rdata), do: <<byte_size(rdata)::16>> <> rdata

  def create_domain_name(name) do
    name
    |> String.split(".")
    |> Enum.map(&create_character_string/1)
    |> concat_binary_list
  end

  def create_character_string(txt), do: <<byte_size(txt)::8, txt::binary>>

  # Speed-optimized parse function with reduced function call overhead
  # credo:disable-for-next-line Credo.Check.Refactor.ABCSize
  def parse(
    <<
    id      :: unsigned-integer-size(16),
    qr      :: size(1),
    opcode  :: size(4),
    aa      :: size(1),
    tc      :: size(1),
    rd      :: size(1),
    ra      :: size(1),
    z       :: size(1),
    ad      :: size(1),
    cd      :: size(1),
    rcode   :: size(4),
    qdcount :: unsigned-integer-size(16),
    ancount :: unsigned-integer-size(16),
    nscount :: unsigned-integer-size(16),
    arcount :: unsigned-integer-size(16),
    body    :: binary,
    >> = orig_body) do

    # Inline parsing for maximum speed
    {rest1, question}   = parse_question_fast(body, qdcount, orig_body, [])
    {rest2, answer}     = parse_answer_fast(rest1, ancount, orig_body, [])
    {rest3, authority}  = parse_answer_fast(rest2, nscount, orig_body, [])
    {_, additional}     = parse_answer_fast(rest3, arcount, orig_body, [])

    edns_info = parse_edns_info(additional)

    %DNSpacket{
      id: id,
      qr: qr,
      opcode: opcode,
      aa: aa,
      tc: tc,
      rd: rd,
      ra: ra,
      z: z,
      ad: ad,
      cd: cd,
      rcode: rcode,
      question: question,
      answer: answer,
      authority: authority,
      additional: additional,
      edns_info: edns_info,
    }
  end

  # Fast parsing functions with reduced overhead
  defp parse_question_fast(body, 0, _orig_body, result), do: {body, result}
  
  defp parse_question_fast(body, count, orig_body, result) do
    {new_body, _, qname} = parse_name(body, orig_body, "")
    <<
    qtype  :: unsigned-integer-size(16),
    qclass :: unsigned-integer-size(16),
    rest   :: binary,
    >> = new_body
    # Pre-cache DNS lookups
    qtype_atom = DNS.type(qtype)
    qclass_atom = DNS.class(qclass)
    parse_question_fast(rest, count - 1, orig_body,
      [%{qname: qname, qtype: qtype_atom, qclass: qclass_atom} | result])
  end

  defp parse_answer_fast(body, 0, _orig_body, result), do: {body, result}

  defp parse_answer_fast(body, count, orig_body, result) do
    {new_body, _, name} = parse_name(body, orig_body, "")
    <<
    type :: unsigned-integer-size(16),
    rest :: binary,
    >> = new_body
    parse_answer_checkopt_fast(rest, type, name, count, orig_body, result)
  end

  # OPT Record : 41 - Fast version
  defp parse_answer_checkopt_fast(<<size     :: unsigned-integer-size(16),
                                   ex_rcode :: unsigned-integer-size(8),
                                   version  :: unsigned-integer-size(8),
                                   dnssec   :: size(1),
                                   z        :: size(15),
                                   rdlength :: unsigned-integer-size(16),
                                   rdata    :: binary-size(rdlength),
                                   body     :: binary>>,
    41, name, count, orig_body, result) do
    parse_answer_fast(body, count - 1, orig_body,
      [%{
          name: name,
          type: :opt,
          payload_size: size,
          ex_rcode: ex_rcode,
          version: version,
          dnssec: dnssec,
          z: z,
          rdlength: rdlength,
          rdata: parse_opt_rr([], rdata),
       }  | result])
  end

  defp parse_answer_checkopt_fast(<<class    :: unsigned-integer-size(16),
                                   ttl      :: unsigned-integer-size(32),
                                   rdlength :: unsigned-integer-size(16),
                                   rdata    :: binary-size(rdlength),
                                   body     :: binary>>,
    type, name, count, orig_body, result) do
    # Cache DNS lookups to avoid double lookups
    type_atom = DNS.type(type)
    class_atom = DNS.class(class)
    parse_answer_fast(body, count - 1, orig_body,
      [%{
          name: name,
          type: type_atom,
          class: class_atom,
          ttl: ttl,
          rdlength: rdlength,
          rdata: parse_rdata(rdata, type_atom || type, class_atom || class, orig_body)
       }  | result])
  end

  # Optimized parse_name using iolist accumulator for better performance
  defp parse_name(body, orig_body, "") do
    parse_name_acc(body, orig_body, [])
  end

  defp parse_name(body, orig_body, result) do
    parse_name_acc(body, orig_body, [result])
  end

  defp parse_name_acc(<<0::8, body::binary>>, orig_body, []) do
    {body, orig_body, "."}
  end

  defp parse_name_acc(<<0::8, body::binary>>, orig_body, acc) do
    {body, orig_body, :erlang.iolist_to_binary(Enum.reverse(acc))}
  end

  defp parse_name_acc(<<0b11::2, offset::14, body::binary>>, orig_body, acc) do
    <<_::binary-size(offset), tmp_body::binary>> = orig_body
    {_, _, name} = parse_name_acc(tmp_body, orig_body, [])
    {body, orig_body, :erlang.iolist_to_binary(Enum.reverse([name | acc]))}
  end

  defp parse_name_acc(<<length::8, name::binary-size(length), body::binary>>, orig_body, acc) do
    parse_name_acc(body, orig_body, ["." | [name | acc]])
  end

  def parse_rdata(<<a1::8, a2::8, a3::8, a4::8>>, :a, :in, _) do
    %{
      addr: {a1, a2, a3, a4}
    }
  end

  def parse_rdata(rdata, :ns, _, orig_body) do
    {_, _, name} = parse_name(rdata, orig_body, "")
    %{
      name: name,
    }
  end

  def parse_rdata(rdata, :cname, _, orig_body) do
    {_, _, name} = parse_name(rdata, orig_body, "")
    %{
      name: name,
    }
  end

  def parse_rdata(rdata, :soa, _, orig_body) do
    {rest1, _, mname} = parse_name(rdata, orig_body, "")
    {rest2, _, rname} = parse_name(rest1, orig_body, "")
    <<
    serial  :: unsigned-integer-size(32),
    refresh :: unsigned-integer-size(32),
    retry   :: unsigned-integer-size(32),
    expire  :: unsigned-integer-size(32),
    minimum :: unsigned-integer-size(32),
    >> = rest2
    %{
      mname: mname,
      rname: rname,
      serial: serial,
      refresh: refresh,
      retry: retry,
      expire: expire,
      minimum: minimum,
    }
  end

  def parse_rdata(rdata, :ptr, _, orig_body) do
    {_, _, name} = parse_name(rdata, orig_body, "")
    %{
      name: name,
    }
  end

  def parse_rdata(<<cpu_length :: unsigned-integer-size(8),
                     cpu       :: binary-size(cpu_length),
                     os_length :: unsigned-integer-size(8),
                     os        :: binary-size(os_length)>>, :hinfo, _, _) do
    %{
      cpu: cpu,
      os: os,
    }
  end

  def parse_rdata(<<preference :: unsigned-integer-size(16),
                   tmp_body    :: binary>>, :mx, _, orig_body) do
    {_, _, name} = parse_name(tmp_body, orig_body, "")
    %{
      preference: preference,
      name: name,
    }
  end

  # FIXME
  # does not support multiple character strings TXT record
  def parse_rdata(<<length :: unsigned-integer-size(8),
                    txt    :: binary-size(length), _::binary>>, :txt, _, _) do
    %{
      txt: txt,
    }
  end

  def parse_rdata(<<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>, :aaaa, :in, _) do
    %{
      addr: {a1, a2, a3, a4, a5, a6, a7, a8},
    }
  end

  def parse_rdata(<<flag       :: unsigned-integer-size(8),
                    tag_length :: unsigned-integer-size(8),
                    tag        :: binary-size(tag_length),
                    value      :: binary>>, :caa, _, _) do
    %{
      flag: flag,
      tag: tag,
      value: value,
    }
  end

  def parse_rdata(rdata, type, class, _) do
    %{type: type, class: class, rdata: rdata}
  end

  def parse_opt_rr(result, <<>>) do
    result
  end

  def parse_opt_rr(result,
    <<
    code   :: 16,
    length :: 16,
    data   :: binary-size(length),
    opt_rr :: binary,
    >>) do
    parse_opt_rr([parse_opt_code(DNS.option(code), data) | result], opt_rr)
  end

  def parse_opt_code(:edns_client_subnet, <<family::16, source::8, scope::8, address::binary>>) do
    %{code: :edns_client_subnet, family: family, source: source, scope: scope, addr: address}
  end

  def parse_opt_code(:extended_dns_error, <<option_code::16, _length::16, info_code::16, txt::binary>>) do
    %{code: :extended_dns_error, option_code: option_code, info_code: info_code, txt: txt}
  end

  def parse_opt_code(:cookie, cookie) do
    %{code: :cookie, cookie: cookie}
  end

  def parse_opt_code(code, data) do
    %{code: code, data: data}
  end

  def check_ecs([]), do: %{family: 0, scope: 0, addr: 0, source: 0}
  def check_ecs(additional) do
    case Enum.find(additional, &match?(%{type: :opt}, &1)) do
      %{rdata: rdata} ->
        Enum.find(rdata, %{family: 0, scope: 0, addr: 0, source: 0}, 
                  &match?(%{code: :edns_client_subnet}, &1))
      _ -> %{family: 0, scope: 0, addr: 0, source: 0}
    end
  end

  @doc """
  Parses EDNS information from additional records into a structured format.
  
  Returns a map with parsed EDNS options for easy access, or nil if no EDNS data found.
  Supports ECS (EDNS Client Subnet), cookies, NSID, extended DNS errors, and other options.
  """
  def parse_edns_info(additional) do
    case Enum.find(additional, &match?(%{type: :opt}, &1)) do
      %{rdata: rdata} = opt_record ->
        parsed_options = parse_edns_options(rdata)
        %{
          payload_size: Map.get(opt_record, :payload_size, 512),
          ex_rcode: Map.get(opt_record, :ex_rcode, 0),
          version: Map.get(opt_record, :version, 0),
          dnssec: Map.get(opt_record, :dnssec, 0),
          z: Map.get(opt_record, :z, 0),
          options: parsed_options
        }
      _ -> nil
    end
  end

  defp parse_edns_options(rdata) do
    Enum.reduce(rdata, %{}, fn option, acc ->
      case option.code do
        :edns_client_subnet ->
          Map.put(acc, :ecs, parse_ecs_option(option))
        :cookie ->
          Map.put(acc, :cookie, parse_cookie_option(option))
        :nsid ->
          Map.put(acc, :nsid, parse_nsid_option(option))
        :extended_dns_error ->
          Map.put(acc, :extended_dns_error, parse_extended_dns_error_option(option))
        :edns_tcp_keepalive ->
          Map.put(acc, :tcp_keepalive, parse_tcp_keepalive_option(option))
        :padding ->
          Map.put(acc, :padding, parse_padding_option(option))
        _ ->
          # Store unknown options in a generic format
          unknown_options = Map.get(acc, :unknown, [])
          Map.put(acc, :unknown, [option | unknown_options])
      end
    end)
  end

  defp parse_ecs_option(%{family: family, source: source, scope: scope, addr: addr}) do
    %{
      family: family,
      client_subnet: parse_ecs_address(family, addr, source),
      source_prefix: source,
      scope_prefix: scope
    }
  end

  defp parse_ecs_address(1, addr_bytes, prefix_len) when is_binary(addr_bytes) do
    # IPv4 address
    padded = pad_address(addr_bytes, 4)
    <<a::8, b::8, c::8, d::8>> = padded
    apply_prefix_mask({a, b, c, d}, prefix_len, 32)
  end

  defp parse_ecs_address(2, addr_bytes, prefix_len) when is_binary(addr_bytes) do
    # IPv6 address
    padded = pad_address(addr_bytes, 16)
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>> = padded
    apply_prefix_mask({a1, a2, a3, a4, a5, a6, a7, a8}, prefix_len, 128)
  end

  defp parse_ecs_address(_, addr_bytes, _prefix_len) do
    # Unknown family, return raw bytes
    addr_bytes
  end

  defp pad_address(addr_bytes, target_size) do
    current_size = byte_size(addr_bytes)
    if current_size < target_size do
      addr_bytes <> <<0::size((target_size - current_size) * 8)>>
    else
      binary_part(addr_bytes, 0, target_size)
    end
  end

  defp apply_prefix_mask(addr_tuple, prefix_len, max_bits) when prefix_len >= max_bits do
    addr_tuple
  end

  defp apply_prefix_mask(addr_tuple, prefix_len, _max_bits) when prefix_len <= 0 do
    # Return zeroed address for prefix length 0 or negative
    case tuple_size(addr_tuple) do
      4 -> {0, 0, 0, 0}
      8 -> {0, 0, 0, 0, 0, 0, 0, 0}
      _ -> addr_tuple
    end
  end

  defp apply_prefix_mask(addr_tuple, prefix_len, max_bits) do
    # Apply prefix mask by zeroing bits beyond prefix length
    addr_list = Tuple.to_list(addr_tuple)
    element_bits = div(max_bits, length(addr_list))

    {masked_list, _} = Enum.map_reduce(addr_list, prefix_len, fn element, remaining_bits ->
      cond do
        remaining_bits <= 0 ->
          {0, 0}
        min(remaining_bits, element_bits) >= element_bits ->
          {element, remaining_bits - element_bits}
        true ->
          bits_to_keep = min(remaining_bits, element_bits)
          mask = bnot((1 <<< (element_bits - bits_to_keep)) - 1)
          {element &&& mask, 0}
      end
    end)

    List.to_tuple(masked_list)
  end

  defp parse_cookie_option(%{cookie: cookie_data}) do
    case byte_size(cookie_data) do
      8 ->
        %{client: cookie_data, server: nil}
      size when size >= 16 and size <= 40 ->
        <<client::binary-size(8), server::binary>> = cookie_data
        %{client: client, server: server}
      _ ->
        %{client: cookie_data, server: nil}
    end
  end

  defp parse_nsid_option(%{data: nsid_data}) do
    # NSID is typically ASCII text
    case String.valid?(nsid_data) do
      true -> nsid_data
      false -> Base.encode16(nsid_data, case: :lower)
    end
  end

  defp parse_extended_dns_error_option(%{info_code: info_code, txt: txt}) do
    %{
      info_code: info_code,
      extra_text: txt
    }
  end

  defp parse_tcp_keepalive_option(%{data: data}) do
    case byte_size(data) do
      0 -> %{timeout: nil}
      2 -> 
        <<timeout::16>> = data
        %{timeout: timeout}
      _ -> %{timeout: nil, raw_data: data}
    end
  end

  defp parse_padding_option(%{data: data}) do
    %{length: byte_size(data)}
  end
end
