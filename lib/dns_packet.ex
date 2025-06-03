defmodule DNSpacket do
  # Aggressive inlining for maximum speed (over memory efficiency)
  @compile {:inline, [
    create_character_string: 1,
    add_rdlength: 1,
    concat_binary_list: 1,
    parse_name: 3,
    parse_name_acc: 3,
    parse_question: 4,
    parse_answer: 4,
    parse_answer_checkopt: 6,
    parse_rdata: 4,
    parse_question_fast: 4,
    parse_answer_fast: 4,
    parse_answer_checkopt_fast: 6
  ]}
  
  # Compile-time optimization for maximum speed
  @compile [:native, {:hipe, [:verbose, :o3]}]

  defstruct id: 0, qr: 0, opcode: 0, aa: 0, tc: 0, rd: 0, ra: 0, z: 0, ad: 0, cd: 0, rcode: 0,
               question: [], answer: [], authority: [], additional: []

  @spec create(%DNSpacket{}) :: <<_::64, _::_*8>>
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
    
    [
      header,
      create_question(packet.question),
      create_answer(packet.answer),
      create_answer(packet.authority),
      create_answer(packet.additional)
    ] |> :erlang.iolist_to_binary()
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
    {body, question}   = parse_question_fast(body, qdcount, orig_body, [])
    {body, answer}     = parse_answer_fast(body, ancount, orig_body, [])
    {body, authority}  = parse_answer_fast(body, nscount, orig_body, [])
    {_, additional}    = parse_answer_fast(body, arcount, orig_body, [])

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
    }
  end

  # Fast parsing functions with reduced overhead
  defp parse_question_fast(body, 0, _orig_body, result), do: {body, result}
  
  defp parse_question_fast(body, count, orig_body, result) do
    {body, _, qname} = parse_name(body, orig_body, "")
    <<
    qtype  :: unsigned-integer-size(16),
    qclass :: unsigned-integer-size(16),
    body   :: binary,
    >> = body
    # Pre-cache DNS lookups
    qtype_atom = DNS.type(qtype)
    qclass_atom = DNS.class(qclass)
    parse_question_fast(body, count - 1, orig_body,
      [%{qname: qname, qtype: qtype_atom, qclass: qclass_atom} | result])
  end

  defp parse_answer_fast(body, 0, _orig_body, result), do: {body, result}

  defp parse_answer_fast(body, count, orig_body, result) do
    {body, _, name} = parse_name(body, orig_body, "")
    <<
    type :: unsigned-integer-size(16),
    body :: binary,
    >> = body
    parse_answer_checkopt_fast(body, type, name, count, orig_body, result)
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
    # Single DNS lookups for speed
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

  def parse_question(body, 0, orig_body, result), do: {body, 0, orig_body, result}

  def parse_question(body, count, orig_body, result) do
    {body, _, qname} = parse_name(body, orig_body, "")
    <<
    qtype  :: unsigned-integer-size(16),
    qclass :: unsigned-integer-size(16),
    body   :: binary,
    >> = body
    parse_question(body, count - 1, orig_body,
      [%{qname: qname, qtype: DNS.type(qtype), qclass: DNS.class(qclass)} | result])
  end

  def parse_answer(body, 0, orig_body, result), do: {body, 0, orig_body, result}

  def parse_answer(body, count, orig_body, result) do
    {body, _, name} = parse_name(body, orig_body, "")
    <<
    type :: unsigned-integer-size(16),
    body :: binary,
    >> = body
    parse_answer_checkopt(body, type, name, count, orig_body, result)
  end

  # OPT Record : 41
  def parse_answer_checkopt(<<size     :: unsigned-integer-size(16),
                              ex_rcode :: unsigned-integer-size(8),
                              version  :: unsigned-integer-size(8),
                              dnssec   :: size(1),
                              z        :: size(15),
                              rdlength :: unsigned-integer-size(16),
                              rdata    :: binary-size(rdlength),
                              body     :: binary>>,
    41, name, count, orig_body, result) do
    parse_answer(body, count - 1, orig_body,
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

  def parse_answer_checkopt(<<class    :: unsigned-integer-size(16),
                              ttl      :: unsigned-integer-size(32),
                              rdlength :: unsigned-integer-size(16),
                              rdata    :: binary-size(rdlength),
                              body     :: binary>>,
    type, name, count, orig_body, result) do
    # Cache DNS lookups to avoid double lookups
    type_atom = DNS.type(type)
    class_atom = DNS.class(class)
    parse_answer(body, count - 1, orig_body,
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

  def parse_rdata(<<a1::8,a2::8,a3::8,a4::8>>, :a, :in, _) do
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
    {rdata, _, mname} = parse_name(rdata, orig_body, "")
    {rdata, _, rname} = parse_name(rdata, orig_body, "")
    <<
    serial  :: unsigned-integer-size(32),
    refresh :: unsigned-integer-size(32),
    retry   :: unsigned-integer-size(32),
    expire  :: unsigned-integer-size(32),
    minimum :: unsigned-integer-size(32),
    >> = rdata
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

  def parse_rdata(<<a1::16,a2::16,a3::16,a4::16,a5::16,a6::16,a7::16,a8::16>>, :aaaa, :in, _) do
    %{
      addr: {a1,a2,a3,a4,a5,a6,a7,a8},
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

  def parse_opt_code(:edns_client_subnet, <<family::16,source::8,scope::8,address::binary>>) do
    %{code: :edns_client_subnet, family: family, source: source, scope: scope, addr: address}
  end

  def parse_opt_code(:extended_dns_error, <<option_code::16,_length::16,info_code::16,txt::binary>>) do
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
end
