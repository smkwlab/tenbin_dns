defmodule DNSpacket do
  # Inline frequently called small functions for better performance
  @compile {:inline, [
    create_character_string: 1,
    add_rdlength: 1,
    concat_binary_list: 1
  ]}

  defstruct id: 0, qr: 0, opcode: 0, aa: 0, tc: 0, rd: 0, ra: 0, z: 0, ad: 0, cd: 0, rcode: 0,
               question: [], answer: [], authority: [], additional: []

  @spec create(%DNSpacket{}) :: <<_::64, _::_*8>>
  def create(packet) do
    create_optimized(packet)
  end

  # Optimized packet creation using iolists to reduce memory allocations
  defp create_optimized(packet) do
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
    |> Enum.map(fn n -> create_question_item(n) end)
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
    |> Enum.map(fn n -> create_rr(n) end)
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

    {body, _, _, question}   = parse_question(body, qdcount, orig_body, [])
    {body, _, _, answer}     = parse_answer(body, ancount, orig_body, [])
    {body, _, _, authority}  = parse_answer(body, nscount, orig_body, [])
    {_,    _, _, additional} = parse_answer(body, arcount, orig_body, [])

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
    parse_answer(body, count - 1, orig_body,
      [%{
          name: name,
          type: DNS.type(type),
          class: DNS.class(class),
          ttl: ttl,
          rdlength: rdlength,
          rdata: parse_rdata(rdata, DNS.type(type) || type, DNS.class(class) || class, orig_body)
       }  | result])
  end

  defp parse_name(<<0x0::size(8),body::binary>>, orig_body, "") do
    {body, orig_body, "."}
  end

  defp parse_name(<<0x0::size(8),body::binary>>, orig_body, result) do
    {body, orig_body, result}
  end

  defp parse_name(<<0b11   :: unsigned-integer-size(2),
                    offset :: unsigned-integer-size(14),
                    body   :: binary>>, orig_body, result) do
    <<_::binary-size(offset), tmp_body::binary>> = orig_body
    {_, _, name} = parse_name(tmp_body, orig_body, result)
    {body, orig_body, name}
  end

  defp parse_name(<<length :: unsigned-integer-size(8),
                    name   :: binary-size(length),
                    body   :: binary>>, orig_body, result) do
    parse_name(body, orig_body, result <> name <> ".")
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
