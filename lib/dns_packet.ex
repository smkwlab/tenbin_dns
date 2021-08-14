defmodule DNSpacket do
  def create(%{id: id, flags: flags, question: question, answer: answer, authority: authority, additional: additional}) do
    <<id                ::16,
      flags             ::16,
      length(question)  ::16,
      length(answer)    ::16,
      length(authority) ::16,
      length(additional)::16>> <>
    create_question(question) <>
    create_answer(answer) <>
    create_answer(authority) <>
    create_answer(additional)
  end

  def create_question(list, result \\ "")

  def create_question([], result) do
    result
  end

  def create_question([question | tail], result) do
    create_question(tail, result <> create_question_item(question))
  end

  def create_question_item(%{qname: qname, qtype: qtype, qclass: qclass}) do
    create_domain_name(qname) <> <<DNS.type[qtype]::16, DNS.class[qclass]::16>>
  end

  def create_answer(rrs, result \\ "")

  def create_answer([], result) do
    result
  end

  def create_answer([rr | tail], result) do
    create_answer(tail, result <> create_rr(rr))
  end

  def create_rr(%{name: name, type: type, class: class, ttl: ttl, rdata: rdata}) do
    create_domain_name(name) <>
    <<DNS.type[type]::16, DNS.class[class]::16, ttl::32>> <> 
    add_rdlength(create_rdata(type, class, rdata))
  end

  def create_rdata(:a, :in, rdata) do
    rdata.addr
  end

  def create_rdata(:ns, _, rdata) do
    create_domain_name(rdata.name)
  end

  def create_rdata(:cname, _, rdata) do
    create_domain_name(rdata.name)
  end

  def create_rdata(:soa, _, rdata) do
    create_domain_name(rdata.mname) <>
    create_domain_name(rdata.rname) <>
    <<rdata.serial ::32,
      rdata.refresh::32,
      rdata.retry  ::32,
      rdata.expire ::32,
      rdata.minimum::32,
    >>
  end

  def create_rdata(:ptr, _, rdata) do
    create_domain_name(rdata.name)
  end

  def create_rdata(:mx, _, rdata) do
    <<rdata.preference::16>> <> create_domain_name(rdata.name)
  end

  def create_rdata(:txt, _, rdata) do
    create_character_string(rdata.txt)
  end

  def create_rdata(:aaaa, :in, rdata) do
    rdata.addr
  end

  defp add_rdlength(rdata) do
    <<byte_size(rdata)::16>> <> rdata
  end

  def create_domain_name(name) do
    create_domain_name_label(String.split(name, "."))
  end
  
  defp create_domain_name_label(label, result \\ <<>>)

  defp create_domain_name_label([], result) do
    result
  end

  defp create_domain_name_label([label | tail], result) do
    create_domain_name_label(tail, result <> create_character_string(label))
  end

  def create_character_string(txt) do
    <<String.length(txt)::8, txt::binary>>
  end

  def parse(
    <<
    id      :: unsigned-integer-size(16),
    qr      :: size(1),
    opcode  :: size(4),
    aa      :: size(1),
    tc      :: size(1),
    rd      :: size(1),
    ra      :: size(1),
    z       :: size(3),
    rcode   :: size(4),
    qdcount :: unsigned-integer-size(16),
    ancount :: unsigned-integer-size(16),
    nscount :: unsigned-integer-size(16),
    arcount :: unsigned-integer-size(16),
    body  :: binary,
    >> = orig_body) do
    
    {body,   offset, _orig_body, _count, question}   = parse_question(body, 12, orig_body, qdcount, [])
    {body,   offset, _orig_body, _count, answer}     = parse_answer(body, offset, orig_body, ancount, [])
    {body,   offset, _orig_body, _count, authority}  = parse_answer(body, offset, orig_body, nscount, [])
    {_body, _offset, _orig_body, _count, additional} = parse_answer(body, offset, orig_body, arcount, [])

    %{
      id: id,
      qr: qr,
      opcode: opcode,
      aa: aa,
      tc: tc,
      rd: rd,
      ra: ra,
      z: z,
      rcode: rcode,
      qdcount: qdcount,
      ancount: ancount,
      nscount: nscount,
      arcount: arcount,
      question: question,
      answer: answer,
      authority: authority,
      additional: additional,
    }
  end

  def parse_question(body, offset, orig_body, 0, result) do
    {body, offset, orig_body, 0, result}
  end
  
  def parse_question(body, offset, orig_body, count, result) do
    {body, offset, orig_body, qname} = parse_name(body, offset, orig_body, "")
    <<
    qtype  :: unsigned-integer-size(16),
    qclass :: unsigned-integer-size(16),
    body   :: binary,
    >> = body
    parse_question(body, offset + 4, orig_body, count - 1, [%{qname: qname, qtype: qtype, qclass: qclass} | result])
  end
  
  def parse_answer(body, offset, orig_body, 0, result) do
    {body, offset, orig_body, 0, result}
  end

  def parse_answer(body, offset, orig_body, count, result) do
    {body, offset, orig_body, name} = parse_name(body, offset, orig_body, "")
    <<
    type     :: unsigned-integer-size(16),
    class    :: unsigned-integer-size(16),
    ttl      :: unsigned-integer-size(32),
    rdlength :: unsigned-integer-size(16),
    rdata    :: binary-size(rdlength),
    body   :: binary,
    >> = body
    parse_answer(body, offset + 10 + rdlength, orig_body, count - 1,
      [%{
          name: name,
          type: DNS.type[type],
          class: DNS.class[class],
          ttl: ttl,
          rdlength: rdlength,
          rdata: parse_rdata(DNS.type[type], type, DNS.class[class], rdata, orig_body)
       } | result])
  end

  defp parse_name(
    <<
    0x0  :: unsigned-integer-size(8),
    body :: binary
    >>, offset, orig_body, result) do
    {body, offset+1, orig_body, result}
  end

  defp parse_name(
    <<
    0b11        :: unsigned-integer-size(2),
    name_offset :: unsigned-integer-size(14),
    body        :: binary,
    >>, offset, orig_body, result) do
    <<_dummy::binary-size(name_offset), tmp_body::binary>> = orig_body
    {_,_,_,name} = parse_name(tmp_body, offset, orig_body, result)
    {body, offset+2, orig_body, name}
  end

  defp parse_name(
    <<
    length :: unsigned-integer-size(8),
    name   :: binary-size(length),
    body   :: binary
    >>, offset, orig_body, result) do
    parse_name(body, offset+length+1, orig_body, result <> name <> ".")
  end

  def parse_rdata(:a, _t0, :in, <<addr::unsigned-integer-size(32)>>, _orig_body) do
    %{
      addr: addr,
    }
  end

  def parse_rdata(:ns, _t0, _class, rdata, orig_body) do
    {_,_,_,name} = parse_name(rdata, 0, orig_body, "")
    %{
      ns: name,
    }
  end

  def parse_rdata(:soa, _t0, _class, rdata, orig_body) do
    {rdata,_,_,mname} = parse_name(rdata, 0, orig_body, "")
    {rdata,_,_,rname} = parse_name(rdata, 0, orig_body, "")
    <<
    serial ::unsigned-integer-size(32),
    refresh::unsigned-integer-size(32),
    retry  ::unsigned-integer-size(32),
    expire ::unsigned-integer-size(32),
    minimum::unsigned-integer-size(32),
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
  

  def parse_rdata(:mx, _t0, _class,
    <<preference::unsigned-integer-size(16), tmp_body::binary>>, orig_body) do
    {_,_,_,name} = parse_name(tmp_body, 0, orig_body, "")
    %{
      preference: preference,
      name: name,
    }
  end

  # does not support multiple character strings TXT record
  def parse_rdata(:txt, _t0, _class,
    <<length::unsigned-integer-size(8), txt::binary-size(length), _rdata::binary>>, _orig_body) do
    %{
      txt: txt,
    }
  end

  def parse_rdata(:aaaa, _t0, :in, <<addr::unsigned-integer-size(128)>>, _orig_body) do
    %{
      addr: addr,
    }
  end

  def parse_rdata(:caa, _t0, _,
    <<
    flag      ::unsigned-integer-size(8),
    tag_length::unsigned-integer-size(8),
    tag       ::binary-size(tag_length),
    value     ::binary>>, _orig_body) do
    %{
      flag: flag,
      tag: tag,
      value: value,
    }
  end
end
