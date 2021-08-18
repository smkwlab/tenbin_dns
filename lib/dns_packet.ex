defmodule DNSpacket do
  def create(%{id: id, flags: flags, question: question, answer: answer, authority: authority, additional: additional}) do
    <<id                ::16,
      flags             ::16,
      length(question)  ::16,
      length(answer)    ::16,
      length(authority) ::16,
      length(additional)::16>> <>
      (question   |> create_question) <>
      (answer     |> create_answer) <>
      (authority  |> create_answer) <>
      (additional |> create_answer)
  end

  def concat_binary_list(list) do
    list
    |> Enum.reduce(<<>>, fn i, acc -> acc<>i end)
  end

  def create_question(question) do
    question
    |> Enum.map(fn n -> n |> create_question_item end)
    |> concat_binary_list
  end

  def create_question_item(%{qname: qname, qtype: qtype, qclass: qclass}) do
    (qname |> create_domain_name) <> <<DNS.type[qtype]::16, DNS.class[qclass]::16>>
  end

  def create_answer(answer) do
    answer
    |> Enum.map(fn n -> n |> create_rr end)
    |> concat_binary_list
  end

  # EDNS0
  def create_rr(%{type: :opt, size: size, rcode: rcode, rdata: rdata}) do
    <<0, DNS.type[:opt]::16, size::16, rcode::32>> <>
    <<rdata |> create_opt_rr |> add_rdlength>>
  end

  def create_rr(%{name: name, type: type, class: class, ttl: ttl, rdata: rdata}) do
    (name |> create_domain_name) <>
    <<DNS.type[type]::16, DNS.class[class]::16, ttl::32>> <> 
    (rdata |> create_rdata(type, class) |> add_rdlength)
  end

  def create_rdata(rdata, :a, :in) do
    rdata.addr
  end

  def create_rdata(rdata, :ns, _) do
    rdata.name |> create_domain_name
  end

  def create_rdata(rdata, :cname, _) do
    rdata.name |> create_domain_name
  end

  def create_rdata(rdata, :soa, _) do
    (rdata.mname |> create_domain_name) <>
    (rdata.rname |> create_domain_name) <>
    <<rdata.serial ::32,
      rdata.refresh::32,
      rdata.retry  ::32,
      rdata.expire ::32,
      rdata.minimum::32,
    >>
  end

  def create_rdata(rdata, :ptr, _) do
    rdata.name |> create_domain_name
  end

  def create_rdata(rdata, :mx, _) do
    <<rdata.preference::16>> <> (rdata.name |> create_domain_name)
  end

  def create_rdata(rdata, :txt, _) do
    rdata.txt |> create_character_string
  end

  def create_rdata(rdata, :aaaa, :in) do
    rdata.addr
  end

  # EDNS0
  def create_opt_rr(option, result \\ <<>>)

  def create_opt_rr([], result) do
    result
  end

  def create_opt_rr([option| tail], result) do
    # XXX
    item = option
    tail |> create_opt_rr(result <> item)
  end

  defp add_rdlength(rdata) do
    <<byte_size(rdata)::16>> <> rdata
  end

  def create_domain_name(name) do
    name
    |> String.split(".")
    |> Enum.map(fn n -> n |> create_character_string end)
    |> concat_binary_list
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
    
    {body, _, _, question}   = body |> parse_question(qdcount, orig_body, [])
    {body, _, _, answer}     = body |> parse_answer(ancount, orig_body, [])
    {body, _, _, authority}  = body |> parse_answer(nscount, orig_body, [])
    {_,    _, _, additional} = body |> parse_answer(arcount, orig_body, [])

    %{
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

  def parse_question(body, 0, orig_body, result) do
    {body, 0, orig_body, result}
  end
  
  def parse_question(body, count, orig_body, result) do
    {body, _, qname} = body |> parse_name(orig_body, "")
    <<
    qtype  :: unsigned-integer-size(16),
    qclass :: unsigned-integer-size(16),
    body   :: binary,
    >> = body
    body |> parse_question(count - 1, orig_body, 
      [%{qname: qname, qtype: DNS.type[qtype], qclass: DNS.class[qclass]} | result])
  end
  
  def parse_answer(body, 0, orig_body, result) do
    {body, 0, orig_body, result}
  end

  def parse_answer(body, count, orig_body, result) do
    {body, _, name} = body |> parse_name(orig_body, "")
    <<
    type :: unsigned-integer-size(16),
    body :: binary,
    >> = body
    body |> parse_answer_checkopt(type, name, count, orig_body, result) 
  end

  # OPT Record
  def parse_answer_checkopt(<<size     :: unsigned-integer-size(16),
                              rcode    :: unsigned-integer-size(8),
                              version  :: unsigned-integer-size(8),
                              d0       :: size(1),
                              z        :: size(15),
                              rdlength :: unsigned-integer-size(16),
                              rdata    :: binary-size(rdlength),
                              body     :: binary>>,
    41, name, count, orig_body, result) do
    body |> parse_answer(count - 1, orig_body, 
      [%{
          name: name,
          type: :opt,
          payload_size: size,
          extended_rcode: rcode,
          version: version,
          d0: d0,
          z: z,
          rdlength: rdlength,
          rdata: [] |> parse_opt_rr(rdata),
       }  | result])
  end

  def parse_answer_checkopt(<<class    :: unsigned-integer-size(16),
                              ttl      :: unsigned-integer-size(32),
                              rdlength :: unsigned-integer-size(16),
                              rdata    :: binary-size(rdlength),
                              body     :: binary>>,
    type, name, count, orig_body, result) do
    body |> parse_answer(count - 1, orig_body, 
      [%{
          name: name,
          type: DNS.type[type],
          class: DNS.class[class],
          ttl: ttl,
          rdlength: rdlength,
          rdata: rdata |> parse_rdata(DNS.type[type] || type, DNS.class[class] || class, orig_body)
       }  | result])
  end

  defp parse_name(<<0x0  :: unsigned-integer-size(8),
                    body :: binary>>, orig_body, "") do
    {body, orig_body, "."}
  end
  
  defp parse_name(<<0x0  :: unsigned-integer-size(8),
                    body :: binary>>, orig_body, result) do
    {body, orig_body, result}
  end

  defp parse_name(<<0b11   :: unsigned-integer-size(2),
                    offset :: unsigned-integer-size(14),
                    body   :: binary>>, orig_body, result) do
    <<_::binary-size(offset), tmp_body::binary>> = orig_body
    {_, _, name} = tmp_body |> parse_name(orig_body, result)
    {body, orig_body, name}
  end

  defp parse_name(<<length :: unsigned-integer-size(8),
                    name   :: binary-size(length),
                    body   :: binary>>, orig_body, result) do
    body |> parse_name(orig_body, result <> name <> ".")
  end

  def parse_rdata(<<addr::unsigned-integer-size(32)>>, :a, :in, _) do
    %{
      addr: addr,
    }
  end

  def parse_rdata(rdata, :ns, _, orig_body) do
    {_, _, name} = rdata |> parse_name(orig_body, "")
    %{
      name: name,
    }
  end

  def parse_rdata(rdata, :cname, _, orig_body) do
    {_, _, name} = rdata |> parse_name(orig_body, "")
    %{
      name: name,
    }
  end

  def parse_rdata(rdata, :soa, _, orig_body) do
    {rdata, _, mname} = rdata |> parse_name(orig_body, "")
    {rdata, _, rname} = rdata |> parse_name(orig_body, "")
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
    {_, _, name} = rdata |> parse_name(orig_body, "")
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
    {_, _, name} = tmp_body |> parse_name(orig_body, "")
    %{
      preference: preference,
      name: name,
    }
  end

  # does not support multiple character strings TXT record
  def parse_rdata(<<length :: unsigned-integer-size(8),
                    txt    :: binary-size(length), _::binary>>, :txt, _, _) do
    %{
      txt: txt,
    }
  end

  def parse_rdata(<<addr::unsigned-integer-size(128)>>, :aaaa, :in, _) do
    %{
      addr: addr,
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
    [parse_opt_code(DNS.option[code], data) | result] |> parse_opt_rr(opt_rr)
  end

  def parse_opt_code(:edns_client_subnet, <<family::16,source::8,scope::8,address::binary>>) do
    %{code: :edns_client_subnet, family: family, souce: source, scope: scope, addr: address}
  end
end
