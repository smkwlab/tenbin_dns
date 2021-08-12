defmodule DNSpacket do
  require Logger

  def create(packet) do
    <<packet.id                ::16,
      packet.flags             ::16,
      length(packet.question)  ::16,
      length(packet.answer)    ::16,
      length(packet.authority) ::16,
      length(packet.additional)::16>> <>
    create_question(packet.question) <>
    create_answer(packet.answer) <>
    create_answer(packet.authority) <>
    create_answer(packet.additional)
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

  # handle invalid question item
  # XXX should be improved
  def create_question_item(_invalid) do
    Logger.debug("invalid argument to create question item")
    <<0>>
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

  # handle invalid answer item
  # XXX should be improved
  def create_rr(_invalid) do
    Logger.debug("invalid argument to create answer item")
    <<0>>
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
    <<rdata.preference::16>> <> create_domain_name(rdata.exchange)
  end

  def create_rdata(:txt, _, rdata) do
    create_character_string(rdata.txt)
  end

  def create_rdata(:aaaa, :in, rdata) do
    rdata.addr
  end

  # unknown type, class rdata
  # XXX should be improved
  def create_rdata(type, class, rdata) do
    Logger.debug("unknown type #{type}/#{class}")
    rdata
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
end
