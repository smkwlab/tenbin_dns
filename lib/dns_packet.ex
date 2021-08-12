defmodule DNSpacket do
  require Logger

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
  def create_question_item(_invalid) do
    Logger.debug("invalid argument to create question item")
    <<0>>
  end

  def create_domain_name(name) do
    create_domain_name_label(String.split(name, "."))
  end
  
  defp create_domain_name_label(label, result \\ <<>>)

  defp create_domain_name_label([], result) do
    result
  end

  defp create_domain_name_label([label | tail], result) do
    create_domain_name_label(tail, result <> <<String.length(label)::8, label::binary>>)
  end
end
