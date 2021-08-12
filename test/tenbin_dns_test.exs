defmodule TenbinDnsTest do
  use ExUnit.Case
  import ExUnit.CaptureLog

  doctest TenbinDns

  test "greets the world" do
    assert TenbinDns.hello() == :world
  end

  test "creqte_domain_name" do
    assert DNSpacket.create_domain_name("example.com") == <<7>><>"example"<><<3>><>"com"<><<0>>
  end

  test "create_question_item" do
    question = %{qname: "example.com", qtype: :a, qclass: :in}
    assert DNSpacket.create_question_item(question) == <<7>><>"example"<><<3>><>"com"<><<0,1::16,1::16>>
    equestion = %{qname: "example.com", qtype: :a}
    assert capture_log(fn -> DNSpacket.create_question_item(equestion)end ) =~ "invalid argument to create question item"
  end

end
