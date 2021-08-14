defmodule TenbinDnsTest do
  use ExUnit.Case

  doctest TenbinDns

  test "greets the world" do
    assert TenbinDns.hello() == :world
  end

  test "create_domain_name" do
    assert DNSpacket.create_domain_name("example.com.") == <<7>><>"example"<><<3>><>"com"<><<0>>
  end

  test "create_question_item" do
    question = %{qname: "example.com.", qtype: :a, qclass: :in}
    assert DNSpacket.create_question_item(question) == <<7>><>"example"<><<3>><>"com"<><<0,1::16,1::16>>
  end

  test "create_answer_item" do
    answer_a = %{name: "localhost.", type: :a, class: :in, ttl: 86331, rdata: %{addr: <<127,0,0,1>>}}
    assert DNSpacket.create_rr(answer_a) == <<9>><>"localhost"<><<0,1::16,1::16,86331::32,4::16,127,0,0,1>>

    answer_ns = %{name: "example.com.", type: :ns, class: :in, ttl: 21599, rdata: %{name: "a.iana-servers.net."}}
    assert DNSpacket.create_rr(answer_ns) == <<7>><>"example"<><<3>><>"com"<><<0,2::16,1::16,0,0,0x54,0x5f,0,0x14,0x01,0x61,0x0c,0x69,0x61,0x6e,0x61,0x2d,0x73,0x65,0x72,0x76,0x65,0x72,0x73,0x03,0x6e,0x65,0x74,0x00>>

  end

  test "create packet" do
    packet = %{
      id: 0x1825,
      flags: 0x0100,
      question: [%{qname: "gmail.com.", qtype: :all, qclass: :in}],
      answer: [],
      authority: [],
      additional: [],
    }
    assert DNSpacket.create(packet) == <<0x18,0x25,1,0,0,1,0,0,0,0,0,0,5,0x67,0x6d,0x61,0x69,0x6c,3,0x63,0x6f,0x6d,0,0,0xff,0,1>>
  end

  test "parse packet" do
    packet = DNSpacket.create(%{
      id: 0x1825,
      flags: 0x8180,
      question: [%{qname: "gmail.com.", qtype: :all, qclass: :in}],
      answer: [%{name: "gmail.com.",
                 type: :soa,
                 class: :in,
                 ttl: 59,
                 rdata: %{
                   mname: "ns1.google.com.",
                   rname: "dns-admin.google.com.",
                   serial: 389589954,
                   refresh: 900,
                   retry: 900,
                   expire: 1800,
                   minimum: 60,
                 }
                }],
      authority: [],
      additional: [],
    })
    parsed = DNSpacket.parse(packet)
    assert parsed.id == 0x1825
    assert hd(parsed.question).qname == "gmail.com."
    assert hd(parsed.question).qtype == 255
    assert hd(parsed.answer).rdata.expire == 1800
  end
end
