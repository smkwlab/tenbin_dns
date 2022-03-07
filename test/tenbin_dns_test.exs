defmodule TenbinDnsTest do
  use ExUnit.Case

  doctest TenbinDns

  describe "Stats on create" do
    setup do
      [
        domain_name: "example.com.",
        domain_name_result: <<7>> <> "example" <> <<3>> <> "com" <> <<0>>
      ]
    end

    test "create_domain_name", fixture do
      assert DNSpacket.create_domain_name(fixture.domain_name) == fixture.domain_name_result
    end

    test "create_question_item", fixture do
      question = %{qname: fixture.domain_name, qtype: :a, qclass: :in}

      assert DNSpacket.create_question_item(question) ==
               fixture.domain_name_result <> <<1::16, 1::16>>
    end

    test "create_answer_item", fixture do
      answer_a = %{
        name: "localhost.",
        type: :a,
        class: :in,
        ttl: 86_331,
        rdata: %{addr: {127, 0, 0, 1}}
      }

      assert DNSpacket.create_rr(answer_a) ==
               <<9>> <> "localhost" <> <<0, 1::16, 1::16, 86_331::32, 4::16, 127, 0, 0, 1>>

      answer_ns = %{
        name: fixture.domain_name,
        type: :ns,
        class: :in,
        ttl: 21_599,
        rdata: %{name: "a.iana-servers.net."}
      }

      assert DNSpacket.create_rr(answer_ns) ==
               fixture.domain_name_result <>
                 <<2::16, 1::16, 0, 0, 0x54, 0x5F, 0, 0x14, 0x01, 0x61, 0x0C, 0x69, 0x61, 0x6E,
                   0x61, 0x2D, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6E, 0x65, 0x74,
                   0x00>>
    end

    test "create packet" do
      packet = %{
        id: 0x1825,
        flags: 0x0100,
        question: [%{qname: "gmail.com.", qtype: :all, qclass: :in}],
        answer: [],
        authority: [],
        additional: []
      }

      assert DNSpacket.create(packet) ==
               <<0x18, 0x25, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 0x67, 0x6D, 0x61, 0x69, 0x6C, 3,
                 0x63, 0x6F, 0x6D, 0, 0, 0xFF, 0, 1>>
    end
  end

  describe "Stats on parse" do
    setup do
      [
        packet:
          DNSpacket.create(%{
            id: 0x1825,
            flags: 0x8180,
            question: [%{qname: "gmail.com.", qtype: :all, qclass: :in}],
            answer: [
              %{
                name: "gmail.com.",
                type: :soa,
                class: :in,
                ttl: 59,
                rdata: %{
                  mname: "ns1.google.com.",
                  rname: "dns-admin.google.com.",
                  serial: 389_589_954,
                  refresh: 900,
                  retry: 900,
                  expire: 1800,
                  minimum: 60
                }
              }
            ],
            authority: [],
            additional: []
          })
      ]
    end

    test "parse packet", fixture do
      parsed = DNSpacket.parse(fixture.packet)
      assert parsed.id == 0x1825
      assert hd(parsed.question).qname == "gmail.com."
      assert hd(parsed.question).qtype == :all
      assert hd(parsed.answer).rdata.expire == 1800
    end
  end
end
