defmodule DNSpacketRoundtripTest do
  @moduledoc """
  Round-trip tests against the supported public API (#94).

  Every supported record type, the question section and the header flags
  are pushed through `DNSpacket.create/1` |> `DNSpacket.parse/1` and must
  come back unchanged. These tests are the safety net that lets internal
  functions (`create_rdata/3`, `parse_rdata/4`, ...) change shape freely.
  """
  use ExUnit.Case, async: true

  defp roundtrip(packet), do: packet |> DNSpacket.create() |> DNSpacket.parse()

  # Round-trips one answer record and returns the parsed rdata
  defp roundtrip_rdata(type, rdata, class \\ :in) do
    packet = %DNSpacket{
      id: 0x1234,
      qr: 1,
      aa: 1,
      question: [%{qname: "example.com.", qtype: type, qclass: class}],
      answer: [%{name: "example.com.", type: type, class: class, ttl: 300, rdata: rdata}]
    }

    parsed = roundtrip(packet)

    assert [%{name: "example.com.", type: ^type, class: ^class, ttl: 300} = record] =
             parsed.answer

    record.rdata
  end

  describe "header round-trip" do
    test "all header fields survive create/parse" do
      packet = %DNSpacket{
        id: 0xBEEF,
        qr: 1,
        opcode: 2,
        aa: 1,
        tc: 1,
        rd: 1,
        ra: 1,
        z: 0,
        ad: 1,
        cd: 1,
        rcode: 3,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
      }

      parsed = roundtrip(packet)

      for field <- [:id, :qr, :opcode, :aa, :tc, :rd, :ra, :z, :ad, :cd, :rcode] do
        assert Map.get(parsed, field) == Map.get(packet, field),
               "header field #{field} did not round-trip"
      end
    end
  end

  describe "question section round-trip" do
    test "qname/qtype/qclass survive for common query types" do
      for qtype <- [:a, :aaaa, :mx, :txt, :ns, :soa, :any] do
        packet = %DNSpacket{
          id: 1,
          question: [%{qname: "www.example.com.", qtype: qtype, qclass: :in}]
        }

        parsed = roundtrip(packet)
        assert parsed.question == [%{qname: "www.example.com.", qtype: qtype, qclass: :in}]
      end
    end
  end

  describe "rdata round-trip per record type" do
    test "A" do
      assert roundtrip_rdata(:a, %{addr: {192, 0, 2, 1}}) == %{addr: {192, 0, 2, 1}}
    end

    test "AAAA" do
      addr = {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
      assert roundtrip_rdata(:aaaa, %{addr: addr}) == %{addr: addr}
    end

    test "NS" do
      assert roundtrip_rdata(:ns, %{name: "ns1.example.com."}) == %{name: "ns1.example.com."}
    end

    test "CNAME" do
      assert roundtrip_rdata(:cname, %{name: "alias.example.com."}) ==
               %{name: "alias.example.com."}
    end

    test "PTR" do
      assert roundtrip_rdata(:ptr, %{name: "host.example.com."}) == %{name: "host.example.com."}
    end

    test "DNAME" do
      assert roundtrip_rdata(:dname, %{target: "new.example.com."}) ==
               %{target: "new.example.com."}
    end

    test "SOA" do
      rdata = %{
        mname: "ns1.example.com.",
        rname: "hostmaster.example.com.",
        serial: 2_026_061_101,
        refresh: 7200,
        retry: 900,
        expire: 1_209_600,
        minimum: 86_400
      }

      assert roundtrip_rdata(:soa, rdata) == rdata
    end

    test "MX" do
      rdata = %{preference: 10, name: "mail.example.com."}
      assert roundtrip_rdata(:mx, rdata) == rdata
    end

    test "TXT" do
      rdata = %{txt: "v=spf1 include:_spf.example.com ~all"}
      assert roundtrip_rdata(:txt, rdata) == rdata
    end

    test "HINFO" do
      rdata = %{cpu: "ARM64", os: "Linux"}
      assert roundtrip_rdata(:hinfo, rdata) == rdata
    end

    test "CAA" do
      rdata = %{flag: 0, tag: "issue", value: "ca.example.com"}
      assert roundtrip_rdata(:caa, rdata) == rdata
    end

    test "SRV" do
      rdata = %{priority: 10, weight: 60, port: 5060, target: "sip.example.com."}
      assert roundtrip_rdata(:srv, rdata) == rdata
    end

    test "NAPTR" do
      rdata = %{
        order: 100,
        preference: 50,
        flags: "s",
        services: "SIP+D2U",
        regexp: "",
        replacement: "_sip._udp.example.com."
      }

      assert roundtrip_rdata(:naptr, rdata) == rdata
    end

    test "DNSKEY" do
      rdata = %{flags: 257, protocol: 3, algorithm: 8, public_key: <<3, 1, 0, 1, 9, 9>>}
      assert roundtrip_rdata(:dnskey, rdata) == rdata
    end

    test "DS" do
      rdata = %{key_tag: 12_345, algorithm: 8, digest_type: 2, digest: <<0xAB, 0xCD, 0xEF>>}
      assert roundtrip_rdata(:ds, rdata) == rdata
    end

    test "RRSIG" do
      rdata = %{
        type_covered: 1,
        algorithm: 8,
        labels: 2,
        original_ttl: 3600,
        signature_expiration: 1_750_000_000,
        signature_inception: 1_740_000_000,
        key_tag: 12_345,
        signer_name: "example.com.",
        signature: <<1, 2, 3, 4, 5, 6, 7, 8>>
      }

      assert roundtrip_rdata(:rrsig, rdata) == rdata
    end

    test "NSEC" do
      rdata = %{next_domain_name: "next.example.com.", type_bit_maps: [:a, :aaaa, :rrsig]}
      assert roundtrip_rdata(:nsec, rdata) == rdata
    end

    test "SVCB" do
      rdata = %{
        priority: 1,
        target: "svc.example.com.",
        svc_params: %{
          alpn: ["h2", "h3"],
          port: 443,
          ipv4_hints: [{192, 0, 2, 1}],
          ipv6_hints: [{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}]
        }
      }

      assert roundtrip_rdata(:svcb, rdata) == rdata
    end

    test "HTTPS" do
      rdata = %{priority: 1, target: "www.example.com.", svc_params: %{alpn: ["h2"]}}
      assert roundtrip_rdata(:https, rdata) == rdata
    end
  end

  describe "multi-section round-trip" do
    test "answer, authority and additional sections all survive" do
      packet = %DNSpacket{
        id: 0x7777,
        qr: 1,
        aa: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: [
          %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 0, 2, 1}}},
          %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 0, 2, 2}}}
        ],
        authority: [
          %{
            name: "example.com.",
            type: :ns,
            class: :in,
            ttl: 86_400,
            rdata: %{name: "ns1.example.com."}
          }
        ],
        additional: [
          %{
            name: "ns1.example.com.",
            type: :a,
            class: :in,
            ttl: 86_400,
            rdata: %{addr: {192, 0, 2, 53}}
          }
        ]
      }

      parsed = roundtrip(packet)

      assert length(parsed.answer) == 2

      # NOTE: parse/1 currently returns each section in reverse wire order
      # (records are accumulated by prepending without a final reverse).
      # This pins the current behavior; tracked in issue #98.
      assert Enum.map(parsed.answer, & &1.rdata.addr) == [{192, 0, 2, 2}, {192, 0, 2, 1}]

      assert [%{type: :ns, rdata: %{name: "ns1.example.com."}}] = parsed.authority
      assert [%{name: "ns1.example.com.", rdata: %{addr: {192, 0, 2, 53}}}] = parsed.additional
    end
  end
end
