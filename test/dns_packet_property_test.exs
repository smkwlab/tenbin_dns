defmodule DNSpacketPropertyTest do
  @moduledoc """
  Property-based round-trip tests for the DNS codec (#107).

  Generated packets are pushed through `DNSpacket.create/1` |>
  `DNSpacket.parse/1` and must come back unchanged. This widens the
  example-based contract suite (dns_packet_roundtrip_test.exs) to
  arbitrary field values and is the safety net for codec-structure
  changes (#111).

  Not covered: `zoneversion` (wire layout under review) and EDNS options
  that only round-trip as raw `unknown_options` payloads.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  defp roundtrip(packet), do: packet |> DNSpacket.create() |> DNSpacket.parse()

  property "rdata of every record type survives create |> parse" do
    check all {type, rdata} <- DNSGenerators.type_and_rdata(),
              name <- DNSGenerators.domain_name(),
              ttl <- StreamData.integer(0..0xFFFFFFFF),
              id <- StreamData.integer(0..0xFFFF) do
      packet = %DNSpacket{
        id: id,
        qr: 1,
        aa: 1,
        question: [%{qname: name, qtype: type, qclass: :in}],
        answer: [%{name: name, type: type, class: :in, ttl: ttl, rdata: rdata}]
      }

      parsed = roundtrip(packet)

      # :rdlength is added by parse/1 at the record level only, never
      # inside rdata — the pattern match above separates it, so the rdata
      # comparison needs no stripping (unlike the whole-record property)
      assert [%{name: ^name, type: ^type, class: :in, ttl: ^ttl, rdata: parsed_rdata}] =
               parsed.answer

      assert parsed_rdata == rdata
    end
  end

  property "question section survives create |> parse" do
    qtypes = [:a, :aaaa, :ns, :cname, :soa, :ptr, :mx, :txt, :srv, :any]

    check all qname <- DNSGenerators.domain_name(),
              qtype <- StreamData.member_of(qtypes) do
      packet = %DNSpacket{id: 1, question: [%{qname: qname, qtype: qtype, qclass: :in}]}

      assert roundtrip(packet).question == [%{qname: qname, qtype: qtype, qclass: :in}]
    end
  end

  property "multi-record sections survive in wire order" do
    record_gen =
      StreamData.map(
        {DNSGenerators.type_and_rdata(), DNSGenerators.domain_name(),
         StreamData.integer(0..0xFFFFFFFF)},
        fn {{type, rdata}, name, ttl} ->
          %{name: name, type: type, class: :in, ttl: ttl, rdata: rdata}
        end
      )

    check all answer <- StreamData.list_of(record_gen, max_length: 3),
              authority <- StreamData.list_of(record_gen, max_length: 2),
              additional <- StreamData.list_of(record_gen, max_length: 2) do
      packet = %DNSpacket{
        id: 0x4242,
        qr: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: answer,
        authority: authority,
        additional: additional
      }

      parsed = roundtrip(packet)

      # parse/1 adds :rdlength (wire metadata) to each record; create/1
      # ignores it, so it is not part of the round-trip contract
      strip = fn records -> Enum.map(records, &Map.delete(&1, :rdlength)) end

      assert strip.(parsed.answer) == answer
      assert strip.(parsed.authority) == authority
      assert strip.(parsed.additional) == additional
    end
  end

  property "EDNS hybrid edns_info survives create |> parse" do
    check all edns_info <- DNSGenerators.edns_info() do
      packet = %DNSpacket{
        id: 0xE0E0,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        edns_info: edns_info
      }

      parsed = roundtrip(packet)

      assert parsed.edns_info != nil

      # parse/1 may add canonical defaults (ex_rcode, version, ...);
      # every key the caller set must come back with the same value
      assert Map.take(parsed.edns_info, Map.keys(edns_info)) == edns_info
    end
  end
end
