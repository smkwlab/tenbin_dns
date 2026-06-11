defmodule DNSpacketTest do
  @moduledoc """
  Internal-contract tests.

  The supported public API of this library is `DNSpacket.create/1`,
  `DNSpacket.parse/1`, the `DNSpacket` struct and the hybrid `edns_info`
  structure — those are covered by `test/dns_packet_roundtrip_test.exs`,
  `test/dns_packet_edns_consistency_test.exs` and
  `test/dns_packet_unknown_options_test.exs`.

  The tests in this file intentionally call internal (`@doc false`)
  functions to pin behavior that a create/parse round-trip cannot reach:
  malformed and truncated input handling, fallback clauses, name
  decompression against crafted binaries, ECS edge cases and similar.
  When internal functions change shape, update these tests freely — the
  round-trip suites are the compatibility contract, not this file.
  """
  use ExUnit.Case
  import Bitwise

  # Internal-contract tests: fallback clauses for unknown record types
  # cannot be exercised through a create/parse round-trip. Per-type
  # create/parse behavior is covered by test/dns_packet_roundtrip_test.exs
  # against the supported public API (create/1 and parse/1).
  describe "internal contract: rdata fallback clauses" do
    test "create_rdata returns rdata as-is for unknown record type" do
      rdata = <<1, 2, 3, 4, 5>>
      result = DNSpacket.create_rdata(rdata, :unknown_type, :in)
      assert result == rdata
    end

    test "parse_rdata wraps raw rdata for unknown record types" do
      rdata = <<1, 2, 3, 4>>
      result = DNSpacket.parse_rdata(rdata, :unknown, :in, <<>>)
      expected = %{type: :unknown, class: :in, rdata: <<1, 2, 3, 4>>}
      assert result == expected
    end
  end

  # Internal-contract tests: wire shapes that create/1 never produces.
  # create_rdata chunks TXT at 255 bytes, so short multi-string records
  # (e.g. <<3, "abc", 3, "def">>) can only be exercised on the parse side.
  describe "internal contract: TXT multi-string wire format (RFC 1035)" do
    test "parse_rdata concatenates multiple character-strings" do
      rdata = <<3, "abc", 3, "def">>
      assert DNSpacket.parse_rdata(rdata, :txt, :in, <<>>) == %{txt: "abcdef"}
    end

    test "parse_rdata ignores a trailing incomplete character-string" do
      # length byte claims 10 bytes but only 2 remain
      rdata = <<3, "abc", 10, "xy">>
      assert DNSpacket.parse_rdata(rdata, :txt, :in, <<>>) == %{txt: "abc"}
    end

    test "create_rdata chunks long TXT values at 255 bytes" do
      txt = String.duplicate("a", 600)
      <<c1::binary-size(255), c2::binary-size(255), c3::binary-size(90)>> = txt

      assert DNSpacket.create_rdata(%{txt: txt}, :txt, :in) ==
               <<255, c1::binary, 255, c2::binary, 90, c3::binary>>
    end

    test "create_rdata emits no empty trailing string for exact 255-byte multiples" do
      txt = String.duplicate("c", 510)
      <<c1::binary-size(255), c2::binary-size(255)>> = txt

      assert DNSpacket.create_rdata(%{txt: txt}, :txt, :in) ==
               <<255, c1::binary, 255, c2::binary>>
    end
  end

  describe "packet creation and parsing roundtrip" do
    test "creates and parses simple query packet" do
      packet = %DNSpacket{
        id: 0x1234,
        qr: 0,
        opcode: 0,
        rd: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x1234
      assert parsed.qr == 0
      assert parsed.rd == 1
      assert length(parsed.question) == 1
      assert hd(parsed.question).qname == "example.com."
      assert hd(parsed.question).qtype == :a
      assert hd(parsed.question).qclass == :in
    end
  end

  describe "additional coverage tests" do
    test "parse_rdata for NS record" do
      # Create a binary with NS record data
      ns_binary = <<3, "ns1", 7, "example", 3, "com", 0>>
      # Add padding for pointer parsing
      orig_body = <<0::96>> <> ns_binary

      result = DNSpacket.parse_rdata(ns_binary, :ns, :in, orig_body)
      assert result.name == "ns1.example.com."
    end

    test "parse_rdata for CNAME record" do
      cname_binary = <<5, "alias", 7, "example", 3, "com", 0>>
      orig_body = <<0::96>> <> cname_binary

      result = DNSpacket.parse_rdata(cname_binary, :cname, :in, orig_body)
      assert result.name == "alias.example.com."
    end

    test "parse_rdata for PTR record" do
      ptr_binary = <<4, "host", 7, "example", 3, "com", 0>>
      orig_body = <<0::96>> <> ptr_binary

      result = DNSpacket.parse_rdata(ptr_binary, :ptr, :in, orig_body)
      assert result.name == "host.example.com."
    end

    test "parse_rdata for SOA record" do
      # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
      soa_binary =
        <<3, "ns1", 7, "example", 3, "com", 0>> <>
          <<5, "admin", 7, "example", 3, "com", 0>> <>
          <<2_023_010_101::32, 7200::32, 3600::32, 604_800::32, 86_400::32>>

      orig_body = <<0::96>> <> soa_binary

      result = DNSpacket.parse_rdata(soa_binary, :soa, :in, orig_body)
      assert result.mname == "ns1.example.com."
      assert result.rname == "admin.example.com."
      # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
      assert result.serial == 2_023_010_101
    end

    test "parse_rdata for MX record" do
      mx_binary = <<10::16>> <> <<4, "mail", 7, "example", 3, "com", 0>>
      orig_body = <<0::96>> <> mx_binary

      result = DNSpacket.parse_rdata(mx_binary, :mx, :in, orig_body)
      assert result.preference == 10
      assert result.name == "mail.example.com."
    end

    test "parse_opt_rr with multiple options" do
      # ECS option
      # Cookie option
      opt_data =
        <<8::16, 4::16, 1, 2, 3, 4>> <>
          <<10::16, 8::16, 1, 2, 3, 4, 5, 6, 7, 8>>

      result = DNSpacket.parse_opt_rr(%{}, opt_data)
      assert map_size(result) == 2
      assert Map.has_key?(result, :edns_client_subnet)
      assert Map.has_key?(result, :cookie)
    end

    test "parse_opt_rr with all supported EDNS options" do
      # Build comprehensive opt_data with many options
      # ECS option (code 8)
      # Cookie option (code 10)
      # NSID option (code 3)
      # Extended DNS Error (code 15)
      # TCP Keepalive (code 11)
      # Padding (code 12)
      # DAU (code 5)
      # DHU (code 6)
      # N3U (code 7)
      # EDNS Expire (code 9)
      # Chain (code 13)
      # EDNS Key Tag (code 14)
      # EDNS Client Tag (code 16)
      # EDNS Server Tag (code 17)
      # Report Channel (code 18)
      # Zone Version (code 19)
      # Update Lease (code 2)
      # LLQ (code 1)
      # Umbrella Ident (code 20292)
      # DeviceID (code 26946)
      opt_data =
        <<8::16, 7::16, 1::16, 24::8, 0::8, 192, 168, 1>> <>
          <<10::16, 16::16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>> <>
          <<3::16, 6::16, "server">> <>
          <<15::16, 9::16, 18::16, "Blocked">> <>
          <<11::16, 2::16, 300::16>> <>
          <<12::16, 4::16, 0::32>> <>
          <<5::16, 3::16, 7, 8, 10>> <>
          <<6::16, 2::16, 1, 2>> <>
          <<7::16, 1::16, 1>> <>
          <<9::16, 4::16, 3600::32>> <>
          <<13::16, 11::16, "example.com">> <>
          <<14::16, 4::16, 12_345::16, 54_321::16>> <>
          <<16::16, 2::16, 1234::16>> <>
          <<17::16, 2::16, 5678::16>> <>
          <<18::16, 17::16, "agent.example.com">> <>
          <<19::16, 8::16, 0, 4, 98, 213, 60, 138, 186, 192>> <>
          <<2::16, 4::16, 7200::32>> <>
          <<1::16, 18::16, 1::16, 1::16, 0::16, 0, 4, 98, 213, 60, 138, 186, 192, 3600::32>> <>
          <<20_292::16, 4::16, 0x12345678::32>> <>
          <<26_946::16, 9::16, "device123">>

      result = DNSpacket.parse_opt_rr(%{}, opt_data)

      # Should parse all 20 options (including unknowns which are accumulated in a list)
      # Count known options + unknown list length
      known_count = map_size(Map.drop(result, [:unknown]))

      unknown_count =
        case Map.get(result, :unknown) do
          nil -> 0
          list -> length(list)
        end

      assert known_count + unknown_count == 20

      # Verify a few specific options - now using tuple format
      {ecs_key, ecs_opt} = Enum.find(result, fn {key, _} -> key == :edns_client_subnet end)
      assert ecs_key == :edns_client_subnet
      assert ecs_opt.family == 1
      assert ecs_opt.source_prefix == 24

      {cookie_key, cookie_opt} = Enum.find(result, fn {key, _} -> key == :cookie end)
      assert cookie_key == :cookie
      assert byte_size(cookie_opt.client) >= 8

      {llq_key, llq_opt} = Enum.find(result, fn {key, _} -> key == :llq end)
      assert llq_key == :llq
      assert llq_opt.version == 1
      assert llq_opt.llq_id == 1_234_567_890_123_456
    end

    test "create_answer with multiple answers" do
      answers = [
        %{name: "test.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, 1}}},
        %{name: "test.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, 2}}}
      ]

      result = DNSpacket.create_answer(answers)
      assert is_binary(result)
      assert byte_size(result) > 0
    end

    test "create_question with multiple questions" do
      questions = [
        %{qname: "test1.com.", qtype: :a, qclass: :in},
        %{qname: "test2.com.", qtype: :aaaa, qclass: :in}
      ]

      result = DNSpacket.create_question(questions)
      assert is_binary(result)
      assert byte_size(result) > 0
    end

    test "create packet with all header flags set" do
      packet = %DNSpacket{
        id: 0x1234,
        qr: 1,
        opcode: 15,
        aa: 1,
        tc: 1,
        rd: 1,
        ra: 1,
        z: 1,
        ad: 1,
        cd: 1,
        rcode: 15,
        question: []
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.qr == 1
      assert parsed.opcode == 15
      assert parsed.aa == 1
      assert parsed.tc == 1
      assert parsed.rd == 1
      assert parsed.ra == 1
      assert parsed.z == 1
      assert parsed.ad == 1
      assert parsed.cd == 1
      assert parsed.rcode == 15
    end

    test "parse_rdata fallback clause coverage" do
      # Test unknown record type that hits the fallback
      unknown_rdata = <<1, 2, 3, 4, 5>>
      result = DNSpacket.parse_rdata(unknown_rdata, :unknown_type, :in, <<>>)
      assert result == %{type: :unknown_type, class: :in, rdata: unknown_rdata}
    end

    test "parse packet with complex name compression edge cases" do
      # Test packet that exercises parse_name internal paths through public API
      complex_packet = <<
        # ID
        0x12,
        0x34,
        # Flags
        0x81,
        0x80,
        # QDCOUNT = 1
        0x00,
        0x01,
        # ANCOUNT = 1
        0x00,
        0x01,
        # NSCOUNT = 0
        0x00,
        0x00,
        # ARCOUNT = 0
        0x00,
        0x00,
        # Question with very deep nesting to test parse_name accumulator
        0x03,
        "sub",
        0x03,
        "sub",
        0x03,
        "sub",
        0x07,
        "example",
        0x03,
        "com",
        0x00,
        # QTYPE = A
        0x00,
        0x01,
        # QCLASS = IN
        0x00,
        0x01,
        # Answer with pointer to test parse_name pointer handling
        # Pointer to question name
        0xC0,
        0x0C,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x00,
        0x01,
        0x2C,
        0x00,
        0x04,
        192,
        168,
        1,
        1
      >>

      parsed = DNSpacket.parse(complex_packet)
      assert hd(parsed.question).qname == "sub.sub.sub.example.com."
      assert hd(parsed.answer).name == "sub.sub.sub.example.com."
    end

    test "parse packet with root domain edge case" do
      # Test root domain handling which exercises parse_name edge cases
      root_packet = <<
        # ID
        0x12,
        0x34,
        # Flags
        0x01,
        0x00,
        # QDCOUNT = 1
        0x00,
        0x01,
        # ANCOUNT = 0
        0x00,
        0x00,
        # NSCOUNT = 0
        0x00,
        0x00,
        # ARCOUNT = 0
        0x00,
        0x00,
        # Root domain name (empty label)
        0x00,
        # QTYPE = A
        0x00,
        0x01,
        # QCLASS = IN
        0x00,
        0x01
      >>

      parsed = DNSpacket.parse(root_packet)
      assert hd(parsed.question).qname == "."
    end

    test "parse_opt_rr edge cases" do
      # Test parse_opt_rr with empty binary
      result = DNSpacket.parse_opt_rr([], <<>>)
      assert result == []

      # Test with pre-existing result
      existing = [%{code: :test, data: <<1, 2>>}]
      result2 = DNSpacket.parse_opt_rr(existing, <<>>)
      assert result2 == existing
    end

    test "create_rdata for all supported types complete coverage" do
      # Test create_rdata edge cases and ensure all paths are covered

      # Test AAAA with different IPv6 format
      rdata = %{addr: {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}}
      result = DNSpacket.create_rdata(rdata, :aaaa, :in)

      expected =
        <<0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16,
          0xFFFF::16>>

      assert result == expected
    end

    test "parse comprehensive packet with all record types" do
      # Create a comprehensive packet to test multiple parsing paths
      packet = %DNSpacket{
        id: 0x9999,
        qr: 1,
        aa: 1,
        rd: 1,
        ra: 1,
        question: [%{qname: "test.example.com.", qtype: :a, qclass: :in}],
        answer: [
          %{
            name: "test.example.com.",
            type: :a,
            class: :in,
            ttl: 300,
            rdata: %{addr: {10, 0, 0, 1}}
          },
          %{
            name: "test.example.com.",
            type: :aaaa,
            class: :in,
            ttl: 300,
            rdata: %{addr: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 2}}
          }
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
            rdata: %{addr: {10, 0, 0, 10}}
          }
        ]
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x9999
      assert length(parsed.answer) == 2
      assert length(parsed.authority) == 1
      assert length(parsed.additional) == 1
    end

    test "create_domain_name handles various domain formats" do
      # Test edge cases for domain name creation
      assert DNSpacket.create_domain_name("") == <<0>>
      assert DNSpacket.create_domain_name(".") == <<0, 0>>

      # Test single label
      result = DNSpacket.create_domain_name("localhost")
      assert result == <<9, "localhost">>

      # Test domain with empty label (edge case)
      result2 = DNSpacket.create_domain_name("test..com")
      expected = <<4, "test", 0, 3, "com">>
      assert result2 == expected
    end

    test "create_character_string with maximum length" do
      # Test with 255 character string (maximum for DNS)
      long_string = String.duplicate("a", 255)
      result = DNSpacket.create_character_string(long_string)
      assert result == <<255>> <> long_string
    end

    test "parse packet with OPT record using old parse functions" do
      # Create packet with OPT record to test the non-fast parse path coverage
      packet_with_opt = <<
        # ID
        0x12,
        0x34,
        # Flags
        0x00,
        0x00,
        # QDCOUNT = 0
        0x00,
        0x00,
        # ANCOUNT = 0
        0x00,
        0x00,
        # NSCOUNT = 0
        0x00,
        0x00,
        # ARCOUNT = 1
        0x00,
        0x01,
        # OPT record
        # Empty name
        0x00,
        # TYPE = OPT (41)
        0x00,
        0x29,
        # Payload size = 1024
        0x04,
        0x00,
        # Extended RCODE
        0x00,
        # Version
        0x00,
        # Flags (DNSSEC OK)
        0x80,
        0x00,
        # RDLENGTH = 0
        0x00,
        0x00
      >>

      parsed = DNSpacket.parse(packet_with_opt)
      assert length(parsed.additional) == 1
      opt_record = hd(parsed.additional)
      assert opt_record.type == :opt
      assert opt_record.payload_size == 1024
      assert opt_record.dnssec == 1
    end

    test "create_rr for OPT record with various EDNS options" do
      # Test create_rr using structured EDNS info format
      edns_info = %{
        ecs_family: 1,
        ecs_subnet: {192, 168, 1, 0},
        ecs_source_prefix: 24,
        ecs_scope_prefix: 0
      }

      # Convert structured format to legacy format for create_rr
      opt_record = DNSpacket.create_edns_info_record(edns_info)
      binary = DNSpacket.create_rr(opt_record)

      # Verify the binary starts with OPT record header
      <<0, 41::16, payload_size::16, ex_rcode::8, version::8, flags::16, rdlength::16,
        _rdata::binary>> = binary

      assert payload_size == 1232
      assert ex_rcode == 0
      assert version == 0
      # DNSSEC bit (default)
      assert flags >>> 15 == 0
      # Should have RDATA for all the options
      assert rdlength > 0
    end

    test "create_rr for OPT record with empty rdata list" do
      opt_record = %{
        type: :opt,
        payload_size: 512,
        ex_rcode: 0,
        version: 0,
        dnssec: 0,
        z: 0,
        rdata: []
      }

      binary = DNSpacket.create_rr(opt_record)

      # Should create valid OPT record with no options
      <<0, 41::16, 512::16, 0, 0, 0::16, 0::16>> = binary
    end

    test "create_rr for normal DNS records" do
      # Test A record
      a_record = %{
        name: "example.com.",
        type: :a,
        class: :in,
        ttl: 300,
        rdata: %{addr: {192, 168, 1, 1}}
      }

      a_binary = DNSpacket.create_rr(a_record)
      assert is_binary(a_binary)

      # Test MX record
      mx_record = %{
        name: "example.com.",
        type: :mx,
        class: :in,
        ttl: 3600,
        rdata: %{preference: 10, name: "mail.example.com."}
      }

      mx_binary = DNSpacket.create_rr(mx_record)
      assert is_binary(mx_binary)

      # Test TXT record
      txt_record = %{
        name: "example.com.",
        type: :txt,
        class: :in,
        ttl: 300,
        rdata: %{txt: "v=spf1 include:_spf.example.com ~all"}
      }

      txt_binary = DNSpacket.create_rr(txt_record)
      assert is_binary(txt_binary)
    end

    test "parse packet with authority and additional sections" do
      packet = %DNSpacket{
        id: 0x5678,
        qr: 1,
        aa: 1,
        question: [%{qname: "test.com.", qtype: :a, qclass: :in}],
        answer: [
          %{name: "test.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, 1}}}
        ],
        authority: [
          %{name: "test.com.", type: :ns, class: :in, ttl: 3600, rdata: %{name: "ns1.test.com."}}
        ],
        additional: [
          %{
            name: "ns1.test.com.",
            type: :a,
            class: :in,
            ttl: 3600,
            rdata: %{addr: {192, 168, 1, 10}}
          }
        ]
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert length(parsed.authority) == 1
      assert length(parsed.additional) == 1
      assert hd(parsed.authority).type == :ns
      assert hd(parsed.additional).type == :a
    end
  end

  describe "Advanced DNS record types tests" do
    test "creates SRV record rdata" do
      rdata = %{
        priority: 10,
        weight: 20,
        port: 443,
        target: "target.example.com."
      }

      result = DNSpacket.create_rdata(rdata, :srv, :in)
      expected = <<10::16, 20::16, 443::16, 6, "target", 7, "example", 3, "com", 0>>
      assert result == expected
    end

    test "creates NAPTR record rdata" do
      rdata = %{
        order: 100,
        preference: 10,
        flags: "S",
        services: "SIP+D2U",
        regexp: "",
        replacement: "sip.example.com."
      }

      result = DNSpacket.create_rdata(rdata, :naptr, :in)
      expected = <<100::16, 10::16, 1, "S", 7, "SIP+D2U", 0, 3, "sip", 7, "example", 3, "com", 0>>
      assert result == expected
    end

    test "creates DNSKEY record rdata" do
      rdata = %{
        flags: 256,
        protocol: 3,
        algorithm: 7,
        public_key: <<1, 2, 3, 4>>
      }

      result = DNSpacket.create_rdata(rdata, :dnskey, :in)
      expected = <<256::16, 3, 7, 1, 2, 3, 4>>
      assert result == expected
    end

    test "creates DS record rdata" do
      rdata = %{
        key_tag: 12_345,
        algorithm: 7,
        digest_type: 1,
        digest: <<0x9F, 0x6A, 0x2B, 0x96>>
      }

      result = DNSpacket.create_rdata(rdata, :ds, :in)
      expected = <<12_345::16, 7, 1, 0x9F, 0x6A, 0x2B, 0x96>>
      assert result == expected
    end

    test "creates NSEC record rdata" do
      rdata = %{
        next_domain_name: "next.example.com.",
        type_bit_maps: <<0, 1, 0x40>>
      }

      result = DNSpacket.create_rdata(rdata, :nsec, :in)
      expected = <<4, "next", 7, "example", 3, "com", 0, 0, 1, 0x40>>
      assert result == expected
    end

    test "creates NSEC record with multiple type bitmaps" do
      rdata = %{
        next_domain_name: "b.example.com.",
        type_bit_maps: [:a, :ns, :soa, :mx, :aaaa, :rrsig, :nsec, :dnskey]
      }

      result = DNSpacket.create_rdata(rdata, :nsec, :in)
      # Should create proper type bitmap representation
      assert is_binary(result)
      # Domain name + type bitmaps
      assert byte_size(result) > 15
    end

    test "parses NSEC record with type bitmaps" do
      # NSEC record with A, NS, SOA types in bitmap
      rdata = <<1, "b", 7, "example", 3, "com", 0, 0, 1, 0x40>>
      result = DNSpacket.parse_rdata(rdata, :nsec, :in, <<>>)

      expected = %{
        next_domain_name: "b.example.com.",
        type_bit_maps: [:a]
      }

      assert result == expected
    end

    test "creates SVCB record rdata" do
      rdata = %{
        priority: 1,
        target: "svc.example.com.",
        svc_params: %{1 => <<1, 187>>, 4 => <<192, 0, 2, 1>>}
      }

      result = DNSpacket.create_rdata(rdata, :svcb, :in)
      # Check that result is binary and has reasonable size
      assert is_binary(result)
      assert byte_size(result) > 10
    end

    test "creates HTTPS record rdata" do
      rdata = %{
        priority: 0,
        target: ".",
        svc_params: %{}
      }

      result = DNSpacket.create_rdata(rdata, :https, :in)
      # Just check that it's a binary with the priority and target
      assert is_binary(result)
      assert byte_size(result) >= 2
    end

    test "parses SRV record rdata" do
      rdata = <<10::16, 20::16, 443::16, 6, "target", 7, "example", 3, "com", 0>>
      result = DNSpacket.parse_rdata(rdata, :srv, :in, <<>>)

      expected = %{
        priority: 10,
        weight: 20,
        port: 443,
        target: "target.example.com."
      }

      assert result == expected
    end

    test "parses SVCB record rdata" do
      rdata = <<1::16, 3, "svc", 7, "example", 3, "com", 0, 1::16, 2::16, 1, 187>>
      result = DNSpacket.parse_rdata(rdata, :svcb, :in, <<>>)

      expected = %{
        priority: 1,
        target: "svc.example.com.",
        svc_params: %{alpn: [<<187>>]}
      }

      assert result == expected
    end

    test "parses HTTPS record rdata" do
      rdata = <<0::16, 0>>
      result = DNSpacket.parse_rdata(rdata, :https, :in, <<>>)

      expected = %{
        priority: 0,
        target: ".",
        svc_params: %{}
      }

      assert result == expected
    end
  end

  describe "SVCB/HTTPS service parameter parsing tests" do
    test "parses service parameters with create_svc_params" do
      params = %{1 => <<443::16>>, 4 => <<192, 0, 2, 1>>}
      result = DNSpacket.create_svc_params(params)
      # This should create the binary representation of service parameters
      assert is_binary(result)
      assert byte_size(result) > 0
    end

    test "parses empty service parameters" do
      result = DNSpacket.parse_svc_params(<<>>)
      expected = %{}
      assert result == expected
    end

    test "parses service parameters with port" do
      # Parameter key=1 (alpn), length=2, value with single byte length prefix
      param_binary = <<1::16, 2::16, 1, 187>>
      result = DNSpacket.parse_svc_params(param_binary)
      expected = %{alpn: [<<187>>]}
      assert result == expected
    end
  end
end
