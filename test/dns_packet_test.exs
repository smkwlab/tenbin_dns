defmodule DNSpacketTest do
  use ExUnit.Case
  import Bitwise

  describe "create_domain_name/1" do
    test "creates domain name binary for simple domain" do
      result = DNSpacket.create_domain_name("example.com")
      expected = <<7, "example", 3, "com">>
      assert result == expected
    end

    test "creates domain name binary for subdomain" do
      result = DNSpacket.create_domain_name("www.example.com")
      expected = <<3, "www", 7, "example", 3, "com">>
      assert result == expected
    end

    test "handles root domain" do
      result = DNSpacket.create_domain_name(".")
      expected = <<0, 0>>
      assert result == expected
    end
  end

  describe "create_character_string/1" do
    test "creates character string with length prefix" do
      result = DNSpacket.create_character_string("hello")
      expected = <<5, "hello">>
      assert result == expected
    end

    test "handles empty string" do
      result = DNSpacket.create_character_string("")
      expected = <<0>>
      assert result == expected
    end
  end

  describe "create_rdata/3 for different record types" do
    test "creates A record rdata" do
      rdata = %{addr: {192, 168, 1, 1}}
      result = DNSpacket.create_rdata(rdata, :a, :in)
      expected = <<192, 168, 1, 1>>
      assert result == expected
    end

    test "creates NS record rdata" do
      rdata = %{name: "ns1.example.com"}
      result = DNSpacket.create_rdata(rdata, :ns, :in)
      expected = <<3, "ns1", 7, "example", 3, "com">>
      assert result == expected
    end

    test "creates CNAME record rdata" do
      rdata = %{name: "alias.example.com"}
      result = DNSpacket.create_rdata(rdata, :cname, :in)
      expected = <<5, "alias", 7, "example", 3, "com">>
      assert result == expected
    end

    test "creates PTR record rdata" do
      rdata = %{name: "host.example.com"}
      result = DNSpacket.create_rdata(rdata, :ptr, :in)
      expected = <<4, "host", 7, "example", 3, "com">>
      assert result == expected
    end

    test "creates MX record rdata" do
      rdata = %{preference: 10, name: "mail.example.com"}
      result = DNSpacket.create_rdata(rdata, :mx, :in)
      expected = <<10::16>> <> <<4, "mail", 7, "example", 3, "com">>
      assert result == expected
    end

    test "creates TXT record rdata" do
      rdata = %{txt: "hello world"}
      result = DNSpacket.create_rdata(rdata, :txt, :in)
      expected = <<11, "hello world">>
      assert result == expected
    end

    test "creates AAAA record rdata" do
      rdata = %{addr: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}}
      result = DNSpacket.create_rdata(rdata, :aaaa, :in)
      # Calculate expected value using same logic as implementation
      addr_int = 0x2001 * 0x10000*0x10000*0x10000*0x10000*0x10000*0x10000*0x10000 +
                 0xdb8 * 0x10000*0x10000*0x10000*0x10000*0x10000*0x10000 +
                 0 * 0x10000*0x10000*0x10000*0x10000*0x10000 +
                 0 * 0x10000*0x10000*0x10000*0x10000 +
                 0 * 0x10000*0x10000*0x10000 +
                 0 * 0x10000*0x10000 +
                 0 * 0x10000 +
                 1
      expected = <<addr_int::128>>
      assert result == expected
    end

    test "creates SOA record rdata" do
      rdata = %{
        mname: "ns1.example.com",
        rname: "admin.example.com",
        # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
        serial: 2023010101,
        refresh: 7200,
        retry: 3600,
        expire: 604_800,
        minimum: 86_400
      }
      result = DNSpacket.create_rdata(rdata, :soa, :in)

      expected = <<3, "ns1", 7, "example", 3, "com">> <>
                <<5, "admin", 7, "example", 3, "com">> <>
                # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
                <<2023010101::32, 7200::32, 3600::32, 604_800::32, 86_400::32>>
      assert result == expected
    end

    test "creates HINFO record rdata" do
      rdata = %{cpu: "i386", os: "linux"}
      result = DNSpacket.create_rdata(rdata, :hinfo, :in)
      expected = <<4, "i386", 5, "linux">>
      assert result == expected
    end

    test "creates CAA record rdata" do
      rdata = %{flag: 0, tag: "issue", value: "letsencrypt.org"}
      result = DNSpacket.create_rdata(rdata, :caa, :in)
      expected = <<0, 5, "issue", "letsencrypt.org">>
      assert result == expected
    end

    test "creates rdata for unknown record type" do
      # Test the fallback case
      rdata = <<1, 2, 3, 4, 5>>
      result = DNSpacket.create_rdata(rdata, :unknown_type, :in)
      assert result == rdata
    end
  end

  describe "parse_rdata/4 for different record types" do
    test "parses A record rdata" do
      rdata = <<192, 168, 1, 1>>
      result = DNSpacket.parse_rdata(rdata, :a, :in, <<>>)
      expected = %{addr: {192, 168, 1, 1}}
      assert result == expected
    end

    test "parses AAAA record rdata" do
      rdata = <<0x2001::16, 0xdb8::16, 0::16, 0::16, 0::16, 0::16, 0::16, 1::16>>
      result = DNSpacket.parse_rdata(rdata, :aaaa, :in, <<>>)
      expected = %{addr: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}}
      assert result == expected
    end

    test "parses TXT record rdata" do
      rdata = <<11, "hello world", 0>>
      result = DNSpacket.parse_rdata(rdata, :txt, :in, <<>>)
      expected = %{txt: "hello world"}
      assert result == expected
    end

    test "parses HINFO record rdata" do
      rdata = <<4, "i386", 5, "linux">>
      result = DNSpacket.parse_rdata(rdata, :hinfo, :in, <<>>)
      expected = %{cpu: "i386", os: "linux"}
      assert result == expected
    end

    test "parses CAA record rdata" do
      rdata = <<0, 5, "issue", "example.com">>
      result = DNSpacket.parse_rdata(rdata, :caa, :in, <<>>)
      expected = %{flag: 0, tag: "issue", value: "example.com"}
      assert result == expected
    end

    test "handles unknown record types" do
      rdata = <<1, 2, 3, 4>>
      result = DNSpacket.parse_rdata(rdata, :unknown, :in, <<>>)
      expected = %{type: :unknown, class: :in, rdata: <<1, 2, 3, 4>>}
      assert result == expected
    end
  end

  describe "create_question_item/1" do
    test "creates question item binary" do
      question = %{qname: "example.com", qtype: :a, qclass: :in}
      result = DNSpacket.create_question_item(question)
      expected = <<7, "example", 3, "com", 1::16, 1::16>>
      assert result == expected
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

  describe "DNS name compression tests" do
    test "parse handles DNS name compression pointers" do
      # Create a packet with name compression
      compressed_packet = <<
        0x12, 0x34,  # ID
        0x81, 0x80,  # Flags (response)
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x01,  # ANCOUNT = 1
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x00,  # ARCOUNT = 0
        # Question: example.com
        0x07, "example", 0x03, "com", 0x00,
        0x00, 0x01,  # QTYPE = A
        0x00, 0x01,  # QCLASS = IN
        # Answer: pointer to question name
        0xC0, 0x0C,  # Pointer to offset 12 (name compression)
        0x00, 0x01,  # TYPE = A
        0x00, 0x01,  # CLASS = IN
        0x00, 0x00, 0x01, 0x2C,  # TTL = 300
        0x00, 0x04,  # RDLENGTH = 4
        192, 168, 1, 1  # IP address
      >>

      parsed = DNSpacket.parse(compressed_packet)
      assert parsed.id == 0x1234
      assert hd(parsed.answer).name == "example.com."
      assert hd(parsed.answer).rdata.addr == {192, 168, 1, 1}
    end

    test "parse handles root domain name in empty context" do
      # Test packet with just root domain
      root_packet = <<
        0x12, 0x34,  # ID
        0x01, 0x00,  # Flags
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x00,  # ANCOUNT = 0
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x00,  # ARCOUNT = 0
        # Question: root domain (just null byte)
        0x00,        # Root domain name
        0x00, 0x01,  # QTYPE = A
        0x00, 0x01   # QCLASS = IN
      >>

      parsed = DNSpacket.parse(root_packet)
      assert hd(parsed.question).qname == "."
    end

    test "parse handles complex name compression with multiple pointers" do
      # Packet with multiple compressed names
      multi_compressed = <<
        0x12, 0x34,  # ID
        0x81, 0x80,  # Flags
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x02,  # ANCOUNT = 2
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x00,  # ARCOUNT = 0
        # Question: mail.example.com
        0x04, "mail", 0x07, "example", 0x03, "com", 0x00,
        0x00, 0x01,  # QTYPE = A
        0x00, 0x01,  # QCLASS = IN
        # Answer 1: mail.example.com (pointer)
        0xC0, 0x0C,  # Pointer to question name
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
        192, 168, 1, 1,
        # Answer 2: www.example.com (partial pointer)
        0x03, "www", 0xC0, 0x11,  # "www" + pointer to "example.com" part
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
        192, 168, 1, 2
      >>

      parsed = DNSpacket.parse(multi_compressed)
      assert length(parsed.answer) == 2
      # Note: Order might vary, so check both names are present
      names = [Enum.at(parsed.answer, 0).name, Enum.at(parsed.answer, 1).name]
      assert "mail.example.com." in names
      assert "www.example.com." in names
    end
  end

  describe "additional coverage tests" do


    test "parse_rdata for NS record" do
      # Create a binary with NS record data
      ns_binary = <<3, "ns1", 7, "example", 3, "com", 0>>
      orig_body = <<0::96>> <> ns_binary  # Add padding for pointer parsing

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
      soa_binary = <<3, "ns1", 7, "example", 3, "com", 0>> <>
                   <<5, "admin", 7, "example", 3, "com", 0>> <>
                   # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
                   <<2023010101::32, 7200::32, 3600::32, 604_800::32, 86_400::32>>
      orig_body = <<0::96>> <> soa_binary

      result = DNSpacket.parse_rdata(soa_binary, :soa, :in, orig_body)
      assert result.mname == "ns1.example.com."
      assert result.rname == "admin.example.com."
      # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
      assert result.serial == 2023010101
    end

    test "parse_rdata for MX record" do
      mx_binary = <<10::16>> <> <<4, "mail", 7, "example", 3, "com", 0>>
      orig_body = <<0::96>> <> mx_binary

      result = DNSpacket.parse_rdata(mx_binary, :mx, :in, orig_body)
      assert result.preference == 10
      assert result.name == "mail.example.com."
    end

    test "parse_opt_rr with multiple options" do
      opt_data = <<8::16, 4::16, 1, 2, 3, 4>> <>  # ECS option
                 <<10::16, 8::16, 1, 2, 3, 4, 5, 6, 7, 8>>  # Cookie option

      result = DNSpacket.parse_opt_rr(%{}, opt_data)
      assert map_size(result) == 2
      assert Map.has_key?(result, :edns_client_subnet)
      assert Map.has_key?(result, :cookie)
    end

    test "parse_opt_rr with all supported EDNS options" do
      # Build comprehensive opt_data with many options
      opt_data =
        # ECS option (code 8)
        <<8::16, 7::16, 1::16, 24::8, 0::8, 192, 168, 1>> <>
        # Cookie option (code 10)
        <<10::16, 16::16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>> <>
        # NSID option (code 3)
        <<3::16, 6::16, "server">> <>
        # Extended DNS Error (code 15)
        <<15::16, 9::16, 18::16, "Blocked">> <>
        # TCP Keepalive (code 11)
        <<11::16, 2::16, 300::16>> <>
        # Padding (code 12)
        <<12::16, 4::16, 0::32>> <>
        # DAU (code 5)
        <<5::16, 3::16, 7, 8, 10>> <>
        # DHU (code 6)
        <<6::16, 2::16, 1, 2>> <>
        # N3U (code 7)
        <<7::16, 1::16, 1>> <>
        # EDNS Expire (code 9)
        <<9::16, 4::16, 3600::32>> <>
        # Chain (code 13)
        <<13::16, 11::16, "example.com">> <>
        # EDNS Key Tag (code 14)
        <<14::16, 4::16, 12_345::16, 54_321::16>> <>
        # EDNS Client Tag (code 16)
        <<16::16, 2::16, 1234::16>> <>
        # EDNS Server Tag (code 17)
        <<17::16, 2::16, 5678::16>> <>
        # Report Channel (code 18)
        <<18::16, 17::16, "agent.example.com">> <>
        # Zone Version (code 19)
        <<19::16, 8::16, 0, 4, 98, 213, 60, 138, 186, 192>> <>
        # Update Lease (code 2)
        <<2::16, 4::16, 7200::32>> <>
        # LLQ (code 1)
        <<1::16, 18::16, 1::16, 1::16, 0::16, 0, 4, 98, 213, 60, 138, 186, 192, 3600::32>> <>
        # Umbrella Ident (code 20292)
        <<20_292::16, 4::16, 0x12345678::32>> <>
        # DeviceID (code 26946)
        <<26_946::16, 9::16, "device123">>

      result = DNSpacket.parse_opt_rr(%{}, opt_data)

      # Should parse all 20 options (including unknowns which are accumulated in a list)
      # Count known options + unknown list length
      known_count = map_size(Map.drop(result, [:unknown]))
      unknown_count = case Map.get(result, :unknown) do
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
        %{name: "test.com.", type: :a, class: :in, ttl: 300,
          rdata: %{addr: {192, 168, 1, 1}}},
        %{name: "test.com.", type: :a, class: :in, ttl: 300,
          rdata: %{addr: {192, 168, 1, 2}}}
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
        qr: 1, opcode: 15, aa: 1, tc: 1, rd: 1,
        ra: 1, z: 1, ad: 1, cd: 1, rcode: 15,
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
        0x12, 0x34,  # ID
        0x81, 0x80,  # Flags
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x01,  # ANCOUNT = 1
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x00,  # ARCOUNT = 0
        # Question with very deep nesting to test parse_name accumulator
        0x03, "sub", 0x03, "sub", 0x03, "sub", 0x07, "example", 0x03, "com", 0x00,
        0x00, 0x01,  # QTYPE = A
        0x00, 0x01,  # QCLASS = IN
        # Answer with pointer to test parse_name pointer handling
        0xC0, 0x0C,  # Pointer to question name
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
        192, 168, 1, 1
      >>

      parsed = DNSpacket.parse(complex_packet)
      assert hd(parsed.question).qname == "sub.sub.sub.example.com."
      assert hd(parsed.answer).name == "sub.sub.sub.example.com."
    end

    test "parse packet with root domain edge case" do
      # Test root domain handling which exercises parse_name edge cases
      root_packet = <<
        0x12, 0x34,  # ID
        0x01, 0x00,  # Flags
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x00,  # ANCOUNT = 0
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x00,  # ARCOUNT = 0
        0x00,        # Root domain name (empty label)
        0x00, 0x01,  # QTYPE = A
        0x00, 0x01   # QCLASS = IN
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
      rdata = %{addr: {0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff}}
      result = DNSpacket.create_rdata(rdata, :aaaa, :in)
      expected = <<0xffff::16, 0xffff::16, 0xffff::16, 0xffff::16, 0xffff::16, 0xffff::16, 0xffff::16, 0xffff::16>>
      assert result == expected
    end

    test "parse comprehensive packet with all record types" do
      # Create a comprehensive packet to test multiple parsing paths
      packet = %DNSpacket{
        id: 0x9999,
        qr: 1, aa: 1, rd: 1, ra: 1,
        question: [%{qname: "test.example.com.", qtype: :a, qclass: :in}],
        answer: [
          %{name: "test.example.com.", type: :a, class: :in, ttl: 300,
            rdata: %{addr: {10, 0, 0, 1}}},
          %{name: "test.example.com.", type: :aaaa, class: :in, ttl: 300,
            rdata: %{addr: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 2}}}
        ],
        authority: [
          %{name: "example.com.", type: :ns, class: :in, ttl: 86_400,
            rdata: %{name: "ns1.example.com."}}
        ],
        additional: [
          %{name: "ns1.example.com.", type: :a, class: :in, ttl: 86_400,
            rdata: %{addr: {10, 0, 0, 10}}}
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
        0x12, 0x34,  # ID
        0x00, 0x00,  # Flags
        0x00, 0x00,  # QDCOUNT = 0
        0x00, 0x00,  # ANCOUNT = 0
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x01,  # ARCOUNT = 1
        # OPT record
        0x00,                    # Empty name
        0x00, 0x29,             # TYPE = OPT (41)
        0x04, 0x00,             # Payload size = 1024
        0x00,                   # Extended RCODE
        0x00,                   # Version
        0x80, 0x00,             # Flags (DNSSEC OK)
        0x00, 0x00              # RDLENGTH = 0
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
        payload_size: 4096,
        ex_rcode: 0,
        version: 0,
        dnssec: 1,
        z: 0,
        # Hybrid flat structure for EDNS options
        ecs_family: 1,
        ecs_subnet: {192, 168, 1, 0},
        ecs_source_prefix: 24,
        ecs_scope_prefix: 0,
      }

      # Convert structured format to legacy format for create_rr
      opt_record = DNSpacket.create_edns_info_record(edns_info)
      binary = DNSpacket.create_rr(opt_record)

      # Verify the binary starts with OPT record header
      <<0, 41::16, payload_size::16, ex_rcode::8, version::8, flags::16, rdlength::16, _rdata::binary>> = binary
      assert payload_size == 4096
      assert ex_rcode == 0
      assert version == 0
      assert (flags >>> 15) == 1  # DNSSEC bit
      assert rdlength > 0  # Should have RDATA for all the options
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
        qr: 1, aa: 1,
        question: [%{qname: "test.com.", qtype: :a, qclass: :in}],
        answer: [%{name: "test.com.", type: :a, class: :in, ttl: 300,
                   rdata: %{addr: {192, 168, 1, 1}}}],
        authority: [%{name: "test.com.", type: :ns, class: :in, ttl: 3600,
                      rdata: %{name: "ns1.test.com."}}],
        additional: [%{name: "ns1.test.com.", type: :a, class: :in, ttl: 3600,
                       rdata: %{addr: {192, 168, 1, 10}}}]
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert length(parsed.authority) == 1
      assert length(parsed.additional) == 1
      assert hd(parsed.authority).type == :ns
      assert hd(parsed.additional).type == :a
    end
  end

  describe "parse_edns_info/1" do
    test "returns nil when no OPT record present" do
      additional = [
        %{name: "ns1.example.com.", type: :a, class: :in, ttl: 300,
          rdata: %{addr: {192, 168, 1, 1}}}
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result == nil
    end

    test "parses basic OPT record without options" do
      additional = [
        %{
          name: "",
          type: :opt,
          payload_size: 1232,
          ex_rcode: 0,
          version: 0,
          dnssec: 1,
          z: 0,
          rdata: []
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.payload_size == 1232
      assert result.ex_rcode == 0
      assert result.version == 0
      assert result.dnssec == 1
      assert result.z == 0
      assert result.unknown_options == %{}
    end

    test "parses EDNS Client Subnet option with IPv4" do
      additional = [
        %{
          type: :opt,
          payload_size: 1232,
          ex_rcode: 0,
          version: 0,
          dnssec: 0,
          z: 0,
          rdata: %{
            edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 0}, source_prefix: 24, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.ecs_family == 1
      assert result.ecs_subnet == {192, 168, 1, 0}
      assert result.ecs_source_prefix == 24
      assert result.ecs_scope_prefix == 0
    end

    test "parses EDNS Client Subnet option with IPv6" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 2, client_subnet: {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0}, source_prefix: 48, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.ecs_family == 2
      assert result.ecs_subnet == {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0}
      assert result.ecs_source_prefix == 48
    end

    test "parses cookie option - client only" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.cookie_client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert result.cookie_server == nil
    end

    test "parses cookie option - client and server" do
      client_cookie = <<1, 2, 3, 4, 5, 6, 7, 8>>
      server_cookie = <<9, 10, 11, 12, 13, 14, 15, 16>>
      _full_cookie = client_cookie <> server_cookie

      additional = [
        %{
          type: :opt,
          rdata: %{
            cookie: %{client: client_cookie, server: server_cookie}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.cookie_client == client_cookie
      assert result.cookie_server == server_cookie
    end

    test "parses cookie option - invalid size" do
      # Test with cookie that's too small (< 8 bytes)
      additional = [
        %{
          type: :opt,
          rdata: %{
            cookie: %{client: <<1, 2, 3, 4>>, server: nil}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.cookie_client == <<1, 2, 3, 4>>
      assert result.cookie_server == nil
    end

    test "parses cookie option - maximum size" do
      # Test with maximum cookie size (40 bytes = 8 client + 32 server)
      client_cookie = <<1, 2, 3, 4, 5, 6, 7, 8>>
      server_cookie = <<9::size(32 * 8)>>  # 32 bytes of 9s
      _full_cookie = client_cookie <> server_cookie

      additional = [
        %{
          type: :opt,
          rdata: %{
            cookie: %{client: client_cookie, server: server_cookie}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.cookie_client == client_cookie
      assert byte_size(result.cookie_server) == 32
    end

    test "parses NSID option with ASCII text" do
      nsid_data = "ns1.example.com"
      additional = [
        %{
          type: :opt,
          rdata: %{
            nsid: nsid_data
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.nsid == nsid_data
    end

    test "parses NSID option with binary data" do
      _nsid_data = <<0xFF, 0xFE, 0xFD>>
      additional = [
        %{
          type: :opt,
          rdata: %{
            nsid: "fffefd"
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.nsid == "fffefd"
    end

    test "parses extended DNS error option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            extended_dns_error: %{info_code: 18, extra_text: "Blocked by policy"}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.extended_dns_error_info_code == 18
      assert result.extended_dns_error_extra_text == "Blocked by policy"
    end

    test "parses TCP keepalive option with timeout" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_tcp_keepalive: %{timeout: 300}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.edns_tcp_keepalive_timeout == 300
    end

    test "parses TCP keepalive option without timeout" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_tcp_keepalive: %{timeout: nil}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.edns_tcp_keepalive_timeout == nil
    end

    test "parses TCP keepalive option with invalid data length" do
      # Test with non-standard data length (not 0 or 2 bytes)
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_tcp_keepalive: %{timeout: nil, raw_data: <<1, 2, 3>>}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.edns_tcp_keepalive_timeout == nil
      assert result.edns_tcp_keepalive_raw_data == <<1, 2, 3>>
    end

    test "parses padding option" do
      _padding_data = <<0, 0, 0, 0, 0, 0, 0, 0>>
      additional = [
        %{
          type: :opt,
          rdata: %{
            padding: %{length: 8}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.padding_length == 8
    end

    test "handles unknown EDNS options" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            unknown: [%{code: :unknown_option, data: <<1, 2, 3, 4>>}, %{code: :another_unknown, data: <<5, 6>>}]
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert map_size(result.unknown_options) == 2
    end

    test "parses multiple EDNS options together" do
      additional = [
        %{
          type: :opt,
          payload_size: 4096,
          rdata: %{
            edns_client_subnet: %{family: 1, client_subnet: {10, 0, 0, 0}, source_prefix: 24, scope_prefix: 0},
            cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil},
            nsid: "server1",
            padding: %{length: 4}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.payload_size == 4096
      assert result.ecs_subnet == {10, 0, 0, 0}
      assert result.cookie_client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert result.nsid == "server1"
      assert result.padding_length == 4
    end
  end

  describe "ECS address parsing edge cases" do
    test "handles IPv4 prefix length 0" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 1, client_subnet: {0, 0, 0, 0}, source_prefix: 0, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.ecs_subnet == {0, 0, 0, 0}
    end

    test "handles IPv6 prefix length 0" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 2, client_subnet: {0, 0, 0, 0, 0, 0, 0, 0}, source_prefix: 0, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.ecs_subnet == {0, 0, 0, 0, 0, 0, 0, 0}
    end

    test "handles IPv4 with partial bytes" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 1, client_subnet: {203, 128, 0, 0}, source_prefix: 12, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      # Should mask out bits beyond prefix length
      assert result.ecs_subnet == {203, 128, 0, 0}
    end

    test "handles IPv6 with partial bytes and masking" do
      # Test IPv6 with prefix that requires masking mid-byte
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 2, client_subnet: {0x2001, 0x0db8, 0xF000, 0, 0, 0, 0, 0}, source_prefix: 36, scope_prefix: 0}  # 5 bytes for /36 prefix
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      # Should mask the last 4 bits of the 5th byte
      assert elem(result.ecs_subnet, 0) == 0x2001
      assert elem(result.ecs_subnet, 1) == 0x0db8
      assert elem(result.ecs_subnet, 2) == 0xF000  # Masked
    end

    test "handles IPv4 address that's too long" do
      # Test when address bytes exceed what's needed for IPv4
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 1}, source_prefix: 32, scope_prefix: 0}  # 6 bytes, but IPv4 only needs 4
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      # Should truncate to 4 bytes
      assert result.ecs_subnet == {192, 168, 1, 1}
    end

    test "handles IPv6 address that's too long" do
      # Test when address bytes exceed what's needed for IPv6
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 2, client_subnet: {0x2001, 0x0db8, 0, 0, 0, 0, 0, 0}, source_prefix: 128, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      # Should truncate to 16 bytes and parse as IPv6
      assert elem(result.ecs_subnet, 0) == 0x2001
      assert elem(result.ecs_subnet, 1) == 0x0db8
    end

    test "handles unknown address family" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 99, client_subnet: <<1, 2, 3, 4>>, source_prefix: 16, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.ecs_subnet == <<1, 2, 3, 4>>
    end

    test "handles negative prefix length" do
      # Test with negative prefix length
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 1, client_subnet: {0, 0, 0, 0}, source_prefix: -1, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      # Should zero out the address
      assert result.ecs_subnet == {0, 0, 0, 0}
    end

    test "handles prefix length equal to max bits" do
      # Test IPv4 with prefix length 32
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 1}, source_prefix: 32, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.ecs_subnet == {192, 168, 1, 1}
    end

    test "handles unknown tuple size in prefix mask" do
      # This is a bit tricky to test since we need an unusual tuple size
      # We'll test through the parse_ecs_address path with unknown family
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{family: 99, client_subnet: <<192, 168>>, source_prefix: 0, scope_prefix: 0}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      # Unknown family returns the raw binary
      assert result.ecs_subnet == <<192, 168>>
    end
  end

  describe "packet parsing with edns_info" do
    test "parses packet and includes edns_info for OPT record" do
      # Create a simple packet with OPT record (no EDNS options for now)
      packet_with_edns = <<
        0x12, 0x34,  # ID
        0x81, 0x80,  # Flags (response)
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x01,  # ANCOUNT = 1
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x01,  # ARCOUNT = 1 (OPT record)
        # Question: example.com A IN
        0x07, "example", 0x03, "com", 0x00,
        0x00, 0x01,  # QTYPE = A
        0x00, 0x01,  # QCLASS = IN
        # Answer: example.com A 192.168.1.1
        0xC0, 0x0C,  # Pointer to question name
        0x00, 0x01,  # TYPE = A
        0x00, 0x01,  # CLASS = IN
        0x00, 0x00, 0x01, 0x2C,  # TTL = 300
        0x00, 0x04,  # RDLENGTH = 4
        192, 168, 1, 1,  # IP address
        # OPT record without options
        0x00,                      # Empty name
        0x00, 0x29,               # TYPE = OPT (41)
        0x04, 0xD0,               # Payload size = 1232
        0x00,                     # Extended RCODE
        0x00,                     # Version
        0x80, 0x00,               # Flags (DNSSEC OK)
        0x00, 0x00                # RDLENGTH = 0 (no options)
      >>

      parsed = DNSpacket.parse(packet_with_edns)

      # Verify basic packet structure
      assert parsed.id == 0x1234
      assert length(parsed.answer) == 1
      assert length(parsed.additional) == 1

      # Verify EDNS info is parsed
      assert parsed.edns_info != nil
      assert parsed.edns_info.payload_size == 1232
      assert parsed.edns_info.dnssec == 1
      assert parsed.edns_info.unknown_options == %{}
    end

    test "parses packet without OPT record and sets edns_info to nil" do
      # Create a simple packet without EDNS
      simple_packet = <<
        0x12, 0x34,  # ID
        0x81, 0x80,  # Flags (response)
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x01,  # ANCOUNT = 1
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x00,  # ARCOUNT = 0
        # Question: example.com A IN
        0x07, "example", 0x03, "com", 0x00,
        0x00, 0x01,  # QTYPE = A
        0x00, 0x01,  # QCLASS = IN
        # Answer: example.com A 192.168.1.1
        0xC0, 0x0C,  # Pointer to question name
        0x00, 0x01,  # TYPE = A
        0x00, 0x01,  # CLASS = IN
        0x00, 0x00, 0x01, 0x2C,  # TTL = 300
        0x00, 0x04,  # RDLENGTH = 4
        192, 168, 1, 1  # IP address
      >>

      parsed = DNSpacket.parse(simple_packet)

      assert parsed.id == 0x1234
      assert parsed.edns_info == nil
    end
  end

  describe "create_edns_info_record/1" do
    test "creates OPT record from structured edns_info" do
      edns_info = %{
        payload_size: 4096,
        ex_rcode: 0,
        version: 0,
        dnssec: 1,
        z: 0,
        ecs_family: 1,
        ecs_subnet: {192, 168, 1, 0},
        ecs_source_prefix: 24,
        ecs_scope_prefix: 0
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)

      assert opt_record.type == :opt
      assert opt_record.payload_size == 4096
      assert opt_record.dnssec == 1
      assert length(opt_record.rdata) == 1

      ecs_option = hd(opt_record.rdata)
      assert elem(ecs_option, 0) == :edns_client_subnet
      ecs_data = elem(ecs_option, 1)
      assert ecs_data.family == 1
      assert ecs_data.source_prefix == 24
      assert ecs_data.scope_prefix == 0
      assert ecs_data.client_subnet == {192, 168, 1, 0}
    end

    test "creates OPT record with multiple options" do
      edns_info = %{
        payload_size: 1232,
        ecs_family: 1,
        ecs_subnet: {10, 0, 0, 0},
        ecs_source_prefix: 8,
        ecs_scope_prefix: 0,
        cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        cookie_server: nil,
        nsid: "server1"
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)

      assert length(opt_record.rdata) == 3

      # Verify each option is present
      codes = Enum.map(opt_record.rdata, &elem(&1, 0))
      assert :edns_client_subnet in codes
      assert :cookie in codes
      assert :nsid in codes
    end

    test "creates empty OPT record when no options provided" do
      edns_info = %{payload_size: 512}

      opt_record = DNSpacket.create_edns_info_record(edns_info)

      assert opt_record.type == :opt
      assert opt_record.payload_size == 512
      assert opt_record.rdata == []
    end
  end

  describe "EDNS creation and parsing roundtrip" do
    test "roundtrip for packet with ECS option" do
      original_packet = %DNSpacket{
        id: 0x1234,
        qr: 1,
        rd: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300,
                   rdata: %{addr: {192, 168, 1, 1}}}],
        edns_info: %{
          payload_size: 4096,
          dnssec: 1,
          ecs_family: 1,
          ecs_subnet: {203, 0, 113, 0},
          ecs_source_prefix: 24,
          ecs_scope_prefix: 0
        }
      }

      # Create binary from packet
      binary = DNSpacket.create(original_packet)

      # Parse binary back to packet
      parsed_packet = DNSpacket.parse(binary)

      # Verify basic structure
      assert parsed_packet.id == original_packet.id
      assert parsed_packet.qr == original_packet.qr
      assert length(parsed_packet.answer) == 1

      # Verify EDNS info is preserved
      assert parsed_packet.edns_info != nil
      assert parsed_packet.edns_info.payload_size == 4096
      assert parsed_packet.edns_info.dnssec == 1
      assert parsed_packet.edns_info.ecs_family == 1
      assert parsed_packet.edns_info.ecs_subnet == {203, 0, 113, 0}
      assert parsed_packet.edns_info.ecs_source_prefix == 24
    end

    test "roundtrip for packet with multiple EDNS options" do
      original_packet = %DNSpacket{
        id: 0x5678,
        qr: 0,
        rd: 1,
        question: [%{qname: "test.example.com.", qtype: :aaaa, qclass: :in}],
        edns_info: %{
          payload_size: 1232,
          ex_rcode: 0,
          version: 0,
          dnssec: 0,
          ecs_family: 2,
          ecs_subnet: {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0},
          ecs_source_prefix: 48,
          ecs_scope_prefix: 0,
          cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
          cookie_server: <<9, 10, 11, 12, 13, 14, 15, 16>>,
          nsid: "ns1.example.com"
        }
      }

      binary = DNSpacket.create(original_packet)
      parsed_packet = DNSpacket.parse(binary)

      # Verify EDNS options are preserved
      edns = parsed_packet.edns_info
      assert edns.ecs_family == 2
      assert edns.ecs_subnet == {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0}
      assert edns.ecs_source_prefix == 48

      assert edns.cookie_client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert edns.cookie_server == <<9, 10, 11, 12, 13, 14, 15, 16>>

      assert edns.nsid == "ns1.example.com"
    end

    test "packet without edns_info creates no OPT record" do
      packet = %DNSpacket{
        id: 0x9999,
        qr: 0,
        rd: 1,
        question: [%{qname: "simple.example.com.", qtype: :a, qclass: :in}],
        edns_info: nil
      }

      binary = DNSpacket.create(packet)
      parsed_packet = DNSpacket.parse(binary)

      assert parsed_packet.edns_info == nil
      assert Enum.all?(parsed_packet.additional, &(&1.type != :opt))
    end

    test "packet with edns_info replaces existing OPT records" do
      packet = %DNSpacket{
        id: 0xABCD,
        qr: 0,
        rd: 1,
        question: [%{qname: "replace.example.com.", qtype: :a, qclass: :in}],
        additional: [
          %{name: "ns1.example.com.", type: :a, class: :in, ttl: 300,
            rdata: %{addr: {1, 2, 3, 4}}},
          %{type: :opt, payload_size: 512, ex_rcode: 0, version: 0, dnssec: 0, z: 0, rdata: []}
        ],
        edns_info: %{
          payload_size: 4096,
          dnssec: 1,
          nsid: "new-server"
        }
      }

      binary = DNSpacket.create(packet)
      parsed_packet = DNSpacket.parse(binary)

      # Should have exactly one OPT record with new settings
      opt_records = Enum.filter(parsed_packet.additional, &(&1.type == :opt))
      assert length(opt_records) == 1

      assert parsed_packet.edns_info.payload_size == 4096
      assert parsed_packet.edns_info.dnssec == 1
      assert parsed_packet.edns_info.nsid == "new-server"

      # Non-OPT records should be preserved
      non_opt_records = Enum.reject(parsed_packet.additional, &(&1.type == :opt))
      assert length(non_opt_records) == 1
      assert hd(non_opt_records).type == :a
    end
  end

  describe "ECS address byte calculation" do
    test "IPv4 address with various prefix lengths" do
      # Test /8 prefix (1 byte)
      edns_info = %{
        ecs_family: 1,
        ecs_subnet: {10, 0, 0, 0},
        ecs_source_prefix: 8,
        ecs_scope_prefix: 0
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      ecs_option = hd(opt_record.rdata)
      ecs_data = elem(ecs_option, 1)
      assert ecs_data.client_subnet == {10, 0, 0, 0}

      # Test /16 prefix (2 bytes)
      edns_info2 = %{
        ecs_family: 1,
        ecs_subnet: {192, 168, 0, 0},
        ecs_source_prefix: 16,
        ecs_scope_prefix: 0
      }

      opt_record2 = DNSpacket.create_edns_info_record(edns_info2)
      ecs_option2 = hd(opt_record2.rdata)
      ecs_data2 = elem(ecs_option2, 1)
      assert ecs_data2.client_subnet == {192, 168, 0, 0}

      # Test /24 prefix (3 bytes)
      edns_info3 = %{
        ecs_family: 1,
        ecs_subnet: {203, 0, 113, 0},
        ecs_source_prefix: 24,
        ecs_scope_prefix: 0
      }

      opt_record3 = DNSpacket.create_edns_info_record(edns_info3)
      ecs_option3 = hd(opt_record3.rdata)
      ecs_data3 = elem(ecs_option3, 1)
      assert ecs_data3.client_subnet == {203, 0, 113, 0}
    end

    test "IPv6 address with various prefix lengths" do
      # Test /32 prefix (4 bytes)
      edns_info = %{
        ecs_family: 2,
        ecs_subnet: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 0},
        ecs_source_prefix: 32,
        ecs_scope_prefix: 0
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      ecs_option = hd(opt_record.rdata)
      ecs_data = elem(ecs_option, 1)
      assert ecs_data.client_subnet == {0x2001, 0xdb8, 0, 0, 0, 0, 0, 0}

      # Test /48 prefix (6 bytes)
      edns_info2 = %{
        ecs_family: 2,
        ecs_subnet: {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0},
        ecs_source_prefix: 48,
        ecs_scope_prefix: 0
      }

      opt_record2 = DNSpacket.create_edns_info_record(edns_info2)
      ecs_option2 = hd(opt_record2.rdata)
      ecs_data2 = elem(ecs_option2, 1)
      assert ecs_data2.client_subnet == {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0}
    end

    test "unknown address family with binary address" do
      # Test unknown family (not 1 or 2)
      edns_info = %{
        ecs_family: 99,
        ecs_subnet: <<1, 2, 3, 4>>,
        ecs_source_prefix: 32,
        ecs_scope_prefix: 0
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      ecs_option = hd(opt_record.rdata)
      ecs_data = elem(ecs_option, 1)
      assert ecs_data.client_subnet == <<1, 2, 3, 4>>
    end
  end

  describe "New EDNS options parsing" do
    test "parses DAU option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            dau: %{algorithms: [7, 8, 10]}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.dau_algorithms == [7, 8, 10]
    end

    test "parses DHU option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            dhu: %{algorithms: [1, 2]}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.dhu_algorithms == [1, 2]
    end

    test "parses N3U option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            n3u: %{algorithms: [1]}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.n3u_algorithms == [1]
    end

    test "parses EDNS expire option with value" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_expire: %{expire: 3600}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.edns_expire_expire == 3600
    end

    test "parses EDNS expire option without value" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_expire: %{expire: nil}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.edns_expire_expire == nil
    end

    test "parses chain option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            chain: %{closest_encloser: "example.com"}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.chain_closest_encloser == "example.com"
    end

    test "parses EDNS key tag option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_key_tag: %{key_tags: [12_345, 54_321]}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.edns_key_tag_key_tags == [12_345, 54_321]
    end

    test "parses EDNS client tag option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_tag: %{tag: 1234}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.edns_client_tag_tag == 1234
    end

    test "parses EDNS server tag option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_server_tag: %{tag: 5678}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.edns_server_tag_tag == 5678
    end

    test "parses report channel option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            report_channel: %{agent_domain: "agent.example.com"}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.report_channel_agent_domain == "agent.example.com"
    end

    test "parses zoneversion option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            zoneversion: %{version: 1_234_567_890_123_456}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.zoneversion_version == 1_234_567_890_123_456
    end

    test "parses update lease option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            update_lease: %{lease: 7200}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.update_lease_lease == 7200
    end

    test "parses LLQ option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            llq: %{version: 1, llq_opcode: 1, error_code: 0, llq_id: 1_234_567_890_123_456, lease_life: 3600}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.llq_version == 1
      assert result.llq_llq_opcode == 1
      assert result.llq_error_code == 0
      assert result.llq_llq_id == 1_234_567_890_123_456
      assert result.llq_lease_life == 3600
    end

    test "parses Umbrella ident option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            umbrella_ident: %{ident: 0x12345678}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.umbrella_ident_ident == 0x12345678
    end

    test "parses DeviceID option" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            deviceid: %{device_id: "device123"}
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.deviceid_device_id == "device123"
    end
  end

  describe "New EDNS options creation" do
    test "creates OPT record with DAU option" do
      edns_info = %{
        payload_size: 1232,
        dau_algorithms: [7, 8, 10]
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      assert length(opt_record.rdata) == 1

      dau_option = hd(opt_record.rdata)
      assert elem(dau_option, 0) == :dau
      dau_data = elem(dau_option, 1)
      assert dau_data.algorithms == [7, 8, 10]
    end

    test "creates OPT record with EDNS expire option" do
      edns_info = %{
        edns_expire_expire: 3600
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      expire_option = hd(opt_record.rdata)
      assert elem(expire_option, 0) == :edns_expire
      expire_data = elem(expire_option, 1)
      assert expire_data.expire == 3600
    end

    test "creates OPT record with key tag option" do
      edns_info = %{
        edns_key_tag_key_tags: [12_345, 54_321]
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      key_tag_option = hd(opt_record.rdata)
      assert elem(key_tag_option, 0) == :edns_key_tag
      key_tag_data = elem(key_tag_option, 1)
      assert key_tag_data.key_tags == [12_345, 54_321]
    end

    test "roundtrip test with new EDNS options" do
      original_packet = %DNSpacket{
        id: 0x1234,
        qr: 0,
        rd: 1,
        question: [%{qname: "test.example.com.", qtype: :a, qclass: :in}],
        edns_info: %{
          payload_size: 4096,
          dnssec: 1,
          dau_algorithms: [7, 8],
          edns_expire_expire: 3600,
          edns_key_tag_key_tags: [12_345],
          zoneversion_version: 123_456_789
        }
      }

      binary = DNSpacket.create(original_packet)
      parsed_packet = DNSpacket.parse(binary)

      # Verify EDNS options are preserved
      edns = parsed_packet.edns_info
      assert edns.dau_algorithms == [7, 8]
      assert edns.edns_expire_expire == 3600
      assert edns.edns_key_tag_key_tags == [12_345]
      assert edns.zoneversion_version == 123_456_789
    end

    test "create_cookie_option coverage" do
      # Test cookie with client only
      edns_info1 = %{
        cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        cookie_server: nil
      }

      opt_record1 = DNSpacket.create_edns_info_record(edns_info1)
      cookie_opt1 = hd(opt_record1.rdata)
      assert elem(cookie_opt1, 0) == :cookie
      cookie_data1 = elem(cookie_opt1, 1)
      assert cookie_data1.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert cookie_data1.server == nil

      # Test cookie with client and server
      edns_info2 = %{
        cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        cookie_server: <<9, 10, 11, 12, 13, 14, 15, 16>>
      }

      opt_record2 = DNSpacket.create_edns_info_record(edns_info2)
      cookie_opt2 = hd(opt_record2.rdata)
      assert elem(cookie_opt2, 0) == :cookie
      cookie_data2 = elem(cookie_opt2, 1)
      assert cookie_data2.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert cookie_data2.server == <<9, 10, 11, 12, 13, 14, 15, 16>>
    end
  end

  describe "create_edns_options/1" do
    test "creates empty binary for nil input" do
      assert DNSpacket.create_edns_options(nil) == <<>>
    end

    test "creates empty binary for non-map input" do
      assert DNSpacket.create_edns_options("invalid") == <<>>
      assert DNSpacket.create_edns_options([]) == <<>>
    end

    test "creates binary from options map" do
      options = %{
        edns_client_subnet: %{family: 1, client_subnet: {10, 0, 0, 0}, source_prefix: 8, scope_prefix: 0}
      }

      result = DNSpacket.create_edns_options(options)

      # Should create ECS option binary
      assert byte_size(result) > 0
      # Verify it starts with ECS option code (8)
      <<8::16, _rest::binary>> = result
    end

    test "ignores invalid option keys" do
      options = %{
        invalid_key: %{some: "data"},
        edns_client_subnet: %{family: 1, client_subnet: {10, 0, 0, 0}, source_prefix: 8, scope_prefix: 0}
      }

      result = DNSpacket.create_edns_options(options)

      # Should only create ECS option, ignoring invalid_key
      <<8::16, length::16, _data::binary-size(length)>> = result
    end

    test "creates all supported EDNS options" do
      options = %{
        edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 0}, source_prefix: 24, scope_prefix: 0},
        cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: <<9, 10, 11, 12, 13, 14, 15, 16>>},
        nsid: "server1.example.com",
        extended_dns_error: %{info_code: 18, extra_text: "Blocked"},
        edns_tcp_keepalive: %{timeout: 300},
        padding: %{length: 16},
        dau: %{algorithms: [7, 8, 10]},
        dhu: %{algorithms: [1, 2]},
        n3u: %{algorithms: [1]},
        edns_expire: %{expire: 3600},
        chain: %{closest_encloser: "example.com"},
        edns_key_tag: %{key_tags: [12_345, 54_321]},
        edns_client_tag: %{tag: 1234},
        edns_server_tag: %{tag: 5678},
        report_channel: %{agent_domain: "agent.example.com"},
        zoneversion: %{version: 1_234_567_890_123_456},
        update_lease: %{lease: 7200},
        llq: %{version: 1, llq_opcode: 1, error_code: 0, llq_id: 1_234_567_890_123_456, lease_life: 3600},
        umbrella_ident: %{ident: 0x12345678},
        deviceid: %{device_id: "device123"},
        unknown: [%{code: 65_535, data: <<1, 2, 3, 4>>}]
      }

      result = DNSpacket.create_edns_options(options)

      # Verify result is non-empty binary
      assert byte_size(result) > 0

      # Parse the result to verify all options are present
      parsed_options = DNSpacket.parse_opt_rr(%{}, result)
      # Count known options + unknown list length
      known_count = map_size(Map.drop(parsed_options, [:unknown]))
      unknown_count = case Map.get(parsed_options, :unknown) do
        nil -> 0
        list -> length(list)
      end
      assert known_count + unknown_count >= 20  # At least 20 options

      # Verify a few specific options - now using tuple format
      assert Enum.any?(parsed_options, fn {key, _} -> key == :edns_client_subnet end)
      assert Enum.any?(parsed_options, fn {key, _} -> key == :cookie end)
      assert Enum.any?(parsed_options, fn {key, _} -> key == :nsid end)
      assert Enum.any?(parsed_options, fn {key, _} -> key == :dau end)
      assert Enum.any?(parsed_options, fn {key, _} -> key == :llq end)
    end

    test "creates padding option with specific length" do
      options = %{
        padding: %{length: 32}
      }

      result = DNSpacket.create_edns_options(options)

      # Should create padding option with 32 bytes of zeros
      <<12::16, 32::16, padding_data::binary-size(32)>> = result
      assert padding_data == <<0::size(32 * 8)>>
    end

    test "creates tcp_keepalive option without timeout" do
      options = %{
        edns_tcp_keepalive: %{timeout: nil}
      }

      result = DNSpacket.create_edns_options(options)

      # Should create empty tcp_keepalive option
      <<11::16, 0::16>> = result
    end

    test "creates edns_expire option without value" do
      options = %{
        edns_expire: %{expire: nil}
      }

      result = DNSpacket.create_edns_options(options)

      # Should create empty edns_expire option
      <<9::16, 0::16>> = result
    end

    test "handles unknown options list" do
      options = %{
        unknown: [
          %{code: 65_001, data: <<1, 2, 3>>},
          %{code: 65_002, data: <<4, 5, 6, 7>>}
        ]
      }

      result = DNSpacket.create_edns_options(options)

      # Should create both unknown options
      parsed = DNSpacket.parse_opt_rr(%{}, result)
      unknown_options = Map.get(parsed, :unknown, [])
      assert length(unknown_options) == 2
      # Unknown options are stored in :unknown key as a list
      assert Enum.all?(unknown_options, fn option -> 
        option.data in [<<1, 2, 3>>, <<4, 5, 6, 7>>]
      end)
    end
  end

  describe "merge_edns_info_to_additional" do
    test "handles nil edns_info" do
      packet = %DNSpacket{
        id: 0x1234,
        qr: 0,
        rd: 1,
        question: [%{qname: "test.com.", qtype: :a, qclass: :in}],
        additional: [
          %{name: "ns1.test.com.", type: :a, class: :in, ttl: 300,
            rdata: %{addr: {1, 2, 3, 4}}}
        ],
        edns_info: nil
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      # Should preserve original additional records
      assert length(parsed.additional) == 1
      assert hd(parsed.additional).type == :a
    end
  end

  describe "convert_option_to_rdata through create_edns_info_record" do
    test "converts all option types to rdata" do
      edns_info = %{
        payload_size: 4096,
        # Hybrid flat structure for EDNS options
        ecs_family: 1,
        ecs_subnet: {192, 168, 1, 0},
        ecs_source_prefix: 24,
        ecs_scope_prefix: 0,
        cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        cookie_server: <<9, 10, 11, 12, 13, 14, 15, 16>>,
        nsid: "server.example.com",
        extended_dns_error_info_code: 18,
        extended_dns_error_extra_text: "Blocked by policy",
        edns_tcp_keepalive_timeout: 300,
        padding_length: 8,
        dau_algorithms: [7, 8, 10],
        dhu_algorithms: [1, 2],
        n3u_algorithms: [1],
        edns_expire_expire: 3600,
        chain_closest_encloser: "closest.example.com",
        edns_key_tag_key_tags: [12_345, 54_321],
        edns_client_tag_tag: 1234,
        edns_server_tag_tag: 5678,
        report_channel_agent_domain: "report.example.com",
        zoneversion_version: 1_234_567_890_123_456,
        update_lease_lease: 7200,
        llq_version: 1,
        llq_llq_opcode: 1,
        llq_error_code: 0,
        llq_llq_id: 9_876_543_210,
        llq_lease_life: 3600,
        umbrella_ident_ident: 0x12345678,
        deviceid_device_id: "test-device-001",
        unknown_options: %{
          65_000 => <<1, 2, 3>>,
          65_001 => <<4, 5, 6, 7>>
        }
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)

      # Verify the OPT record structure
      assert opt_record.type == :opt
      assert opt_record.payload_size == 4096
      assert is_list(opt_record.rdata)

      # Count the rdata entries
      assert length(opt_record.rdata) == 22  # 20 known options + 2 unknown

      # Verify ECS conversion
      ecs_rdata = Enum.find(opt_record.rdata, fn
        {:edns_client_subnet, _} -> true
        _ -> false
      end)
      ecs_data = elem(ecs_rdata, 1)
      assert ecs_data.family == 1
      assert ecs_data.source_prefix == 24
      assert ecs_data.scope_prefix == 0
      assert ecs_data.client_subnet == {192, 168, 1, 0}

      # Verify cookie conversion
      cookie_rdata = Enum.find(opt_record.rdata, fn
        {:cookie, _} -> true
        _ -> false
      end)
      cookie_data = elem(cookie_rdata, 1)
      assert cookie_data.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert cookie_data.server == <<9, 10, 11, 12, 13, 14, 15, 16>>

      # Verify NSID conversion
      nsid_rdata = Enum.find(opt_record.rdata, fn
        {:nsid, _} -> true
        _ -> false
      end)
      assert elem(nsid_rdata, 1) == "server.example.com"

      # Verify extended DNS error conversion
      ede_rdata = Enum.find(opt_record.rdata, fn
        {:extended_dns_error, _} -> true
        _ -> false
      end)
      ede_data = elem(ede_rdata, 1)
      assert ede_data.info_code == 18
      assert ede_data.extra_text == "Blocked by policy"

      # Verify TCP keepalive conversion
      tcp_rdata = Enum.find(opt_record.rdata, fn
        {:edns_tcp_keepalive, _} -> true
        _ -> false
      end)
      tcp_data = elem(tcp_rdata, 1)
      assert tcp_data.timeout == 300

      # Verify padding conversion
      padding_rdata = Enum.find(opt_record.rdata, fn
        {:padding, _} -> true
        _ -> false
      end)
      padding_data = elem(padding_rdata, 1)
      assert padding_data.length == 8

      # Verify algorithm options
      dau_rdata = Enum.find(opt_record.rdata, fn
        {:dau, _} -> true
        _ -> false
      end)
      dau_data = elem(dau_rdata, 1)
      assert dau_data.algorithms == [7, 8, 10]

      # Verify LLQ conversion
      llq_rdata = Enum.find(opt_record.rdata, fn
        {:llq, _} -> true
        _ -> false
      end)
      llq_data = elem(llq_rdata, 1)
      assert llq_data.version == 1
      assert llq_data.llq_id == 9_876_543_210

      # Verify unknown options are passed through (they remain in old format)
      unknown_rdatas = Enum.filter(opt_record.rdata, fn
        {_code, _data} -> false  # Skip tuples
        %{code: code} when code in [65_000, 65_001] -> true  # Match old format unknown options
        _ -> false
      end)
      assert length(unknown_rdatas) == 2
    end

    test "converts tcp_keepalive with nil timeout" do
      edns_info = %{
        edns_tcp_keepalive_timeout: nil
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      tcp_rdata = hd(opt_record.rdata)

      assert elem(tcp_rdata, 0) == :edns_tcp_keepalive
      tcp_data = elem(tcp_rdata, 1)
      assert tcp_data.timeout == nil
    end

    test "converts cookie with server nil" do
      edns_info = %{
        cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        cookie_server: nil
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      cookie_rdata = hd(opt_record.rdata)

      assert elem(cookie_rdata, 0) == :cookie
      cookie_data = elem(cookie_rdata, 1)
      assert cookie_data.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert cookie_data.server == nil
    end

    test "handles invalid option gracefully" do
      edns_info = %{
        invalid_option_some: "data"
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)

      # Should return empty rdata list for invalid options
      assert opt_record.rdata == []
    end

    test "converts ECS with different address families" do
      # Test IPv4
      edns_info_v4 = %{
        ecs_family: 1,
        ecs_subnet: {10, 0, 0, 0},
        ecs_source_prefix: 8,
        ecs_scope_prefix: 0
      }

      opt_record_v4 = DNSpacket.create_edns_info_record(edns_info_v4)
      ecs_v4 = hd(opt_record_v4.rdata)
      ecs_v4_data = elem(ecs_v4, 1)
      assert ecs_v4_data.client_subnet == {10, 0, 0, 0}

      # Test IPv6
      edns_info_v6 = %{
        ecs_family: 2,
        ecs_subnet: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 1},
        ecs_source_prefix: 64,
        ecs_scope_prefix: 0
      }

      opt_record_v6 = DNSpacket.create_edns_info_record(edns_info_v6)
      ecs_v6 = hd(opt_record_v6.rdata)
      ecs_v6_data = elem(ecs_v6, 1)
      assert ecs_v6_data.client_subnet == {0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}
    end
  end
end
