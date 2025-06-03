defmodule DNSpacketTest do
  use ExUnit.Case

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

  describe "concat_binary_list/1" do
    test "concatenates list of binaries" do
      list = [<<1, 2>>, <<3, 4>>, <<5, 6>>]
      result = DNSpacket.concat_binary_list(list)
      expected = <<1, 2, 3, 4, 5, 6>>
      assert result == expected
    end

    test "handles empty list" do
      result = DNSpacket.concat_binary_list([])
      expected = <<>>
      assert result == expected
    end

    test "handles single binary" do
      result = DNSpacket.concat_binary_list([<<1, 2, 3>>])
      expected = <<1, 2, 3>>
      assert result == expected
    end
  end

  describe "parse_opt_code/2" do
    test "parses EDNS client subnet option" do
      data = <<1::16, 24::8, 0::8, 192, 168, 1>>
      result = DNSpacket.parse_opt_code(:edns_client_subnet, data)
      expected = %{code: :edns_client_subnet, family: 1, source: 24, scope: 0, addr: <<192, 168, 1>>}
      assert result == expected
    end

    test "parses cookie option" do
      data = <<1, 2, 3, 4, 5, 6, 7, 8>>
      result = DNSpacket.parse_opt_code(:cookie, data)
      expected = %{code: :cookie, cookie: <<1, 2, 3, 4, 5, 6, 7, 8>>}
      assert result == expected
    end

    test "parses extended DNS error option" do
      data = <<15::16, 8::16, 18::16, "Blocked">>
      result = DNSpacket.parse_opt_code(:extended_dns_error, data)
      expected = %{code: :extended_dns_error, option_code: 15, info_code: 18, txt: "Blocked"}
      assert result == expected
    end

    test "handles unknown option code" do
      data = <<1, 2, 3, 4>>
      result = DNSpacket.parse_opt_code(:unknown, data)
      expected = %{code: :unknown, data: <<1, 2, 3, 4>>}
      assert result == expected
    end
  end

  describe "check_ecs/1" do
    test "returns default values for empty additional section" do
      result = DNSpacket.check_ecs([])
      expected = %{family: 0, scope: 0, addr: 0, source: 0}
      assert result == expected
    end

    test "extracts ECS data from OPT record" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :edns_client_subnet, family: 1, source: 24, scope: 0, addr: <<192, 168, 1>>}
          ]
        }
      ]
      result = DNSpacket.check_ecs(additional)
      expected = %{code: :edns_client_subnet, family: 1, source: 24, scope: 0, addr: <<192, 168, 1>>}
      assert result == expected
    end

    test "returns default when no ECS option found" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :cookie, cookie: <<1, 2, 3, 4>>}
          ]
        }
      ]
      result = DNSpacket.check_ecs(additional)
      expected = %{family: 0, scope: 0, addr: 0, source: 0}
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
    test "create_options/1 returns empty string" do
      result = DNSpacket.create_options(%{code: :test})
      assert result == ""
    end

    test "create_opt_rr/1 with empty list" do
      result = DNSpacket.create_opt_rr([])
      assert result == <<>>
    end

    test "create_opt_rr/2 with non-empty list" do
      result = DNSpacket.create_opt_rr([<<1, 2>>], <<>>)
      assert result == <<1, 2>>
    end

    test "create_opt_rr/2 with multiple options" do
      options = [<<0x00, 0x08>>, <<0x00, 0x04>>, <<192, 168, 1, 0>>]
      result = DNSpacket.create_opt_rr(options, <<0x10>>)
      expected = <<0x10, 0x00, 0x08, 0x00, 0x04, 192, 168, 1, 0>>
      assert result == expected
    end

    test "create_opt_rr/2 recursive with tail processing" do
      options = [<<1, 2>>, <<3, 4, 5>>, <<6>>]
      result = DNSpacket.create_opt_rr(options, <<0>>)
      expected = <<0, 1, 2, 3, 4, 5, 6>>
      assert result == expected
    end


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
      
      result = DNSpacket.parse_opt_rr([], opt_data)
      assert length(result) == 2
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

    test "create_options edge case coverage" do
      # Test the create_options function that currently returns empty string
      result = DNSpacket.create_options(%{code: :edns_client_subnet, data: <<1, 2, 3>>})
      assert result == ""
    end

    test "create_opt_rr with single option" do
      # Test create_opt_rr with exactly one option
      result = DNSpacket.create_opt_rr([<<0x00, 0x08, 0x00, 0x04, 192, 168, 1, 0>>])
      assert result == <<0x00, 0x08, 0x00, 0x04, 192, 168, 1, 0>>
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

    test "parse_opt_code with extended DNS error different format" do
      # Test different format of extended DNS error
      data = <<5::16, 4::16, 12::16, "Bad">>
      result = DNSpacket.parse_opt_code(:extended_dns_error, data)
      assert result.option_code == 5
      assert result.info_code == 12
      assert result.txt == "Bad"
    end

    test "check_ecs with malformed OPT record" do
      # Test check_ecs with OPT record but no ECS option
      additional = [
        %{type: :opt, rdata: [%{code: :other_option, data: <<1, 2, 3>>}]}
      ]
      result = DNSpacket.check_ecs(additional)
      assert result == %{family: 0, scope: 0, addr: 0, source: 0}
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
      assert result.options == %{}
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
          rdata: [
            %{code: :edns_client_subnet, family: 1, source: 24, scope: 0, addr: <<192, 168, 1>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.ecs.family == 1
      assert result.options.ecs.client_subnet == {192, 168, 1, 0}
      assert result.options.ecs.source_prefix == 24
      assert result.options.ecs.scope_prefix == 0
    end

    test "parses EDNS Client Subnet option with IPv6" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :edns_client_subnet, family: 2, source: 48, scope: 0, 
              addr: <<0x2001::16, 0xdb8::16, 0x1234::16>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.ecs.family == 2
      assert result.options.ecs.client_subnet == {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0}
      assert result.options.ecs.source_prefix == 48
    end

    test "parses cookie option - client only" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :cookie, cookie: <<1, 2, 3, 4, 5, 6, 7, 8>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.cookie.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert result.options.cookie.server == nil
    end

    test "parses cookie option - client and server" do
      client_cookie = <<1, 2, 3, 4, 5, 6, 7, 8>>
      server_cookie = <<9, 10, 11, 12, 13, 14, 15, 16>>
      full_cookie = client_cookie <> server_cookie
      
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :cookie, cookie: full_cookie}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.cookie.client == client_cookie
      assert result.options.cookie.server == server_cookie
    end

    test "parses NSID option with ASCII text" do
      nsid_data = "ns1.example.com"
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :nsid, data: nsid_data}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.nsid == nsid_data
    end

    test "parses NSID option with binary data" do
      nsid_data = <<0xFF, 0xFE, 0xFD>>
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :nsid, data: nsid_data}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.nsid == "fffefd"
    end

    test "parses extended DNS error option" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :extended_dns_error, info_code: 18, txt: "Blocked by policy"}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.extended_dns_error.info_code == 18
      assert result.options.extended_dns_error.extra_text == "Blocked by policy"
    end

    test "parses TCP keepalive option with timeout" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :edns_tcp_keepalive, data: <<300::16>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.tcp_keepalive.timeout == 300
    end

    test "parses TCP keepalive option without timeout" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :edns_tcp_keepalive, data: <<>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.tcp_keepalive.timeout == nil
    end

    test "parses padding option" do
      padding_data = <<0, 0, 0, 0, 0, 0, 0, 0>>
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :padding, data: padding_data}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.padding.length == 8
    end

    test "handles unknown EDNS options" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :unknown_option, data: <<1, 2, 3, 4>>},
            %{code: :another_unknown, data: <<5, 6>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert length(result.options.unknown) == 2
    end

    test "parses multiple EDNS options together" do
      additional = [
        %{
          type: :opt,
          payload_size: 4096,
          rdata: [
            %{code: :edns_client_subnet, family: 1, source: 24, scope: 0, addr: <<10, 0, 0>>},
            %{code: :cookie, cookie: <<1, 2, 3, 4, 5, 6, 7, 8>>},
            %{code: :nsid, data: "server1"},
            %{code: :padding, data: <<0, 0, 0, 0>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.payload_size == 4096
      assert result.options.ecs.client_subnet == {10, 0, 0, 0}
      assert result.options.cookie.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert result.options.nsid == "server1"
      assert result.options.padding.length == 4
    end
  end

  describe "ECS address parsing edge cases" do
    test "handles IPv4 prefix length 0" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :edns_client_subnet, family: 1, source: 0, scope: 0, addr: <<>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.ecs.client_subnet == {0, 0, 0, 0}
    end

    test "handles IPv6 prefix length 0" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :edns_client_subnet, family: 2, source: 0, scope: 0, addr: <<>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.ecs.client_subnet == {0, 0, 0, 0, 0, 0, 0, 0}
    end

    test "handles IPv4 with partial bytes" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :edns_client_subnet, family: 1, source: 12, scope: 0, addr: <<203, 128>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      # Should mask out bits beyond prefix length
      assert result.options.ecs.client_subnet == {203, 128, 0, 0}
    end

    test "handles unknown address family" do
      additional = [
        %{
          type: :opt,
          rdata: [
            %{code: :edns_client_subnet, family: 99, source: 16, scope: 0, 
              addr: <<1, 2, 3, 4>>}
          ]
        }
      ]
      
      result = DNSpacket.parse_edns_info(additional)
      assert result.options.ecs.client_subnet == <<1, 2, 3, 4>>
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
      assert parsed.edns_info.options == %{}
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
        options: %{
          ecs: %{
            family: 1,
            client_subnet: {192, 168, 1, 0},
            source_prefix: 24,
            scope_prefix: 0
          }
        }
      }
      
      opt_record = DNSpacket.create_edns_info_record(edns_info)
      
      assert opt_record.type == :opt
      assert opt_record.payload_size == 4096
      assert opt_record.dnssec == 1
      assert length(opt_record.rdata) == 1
      
      ecs_option = hd(opt_record.rdata)
      assert ecs_option.code == :edns_client_subnet
      assert ecs_option.family == 1
      assert ecs_option.source == 24
      assert ecs_option.scope == 0
      assert ecs_option.addr == <<192, 168, 1>>
    end

    test "creates OPT record with multiple options" do
      edns_info = %{
        payload_size: 1232,
        options: %{
          ecs: %{family: 1, client_subnet: {10, 0, 0, 0}, source_prefix: 8, scope_prefix: 0},
          cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil},
          nsid: "server1"
        }
      }
      
      opt_record = DNSpacket.create_edns_info_record(edns_info)
      
      assert length(opt_record.rdata) == 3
      
      # Verify each option is present
      codes = Enum.map(opt_record.rdata, & &1.code)
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
          options: %{
            ecs: %{
              family: 1,
              client_subnet: {203, 0, 113, 0},
              source_prefix: 24,
              scope_prefix: 0
            }
          }
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
      assert parsed_packet.edns_info.options.ecs.family == 1
      assert parsed_packet.edns_info.options.ecs.client_subnet == {203, 0, 113, 0}
      assert parsed_packet.edns_info.options.ecs.source_prefix == 24
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
          options: %{
            ecs: %{
              family: 2,
              client_subnet: {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0},
              source_prefix: 48,
              scope_prefix: 0
            },
            cookie: %{
              client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
              server: <<9, 10, 11, 12, 13, 14, 15, 16>>
            },
            nsid: "ns1.example.com"
          }
        }
      }
      
      binary = DNSpacket.create(original_packet)
      parsed_packet = DNSpacket.parse(binary)
      
      # Verify EDNS options are preserved
      edns = parsed_packet.edns_info
      assert edns.options.ecs.family == 2
      assert edns.options.ecs.client_subnet == {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0}
      assert edns.options.ecs.source_prefix == 48
      
      assert edns.options.cookie.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert edns.options.cookie.server == <<9, 10, 11, 12, 13, 14, 15, 16>>
      
      assert edns.options.nsid == "ns1.example.com"
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
          options: %{
            nsid: "new-server"
          }
        }
      }
      
      binary = DNSpacket.create(packet)
      parsed_packet = DNSpacket.parse(binary)
      
      # Should have exactly one OPT record with new settings
      opt_records = Enum.filter(parsed_packet.additional, &(&1.type == :opt))
      assert length(opt_records) == 1
      
      assert parsed_packet.edns_info.payload_size == 4096
      assert parsed_packet.edns_info.dnssec == 1
      assert parsed_packet.edns_info.options.nsid == "new-server"
      
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
        options: %{
          ecs: %{family: 1, client_subnet: {10, 0, 0, 0}, source_prefix: 8, scope_prefix: 0}
        }
      }
      
      opt_record = DNSpacket.create_edns_info_record(edns_info)
      ecs_option = hd(opt_record.rdata)
      assert ecs_option.addr == <<10>>
      
      # Test /16 prefix (2 bytes)
      edns_info2 = %{
        options: %{
          ecs: %{family: 1, client_subnet: {192, 168, 0, 0}, source_prefix: 16, scope_prefix: 0}
        }
      }
      
      opt_record2 = DNSpacket.create_edns_info_record(edns_info2)
      ecs_option2 = hd(opt_record2.rdata)
      assert ecs_option2.addr == <<192, 168>>
      
      # Test /24 prefix (3 bytes)
      edns_info3 = %{
        options: %{
          ecs: %{family: 1, client_subnet: {203, 0, 113, 0}, source_prefix: 24, scope_prefix: 0}
        }
      }
      
      opt_record3 = DNSpacket.create_edns_info_record(edns_info3)
      ecs_option3 = hd(opt_record3.rdata)
      assert ecs_option3.addr == <<203, 0, 113>>
    end

    test "IPv6 address with various prefix lengths" do
      # Test /32 prefix (4 bytes)
      edns_info = %{
        options: %{
          ecs: %{family: 2, client_subnet: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 0}, source_prefix: 32, scope_prefix: 0}
        }
      }
      
      opt_record = DNSpacket.create_edns_info_record(edns_info)
      ecs_option = hd(opt_record.rdata)
      assert ecs_option.addr == <<0x20, 0x01, 0x0d, 0xb8>>
      
      # Test /48 prefix (6 bytes)
      edns_info2 = %{
        options: %{
          ecs: %{family: 2, client_subnet: {0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0}, source_prefix: 48, scope_prefix: 0}
        }
      }
      
      opt_record2 = DNSpacket.create_edns_info_record(edns_info2)
      ecs_option2 = hd(opt_record2.rdata)
      assert ecs_option2.addr == <<0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34>>
    end
  end
end
