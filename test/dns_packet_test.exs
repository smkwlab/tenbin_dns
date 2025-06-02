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
        serial: 2023010101,
        refresh: 7200,
        retry: 3600,
        expire: 604800,
        minimum: 86400
      }
      result = DNSpacket.create_rdata(rdata, :soa, :in)
      
      expected = <<3, "ns1", 7, "example", 3, "com">> <>
                <<5, "admin", 7, "example", 3, "com">> <>
                <<2023010101::32, 7200::32, 3600::32, 604800::32, 86400::32>>
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
                   <<2023010101::32, 7200::32, 3600::32, 604800::32, 86400::32>>
      orig_body = <<0::96>> <> soa_binary
      
      result = DNSpacket.parse_rdata(soa_binary, :soa, :in, orig_body)
      assert result.mname == "ns1.example.com."
      assert result.rname == "admin.example.com."
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
end