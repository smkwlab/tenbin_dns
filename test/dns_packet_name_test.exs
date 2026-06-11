defmodule DNSpacketNameTest do
  @moduledoc """
  Internal-contract tests for domain-name wire encoding and decompression
  (split out of dns_packet_test.exs, #96).

  Name compression uses crafted binaries against internal helpers and
  parse/1, pinning pointer-following behavior that the create-side never
  produces (create/1 does not compress). See the moduledoc of
  dns_packet_test.exs for the internal-contract charter.
  """
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

  describe "DNS name compression tests" do
    test "parse handles DNS name compression pointers" do
      # Create a packet with name compression
      compressed_packet = <<
        # ID
        0x12,
        0x34,
        # Flags (response)
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
        # Question: example.com
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
        # Answer: pointer to question name
        # Pointer to offset 12 (name compression)
        0xC0,
        0x0C,
        # TYPE = A
        0x00,
        0x01,
        # CLASS = IN
        0x00,
        0x01,
        # TTL = 300
        0x00,
        0x00,
        0x01,
        0x2C,
        # RDLENGTH = 4
        0x00,
        0x04,
        # IP address
        192,
        168,
        1,
        1
      >>

      parsed = DNSpacket.parse(compressed_packet)
      assert parsed.id == 0x1234
      assert hd(parsed.answer).name == "example.com."
      assert hd(parsed.answer).rdata.addr == {192, 168, 1, 1}
    end

    test "parse handles root domain name in empty context" do
      # Test packet with just root domain
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
        # Question: root domain (just null byte)
        # Root domain name
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

    test "parse handles complex name compression with multiple pointers" do
      # Packet with multiple compressed names
      multi_compressed = <<
        # ID
        0x12,
        0x34,
        # Flags
        0x81,
        0x80,
        # QDCOUNT = 1
        0x00,
        0x01,
        # ANCOUNT = 2
        0x00,
        0x02,
        # NSCOUNT = 0
        0x00,
        0x00,
        # ARCOUNT = 0
        0x00,
        0x00,
        # Question: mail.example.com
        0x04,
        "mail",
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
        # Answer 1: mail.example.com (pointer)
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
        1,
        # Answer 2: www.example.com (partial pointer)
        # "www" + pointer to "example.com" part
        0x03,
        "www",
        0xC0,
        0x11,
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
        2
      >>

      parsed = DNSpacket.parse(multi_compressed)
      assert length(parsed.answer) == 2
      # Note: Order might vary, so check both names are present
      names = [Enum.at(parsed.answer, 0).name, Enum.at(parsed.answer, 1).name]
      assert "mail.example.com." in names
      assert "www.example.com." in names
    end
  end
end
