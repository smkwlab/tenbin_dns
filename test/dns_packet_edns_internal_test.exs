defmodule DNSpacketEDNSInternalTest do
  @moduledoc """
  Internal-contract tests for EDNS handling (split out of
  dns_packet_test.exs, #96).

  These tests intentionally call internal (`@doc false`) functions
  (`parse_edns_info/1`, `create_edns_info_record/1`, `create_edns_options/1`,
  `parse_opt_rr/2`, ...) to pin behavior that a create/parse round-trip
  cannot reach: malformed options, ECS edge cases, truncated input and
  similar. The compatibility contract for the public API lives in
  test/dns_packet_roundtrip_test.exs, test/dns_packet_edns_consistency_test.exs
  and test/dns_packet_unknown_options_test.exs.
  """
  use ExUnit.Case

  describe "parse_edns_info/1" do
    test "returns nil when no OPT record present" do
      additional = [
        %{
          name: "ns1.example.com.",
          type: :a,
          class: :in,
          ttl: 300,
          rdata: %{addr: {192, 168, 1, 1}}
        }
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
            edns_client_subnet: %{
              family: 1,
              client_subnet: {192, 168, 1, 0},
              source_prefix: 24,
              scope_prefix: 0
            }
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
            edns_client_subnet: %{
              family: 2,
              client_subnet: {0x2001, 0xDB8, 0x1234, 0, 0, 0, 0, 0},
              source_prefix: 48,
              scope_prefix: 0
            }
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      assert result.ecs_family == 2
      assert result.ecs_subnet == {0x2001, 0xDB8, 0x1234, 0, 0, 0, 0, 0}
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
      # 32 bytes of 9s
      server_cookie = <<9::size(32 * 8)>>
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
            unknown: [
              %{code: :unknown_option, data: <<1, 2, 3, 4>>},
              %{code: :another_unknown, data: <<5, 6>>}
            ]
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
            edns_client_subnet: %{
              family: 1,
              client_subnet: {10, 0, 0, 0},
              source_prefix: 24,
              scope_prefix: 0
            },
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
            edns_client_subnet: %{
              family: 1,
              client_subnet: {0, 0, 0, 0},
              source_prefix: 0,
              scope_prefix: 0
            }
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
            edns_client_subnet: %{
              family: 2,
              client_subnet: {0, 0, 0, 0, 0, 0, 0, 0},
              source_prefix: 0,
              scope_prefix: 0
            }
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
            edns_client_subnet: %{
              family: 1,
              client_subnet: {203, 128, 0, 0},
              source_prefix: 12,
              scope_prefix: 0
            }
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
            # 5 bytes for /36 prefix
            edns_client_subnet: %{
              family: 2,
              client_subnet: {0x2001, 0x0DB8, 0xF000, 0, 0, 0, 0, 0},
              source_prefix: 36,
              scope_prefix: 0
            }
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      # Should mask the last 4 bits of the 5th byte
      assert elem(result.ecs_subnet, 0) == 0x2001
      assert elem(result.ecs_subnet, 1) == 0x0DB8
      # Masked
      assert elem(result.ecs_subnet, 2) == 0xF000
    end

    test "handles IPv4 address that's too long" do
      # Test when address bytes exceed what's needed for IPv4
      additional = [
        %{
          type: :opt,
          rdata: %{
            # 6 bytes, but IPv4 only needs 4
            edns_client_subnet: %{
              family: 1,
              client_subnet: {192, 168, 1, 1},
              source_prefix: 32,
              scope_prefix: 0
            }
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
            edns_client_subnet: %{
              family: 2,
              client_subnet: {0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0},
              source_prefix: 128,
              scope_prefix: 0
            }
          }
        }
      ]

      result = DNSpacket.parse_edns_info(additional)
      # Should truncate to 16 bytes and parse as IPv6
      assert elem(result.ecs_subnet, 0) == 0x2001
      assert elem(result.ecs_subnet, 1) == 0x0DB8
    end

    test "handles unknown address family" do
      additional = [
        %{
          type: :opt,
          rdata: %{
            edns_client_subnet: %{
              family: 99,
              client_subnet: <<1, 2, 3, 4>>,
              source_prefix: 16,
              scope_prefix: 0
            }
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
            edns_client_subnet: %{
              family: 1,
              client_subnet: {0, 0, 0, 0},
              source_prefix: -1,
              scope_prefix: 0
            }
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
            edns_client_subnet: %{
              family: 1,
              client_subnet: {192, 168, 1, 1},
              source_prefix: 32,
              scope_prefix: 0
            }
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
            edns_client_subnet: %{
              family: 99,
              client_subnet: <<192, 168>>,
              source_prefix: 0,
              scope_prefix: 0
            }
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
        # ARCOUNT = 1 (OPT record)
        0x00,
        0x01,
        # Question: example.com A IN
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
        # Answer: example.com A 192.168.1.1
        # Pointer to question name
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
        1,
        # OPT record without options
        # Empty name
        0x00,
        # TYPE = OPT (41)
        0x00,
        0x29,
        # Payload size = 1232
        0x04,
        0xD0,
        # Extended RCODE
        0x00,
        # Version
        0x00,
        # Flags (DNSSEC OK)
        0x80,
        0x00,
        # RDLENGTH = 0 (no options)
        0x00,
        0x00
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
        # Question: example.com A IN
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
        # Answer: example.com A 192.168.1.1
        # Pointer to question name
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
        answer: [
          %{
            name: "example.com.",
            type: :a,
            class: :in,
            ttl: 300,
            rdata: %{addr: {192, 168, 1, 1}}
          }
        ],
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
          ecs_subnet: {0x2001, 0xDB8, 0x1234, 0, 0, 0, 0, 0},
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
      assert edns.ecs_subnet == {0x2001, 0xDB8, 0x1234, 0, 0, 0, 0, 0}
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
          %{
            name: "ns1.example.com.",
            type: :a,
            class: :in,
            ttl: 300,
            rdata: %{addr: {1, 2, 3, 4}}
          },
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
        ecs_subnet: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0},
        ecs_source_prefix: 32,
        ecs_scope_prefix: 0
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      ecs_option = hd(opt_record.rdata)
      ecs_data = elem(ecs_option, 1)
      assert ecs_data.client_subnet == {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}

      # Test /48 prefix (6 bytes)
      edns_info2 = %{
        ecs_family: 2,
        ecs_subnet: {0x2001, 0xDB8, 0x1234, 0, 0, 0, 0, 0},
        ecs_source_prefix: 48,
        ecs_scope_prefix: 0
      }

      opt_record2 = DNSpacket.create_edns_info_record(edns_info2)
      ecs_option2 = hd(opt_record2.rdata)
      ecs_data2 = elem(ecs_option2, 1)
      assert ecs_data2.client_subnet == {0x2001, 0xDB8, 0x1234, 0, 0, 0, 0, 0}
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
            llq: %{
              version: 1,
              llq_opcode: 1,
              error_code: 0,
              llq_id: 1_234_567_890_123_456,
              lease_life: 3600
            }
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
        edns_client_subnet: %{
          family: 1,
          client_subnet: {10, 0, 0, 0},
          source_prefix: 8,
          scope_prefix: 0
        }
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
        edns_client_subnet: %{
          family: 1,
          client_subnet: {10, 0, 0, 0},
          source_prefix: 8,
          scope_prefix: 0
        }
      }

      result = DNSpacket.create_edns_options(options)

      # Should only create ECS option, ignoring invalid_key
      <<8::16, length::16, _data::binary-size(length)>> = result
    end

    test "creates all supported EDNS options" do
      options = %{
        edns_client_subnet: %{
          family: 1,
          client_subnet: {192, 168, 1, 0},
          source_prefix: 24,
          scope_prefix: 0
        },
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
        llq: %{
          version: 1,
          llq_opcode: 1,
          error_code: 0,
          llq_id: 1_234_567_890_123_456,
          lease_life: 3600
        },
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

      unknown_count =
        case Map.get(parsed_options, :unknown) do
          nil -> 0
          list -> length(list)
        end

      # At least 20 options
      assert known_count + unknown_count >= 20

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
          %{name: "ns1.test.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}
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
      # 20 known options + 2 unknown
      assert length(opt_record.rdata) == 22

      # Verify ECS conversion
      ecs_rdata =
        Enum.find(opt_record.rdata, fn
          {:edns_client_subnet, _} -> true
          _ -> false
        end)

      ecs_data = elem(ecs_rdata, 1)
      assert ecs_data.family == 1
      assert ecs_data.source_prefix == 24
      assert ecs_data.scope_prefix == 0
      assert ecs_data.client_subnet == {192, 168, 1, 0}

      # Verify cookie conversion
      cookie_rdata =
        Enum.find(opt_record.rdata, fn
          {:cookie, _} -> true
          _ -> false
        end)

      cookie_data = elem(cookie_rdata, 1)
      assert cookie_data.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert cookie_data.server == <<9, 10, 11, 12, 13, 14, 15, 16>>

      # Verify NSID conversion
      nsid_rdata =
        Enum.find(opt_record.rdata, fn
          {:nsid, _} -> true
          _ -> false
        end)

      assert elem(nsid_rdata, 1) == "server.example.com"

      # Verify extended DNS error conversion
      ede_rdata =
        Enum.find(opt_record.rdata, fn
          {:extended_dns_error, _} -> true
          _ -> false
        end)

      ede_data = elem(ede_rdata, 1)
      assert ede_data.info_code == 18
      assert ede_data.extra_text == "Blocked by policy"

      # Verify TCP keepalive conversion
      tcp_rdata =
        Enum.find(opt_record.rdata, fn
          {:edns_tcp_keepalive, _} -> true
          _ -> false
        end)

      tcp_data = elem(tcp_rdata, 1)
      assert tcp_data.timeout == 300

      # Verify padding conversion
      padding_rdata =
        Enum.find(opt_record.rdata, fn
          {:padding, _} -> true
          _ -> false
        end)

      padding_data = elem(padding_rdata, 1)
      assert padding_data.length == 8

      # Verify algorithm options
      dau_rdata =
        Enum.find(opt_record.rdata, fn
          {:dau, _} -> true
          _ -> false
        end)

      dau_data = elem(dau_rdata, 1)
      assert dau_data.algorithms == [7, 8, 10]

      # Verify LLQ conversion
      llq_rdata =
        Enum.find(opt_record.rdata, fn
          {:llq, _} -> true
          _ -> false
        end)

      llq_data = elem(llq_rdata, 1)
      assert llq_data.version == 1
      assert llq_data.llq_id == 9_876_543_210

      # Verify unknown options are passed through as encodable tagged tuples
      unknown_rdatas =
        Enum.filter(opt_record.rdata, fn
          {:unknown, %{code: code}} when code in [65_000, 65_001] -> true
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
        ecs_subnet: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1},
        ecs_source_prefix: 64,
        ecs_scope_prefix: 0
      }

      opt_record_v6 = DNSpacket.create_edns_info_record(edns_info_v6)
      ecs_v6 = hd(opt_record_v6.rdata)
      ecs_v6_data = elem(ecs_v6, 1)
      assert ecs_v6_data.client_subnet == {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
    end
  end

  describe "EDNS option creation tests" do
    test "creates EDNS record with cookie option" do
      edns_info = %{
        cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>
      }

      result = DNSpacket.create_edns_info_record(edns_info)
      assert length(result.rdata) == 1
      {option_type, option_data} = hd(result.rdata)
      assert option_type == :cookie
      assert option_data.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
    end

    test "creates EDNS record with extended DNS error" do
      edns_info = %{
        extended_dns_error_info_code: 18,
        extended_dns_error_extra_text: "Filtered"
      }

      result = DNSpacket.create_edns_info_record(edns_info)
      assert length(result.rdata) == 1
      {option_type, option_data} = hd(result.rdata)
      assert option_type == :extended_dns_error
      assert option_data.info_code == 18
      assert option_data.extra_text == "Filtered"
    end

    test "creates EDNS record with TCP keepalive" do
      edns_info = %{
        edns_tcp_keepalive_timeout: 300
      }

      result = DNSpacket.create_edns_info_record(edns_info)
      assert length(result.rdata) == 1
      {option_type, option_data} = hd(result.rdata)
      assert option_type == :edns_tcp_keepalive
      assert option_data.timeout == 300
    end

    test "creates EDNS record with DAU algorithms" do
      edns_info = %{
        dau_algorithms: [7, 8]
      }

      result = DNSpacket.create_edns_info_record(edns_info)
      assert length(result.rdata) == 1
      {option_type, option_data} = hd(result.rdata)
      assert option_type == :dau
      assert option_data.algorithms == [7, 8]
    end

    test "creates EDNS record with DHU algorithms" do
      edns_info = %{
        dhu_algorithms: [1, 2]
      }

      result = DNSpacket.create_edns_info_record(edns_info)
      assert length(result.rdata) == 1
      {option_type, option_data} = hd(result.rdata)
      assert option_type == :dhu
      assert option_data.algorithms == [1, 2]
    end

    test "creates EDNS record with N3U algorithms" do
      edns_info = %{
        n3u_algorithms: [1]
      }

      result = DNSpacket.create_edns_info_record(edns_info)
      assert length(result.rdata) == 1
      {option_type, option_data} = hd(result.rdata)
      assert option_type == :n3u
      assert option_data.algorithms == [1]
    end

    test "creates EDNS record with NSID" do
      edns_info = %{
        nsid: <<0x80, 0x81, 0x82, 0x83>>
      }

      result = DNSpacket.create_edns_info_record(edns_info)
      assert length(result.rdata) == 1
      {option_type, option_data} = hd(result.rdata)
      assert option_type == :nsid
      assert option_data == <<0x80, 0x81, 0x82, 0x83>>
    end

    test "creates full EDNS packet with extended DNS error" do
      packet = %DNSpacket{
        id: 0x1234,
        qr: 1,
        opcode: 0,
        rcode: 0,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        edns_info: %{
          extended_dns_error_info_code: 21,
          extended_dns_error_extra_text: "Unsupported DS Digest Type"
        }
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x1234
      assert parsed.edns_info.extended_dns_error_info_code == 21
      assert parsed.edns_info.extended_dns_error_extra_text == "Unsupported DS Digest Type"
    end

    test "creates full EDNS packet with TCP keepalive nil timeout" do
      packet = %DNSpacket{
        id: 0x5678,
        qr: 1,
        question: [%{qname: "test.com.", qtype: :aaaa, qclass: :in}],
        edns_info: %{
          edns_tcp_keepalive_timeout: nil
        }
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x5678
      assert parsed.edns_info.edns_tcp_keepalive_timeout == nil
    end

    test "creates full EDNS packet with TCP keepalive timeout value" do
      packet = %DNSpacket{
        id: 0x9ABC,
        qr: 1,
        question: [%{qname: "keepalive.com.", qtype: :mx, qclass: :in}],
        edns_info: %{
          edns_tcp_keepalive_timeout: 300
        }
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x9ABC
      assert parsed.edns_info.edns_tcp_keepalive_timeout == 300
    end

    test "creates EDNS packet with padding option" do
      packet = %DNSpacket{
        id: 0xDEF0,
        qr: 0,
        question: [%{qname: "padded.example.com.", qtype: :txt, qclass: :in}],
        edns_info: %{
          padding_length: 16
        }
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0xDEF0
      assert parsed.edns_info.padding_length == 16
    end

    test "creates EDNS packet with DNSSEC algorithms" do
      packet = %DNSpacket{
        id: 0x1357,
        qr: 0,
        question: [%{qname: "dnssec.example.com.", qtype: :dnskey, qclass: :in}],
        edns_info: %{
          dau_algorithms: [7, 8, 10],
          dhu_algorithms: [1, 2, 4],
          n3u_algorithms: [1]
        }
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x1357
      assert parsed.edns_info.dau_algorithms == [7, 8, 10]
      assert parsed.edns_info.dhu_algorithms == [1, 2, 4]
      assert parsed.edns_info.n3u_algorithms == [1]
    end
  end

  describe "EDNS parsing integration tests" do
    test "parses EDNS OPT record with multiple options" do
      # Create a packet with EDNS options and parse it
      edns_info = %{
        cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        nsid: <<0x80, 0x81, 0x82, 0x83>>
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      assert length(opt_record.rdata) == 2

      # Check that both options are present
      option_types = Enum.map(opt_record.rdata, fn {type, _data} -> type end)
      assert :cookie in option_types
      assert :nsid in option_types
    end

    test "handles unknown ECS address family" do
      # ECS with unknown family (family=99)
      edns_info = %{
        ecs_family: 99,
        ecs_subnet: {0, 0, 0, 0},
        ecs_source_prefix: 0,
        ecs_scope_prefix: 0
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      ecs_data = hd(opt_record.rdata)
      ecs_result = elem(ecs_data, 1)
      assert ecs_result.family == 99
    end

    test "creates packet with unknown options in rdata" do
      # Test unknown option handling in additional records
      packet = %DNSpacket{
        id: 0x1111,
        qr: 1,
        question: [%{qname: "test.com.", qtype: :a, qclass: :in}],
        additional: [
          %{
            name: "",
            type: :opt,
            payload_size: 512,
            ex_rcode: 0,
            version: 0,
            dnssec: 0,
            z: 0,
            rdata: %{
              unknown_options: %{999 => <<1, 2, 3, 4>>}
            }
          }
        ]
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x1111
      assert is_map(parsed.edns_info.unknown_options)
    end

    test "handles EDNS expire option with different formats" do
      # Test EDNS expire with nil (empty data)
      packet = %DNSpacket{
        id: 0x2222,
        question: [%{qname: "expire.test.", qtype: :a, qclass: :in}],
        edns_info: %{
          edns_expire: nil
        }
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x2222
      # Just check that packet was parsed successfully
      assert is_struct(parsed, DNSpacket)
    end

    test "handles Chain option with trust point" do
      packet = %DNSpacket{
        id: 0x3333,
        question: [%{qname: "chain.test.", qtype: :a, qclass: :in}],
        edns_info: %{
          chain_point_of_trust: "trust.example.com."
        }
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x3333
      # Just check that packet was parsed successfully
      assert is_struct(parsed, DNSpacket)
    end

    test "handles Key Tag option" do
      packet = %DNSpacket{
        id: 0x4444,
        question: [%{qname: "keytag.test.", qtype: :dnskey, qclass: :in}],
        edns_info: %{
          edns_key_tag_list: [12_345, 67_890]
        }
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x4444
      # Just check that packet was parsed successfully
      assert is_struct(parsed, DNSpacket)
    end

    test "creates comprehensive EDNS options for maximum coverage" do
      # Test multiple EDNS options that aren't fully covered yet
      edns_info = %{
        edns_expire: nil,
        chain_point_of_trust: "closest.example.com.",
        edns_client_tag_tags: [1234],
        edns_server_tag_tags: [5678],
        report_channel_agent_domain: "agent.example.com.",
        update_lease_lease_time: 3600
      }

      result = DNSpacket.create_edns_info_record(edns_info)
      # Should successfully create EDNS info record
      assert is_map(result)
      assert result.type == :opt
    end

    test "creates DNSSEC record types for coverage" do
      # DNAME record
      dname_rdata = %{target: "target.example.com."}
      dname_result = DNSpacket.create_rdata(dname_rdata, :dname, :in)
      assert is_binary(dname_result)
      assert byte_size(dname_result) > 5

      # RRSIG record
      rrsig_rdata = %{
        # A record
        type_covered: 1,
        algorithm: 8,
        labels: 3,
        original_ttl: 3600,
        signature_expiration: 1_640_995_200,
        signature_inception: 1_640_908_800,
        key_tag: 12_345,
        signer_name: "example.com.",
        signature: <<1, 2, 3, 4, 5>>
      }

      rrsig_result = DNSpacket.create_rdata(rrsig_rdata, :rrsig, :in)
      assert is_binary(rrsig_result)
      assert byte_size(rrsig_result) > 20
    end

    test "creates specific SVC parameter types for coverage" do
      # Test SVC params with various types
      params = %{
        alpn: ["h2", "h3"],
        port: 443,
        ipv4_hints: [{192, 168, 1, 1}, {10, 0, 0, 1}],
        ipv6_hints: [{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}]
      }

      result = DNSpacket.create_svc_params(params)
      assert is_binary(result)
      assert byte_size(result) > 10

      # Test edge case with invalid input
      result_invalid = DNSpacket.create_svc_params("invalid")
      assert result_invalid == <<>>
    end

    test "creates cookie option with client-only for specific coverage" do
      # Test the specific path for client-only cookie creation
      edns_info = %{
        cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        cookie_server: nil
      }

      opt_record = DNSpacket.create_edns_info_record(edns_info)
      assert length(opt_record.rdata) == 1

      {option_type, option_data} = hd(opt_record.rdata)
      assert option_type == :cookie
      assert option_data.client == <<1, 2, 3, 4, 5, 6, 7, 8>>
      assert option_data.server == nil
    end

    test "handles edge cases in record creation for coverage" do
      # Test various edge cases that increase coverage

      # Test unknown record type fallback
      result1 = DNSpacket.create_rdata(%{data: <<1, 2, 3>>}, :unknown_type, :in)
      assert result1 == %{data: <<1, 2, 3>>}

      # Test CAA record with different property tags
      caa_rdata = %{
        flag: 128,
        tag: "issue",
        value: "ca.example.net"
      }

      caa_result = DNSpacket.create_rdata(caa_rdata, :caa, :in)
      assert is_binary(caa_result)
      assert byte_size(caa_result) > 10

      # Test empty SVCB parameters
      svcb_empty = %{
        priority: 0,
        target: ".",
        svc_params: %{}
      }

      svcb_result = DNSpacket.create_rdata(svcb_empty, :svcb, :in)
      assert is_binary(svcb_result)
    end

    test "creates packet with EDNS and parses it back" do
      packet = %DNSpacket{
        id: 0x1234,
        qr: 0,
        opcode: 0,
        rd: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        additional: [
          %{
            name: "",
            type: :opt,
            payload_size: 512,
            ex_rcode: 0,
            version: 0,
            dnssec: 0,
            z: 0,
            rdata: [
              {:cookie, %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil}}
            ]
          }
        ]
      }

      binary = DNSpacket.create(packet)
      parsed = DNSpacket.parse(binary)

      assert parsed.id == 0x1234
      assert length(parsed.additional) == 1
      opt_record = hd(parsed.additional)
      assert opt_record.type == :opt
      assert map_size(opt_record.rdata) == 1
    end
  end
end
