defmodule Tenbin.DNS do
  @external_resource "mix.exs"
  @version Mix.Project.config()[:version]

  @moduledoc """
  DNS packet parsing and creation library for Elixir.

  Tenbin.DNS provides fast and reliable DNS protocol operations with support for
  standard DNS records and EDNS0 extensions. It features a revolutionary hybrid
  structure for EDNS information that provides significant performance improvements
  and better developer experience.

  ## Features

  - **Optimized**: Binary pattern matching with compile-time optimizations
  - **EDNS Hybrid Structure**: 35-69% faster access to common EDNS options
  - **DNS Support**: 19+ record types including A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA, SRV, NAPTR, DNAME, DNSKEY, DS, RRSIG, NSEC, SVCB, HTTPS
  - **EDNS0 Extensions**: Support for EDNS options with industry-standard naming
  - **Unknown Option Handling**: Graceful handling of unknown DNS types and EDNS options

  ## Quick Start

      # Parse a DNS packet
      packet = DNSpacket.parse(dns_binary_data)

      # Access EDNS information with simple syntax
      if packet.edns_info do
        family = packet.edns_info.ecs_family
        subnet = packet.edns_info.ecs_subnet
        nsid = packet.edns_info.nsid
      end

      # Create a DNS packet with A record
      packet = %DNSpacket{
        id: 12345,
        qr: 1,
        question: [%{qname: "example.com", qtype: :a, qclass: :in}],
        answer: [%{name: "example.com", type: :a, class: :in, ttl: 300, 
                   rdata: %{addr: {192, 0, 2, 1}}}]
      }

      binary = DNSpacket.create(packet)

      # Create HTTPS record with Service Parameters
      https_packet = %DNSpacket{
        id: 12346,
        qr: 1,
        question: [%{qname: "example.com", qtype: :https, qclass: :in}],
        answer: [%{name: "example.com", type: :https, class: :in, ttl: 300,
                   rdata: %{priority: 1, target: ".", 
                           svc_params: %{alpn: ["h3", "h2"], port: 443}}}]
      }

      # Create SRV record
      srv_packet = %DNSpacket{
        id: 12347,
        qr: 1,
        question: [%{qname: "_sip._tcp.example.com", qtype: :srv, qclass: :in}],
        answer: [%{name: "_sip._tcp.example.com", type: :srv, class: :in, ttl: 300,
                   rdata: %{priority: 10, weight: 5, port: 5060, target: "sip.example.com"}}]
      }

  ## Core Modules

  - `DNSpacket` - Main DNS packet parsing and creation
  - `DNS` - DNS constants and type/class mappings
  - `Tenbin.DNS` - Main module (this module)

  For detailed information about EDNS hybrid structure and naming conventions,
  see the [EDNS Naming Convention Guide](docs/EDNS_NAMING_CONVENTION.md).
  """

  @doc """
  Returns the current version of Tenbin.DNS.

  ## Examples

      iex> Tenbin.DNS.version()
      #{inspect(@version)}

  """
  def version do
    @version
  end
end
