defmodule Tenbin.DNS do
  @moduledoc """
  High-performance DNS packet parsing and creation library for Elixir.

  Tenbin.DNS provides fast and reliable DNS protocol operations with support for
  standard DNS records and EDNS0 extensions. It features a revolutionary hybrid
  structure for EDNS information that provides significant performance improvements
  and better developer experience.

  ## Features

  - **High Performance**: Optimized binary pattern matching with compile-time optimizations
  - **EDNS Hybrid Structure**: 35-69% faster access to common EDNS options
  - **Comprehensive DNS Support**: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA records
  - **EDNS0 Extensions**: Full support for EDNS options with industry-standard naming
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

      # Create a DNS packet
      packet = %DNSpacket{
        id: 12345,
        qr: 1,
        question: [%{qname: "example.com", qtype: :a, qclass: :in}],
        answer: [%{name: "example.com", type: :a, class: :in, ttl: 300, 
                   rdata: %{addr: {192, 0, 2, 1}}}]
      }

      binary = DNSpacket.create(packet)

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
      "0.6.0"

  """
  def version do
    Application.spec(:tenbin_dns, :vsn) |> to_string()
  end
end
