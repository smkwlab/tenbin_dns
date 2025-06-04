# Tenbin.DNS

A high-performance Elixir library for DNS packet parsing and creation. Tenbin.DNS provides efficient handling of DNS protocol operations with support for standard DNS records, EDNS0, and domain name compression.

## Features

- **Fast DNS packet parsing and creation** - Optimized binary pattern matching
- **Standard DNS record support** - A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA records
- **EDNS0 support** - Including OPT record handling
- **Domain name compression** - Efficient compression and decompression
- **Comprehensive DNS constants** - Types, classes, opcodes, and response codes
- **High test coverage** - Extensive test suite with binary data validation

## Installation

Add `tenbin_dns` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tenbin_dns, "~> 0.4.0"}
  ]
end
```

## Usage

### Creating DNS packets

```elixir
# Create a DNS query packet
packet = %DNSpacket{
  id: 12345,
  rd: 1,
  question: [
    %{qname: "example.com", qtype: DNS.type(:a), qclass: DNS.class(:in)}
  ]
}

# Convert to binary format
binary_packet = DNSpacket.create(packet)
```

### Parsing DNS packets

```elixir
# Parse a binary DNS packet
{:ok, parsed_packet} = DNSpacket.parse(binary_data)

# Access packet fields
IO.puts("Query ID: #{parsed_packet.id}")
IO.puts("Response code: #{DNS.rcode_name(parsed_packet.rcode)}")
```

### Working with DNS constants

```elixir
# Convert between numeric codes and atoms
DNS.type(:a)           # Returns 1
DNS.type_name(1)       # Returns :a
DNS.class(:in)         # Returns 1
DNS.rcode(:noerror)    # Returns 0
```

## Development

```bash
# Install dependencies
mix deps.get

# Run tests
mix test

# Run code analysis
mix credo
mix dialyzer

# Generate documentation
mix docs
```

## Performance

Tenbin.DNS is optimized for high-performance DNS operations:
- Compile-time optimization with native compilation
- Aggressive function inlining for speed-critical paths
- Efficient binary pattern matching for protocol handling
- O(1) constant lookups using compile-time generated maps

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

