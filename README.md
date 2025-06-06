# Tenbin.DNS

An Elixir library for DNS packet parsing and creation. Tenbin.DNS provides handling of DNS protocol operations with support for 19+ DNS record types, DNSSEC, web optimization features, and EDNS0 extensions.

## Features

- **DNS packet parsing and creation** - Binary pattern matching with compile-time optimizations
- **DNS record support** - 19+ record types including:
  - **Basic records**: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA
  - **Service discovery**: SRV, NAPTR
  - **DNSSEC support**: DNSKEY, DS, RRSIG, NSEC
  - **Web optimization**: SVCB, HTTPS with Service Parameters (ALPN, IPv4/IPv6 hints)
  - **Delegation**: DNAME
  - **Legacy**: HINFO
- **EDNS0 hybrid structure** - 35-69% faster access to common EDNS options
- **DNSSEC support** - DNS Security Extensions
- **HTTP/3 support** - SVCB/HTTPS records with ALPN parameter support
- **Domain name compression** - Decompression support (parsing compressed names)
- **DNS constants** - Types, classes, opcodes, and response codes
- **Test coverage** - 161 tests with binary data validation

## Installation

Add `tenbin_dns` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tenbin_dns, "~> 0.7.0"}
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
    %{qname: "example.com", qtype: :a, qclass: :in}
  ]
}

# Convert to binary format
binary_packet = DNSpacket.create(packet)
```

### Modern DNS Records

```elixir
# HTTPS record with Service Parameters (HTTP/3 optimization)
https_packet = %DNSpacket{
  id: 12346,
  qr: 1,
  question: [%{qname: "example.com", qtype: :https, qclass: :in}],
  answer: [%{
    name: "example.com", 
    type: :https, 
    class: :in, 
    ttl: 300,
    rdata: %{
      priority: 1, 
      target: ".", 
      svc_params: %{
        alpn: ["h3", "h2"],                           # HTTP/3, HTTP/2 support
        ipv4_hints: [{104, 16, 132, 229}],           # IPv4 optimization hints
        port: 443
      }
    }
  }]
}

# SRV record for service discovery
srv_packet = %DNSpacket{
  id: 12347,
  qr: 1,
  question: [%{qname: "_sip._tcp.example.com", qtype: :srv, qclass: :in}],
  answer: [%{
    name: "_sip._tcp.example.com", 
    type: :srv, 
    class: :in, 
    ttl: 300,
    rdata: %{priority: 10, weight: 5, port: 5060, target: "sip.example.com"}
  }]
}

# DNSSEC records
dnskey_packet = %DNSpacket{
  id: 12348,
  qr: 1,
  answer: [%{
    name: "example.com", 
    type: :dnskey, 
    class: :in, 
    ttl: 3600,
    rdata: %{flags: 257, protocol: 3, algorithm: 8, public_key: <<0x03, 0x01, 0x00, 0x01>>}
  }]
}
```

### Parsing DNS packets

```elixir
# Parse a binary DNS packet
parsed_packet = DNSpacket.parse(binary_data)

# Access packet fields
IO.puts("Query ID: #{parsed_packet.id}")
IO.puts("Response code: #{DNS.rcode(parsed_packet.rcode)}")

# Access HTTPS Service Parameters
if packet.answer do
  Enum.each(packet.answer, fn record ->
    if record.type == :https and record.rdata.svc_params do
      alpn = record.rdata.svc_params[:alpn]
      IO.puts("Supported protocols: #{inspect(alpn)}")
    end
  end)
end
```

### Working with DNS constants

```elixir
# Convert between numeric codes and atoms
DNS.type_code(:a)      # Returns 1
DNS.type(1)            # Returns :a
DNS.type_code(:https)  # Returns 65
DNS.class_code(:in)    # Returns 1
DNS.rcode_code(:noerror) # Returns 0

# New record types
DNS.type_code(:srv)    # Returns 33
DNS.type_code(:dnskey) # Returns 48
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

## Git Hooks

This project uses [Lefthook](https://github.com/evilmartians/lefthook) for Git hooks management to ensure code quality before commits.

### Installation

```bash
# Install Lefthook (if not already installed)
# On macOS with Homebrew:
brew install lefthook

# On other systems:
# See https://github.com/evilmartians/lefthook/blob/master/docs/install.md

# Install hooks in the repository
lefthook install
```

### Pre-commit checks

The following checks run automatically before each commit:
1. **Code formatting** - `mix format` (auto-fixes files)
2. **Tests** - `mix test --cover` (with coverage analysis)
3. **Code quality** - `mix credo --strict`

### Skipping hooks

If you need to skip hooks for an emergency commit:
```bash
LEFTHOOK=0 git commit -m "Emergency fix"
```

## Performance

Tenbin.DNS includes optimizations for DNS operations:
- **Compile-time optimization** with native compilation
- **Function inlining** for speed-critical paths  
- **Binary pattern matching** for protocol handling
- **O(1) constant lookups** using compile-time generated maps
- **EDNS hybrid structure** providing 35-69% faster access to common options
- **Fast paths** for A/AAAA record parsing
- **161 tests** for reliability and performance validation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

