defmodule ParseComparison do
  @moduledoc """
  Comparison benchmark for parse function optimizations
  
  Run with: mix run bench/parse_comparison.exs
  """

  def run_comparison do
    # Create various test packets
    simple_packet = %DNSpacket{
      id: 0x1234,
      qr: 0,
      opcode: 0,
      rd: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
    }
    
    complex_packet = %DNSpacket{
      id: 0x5678,
      qr: 1,
      aa: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :a, class: :in, ttl: 300, 
          rdata: %{addr: {192, 168, 1, 1}}},
        %{name: "example.com.", type: :a, class: :in, ttl: 300,
          rdata: %{addr: {192, 168, 1, 2}}},
        %{name: "example.com.", type: :mx, class: :in, ttl: 3600,
          rdata: %{preference: 10, name: "mail.example.com."}},
      ],
      authority: [
        %{name: "example.com.", type: :ns, class: :in, ttl: 86400,
          rdata: %{name: "ns1.example.com."}},
      ],
      additional: [
        %{name: "ns1.example.com.", type: :a, class: :in, ttl: 86400,
          rdata: %{addr: {192, 168, 1, 10}}},
      ]
    }
    
    # Long domain name packet
    long_domain_packet = %DNSpacket{
      id: 0x9999,
      qr: 0,
      question: [%{qname: "very.long.subdomain.with.many.labels.example.com.", qtype: :a, qclass: :in}]
    }
    
    # Pre-create binaries
    simple_binary = DNSpacket.create(simple_packet)
    complex_binary = DNSpacket.create(complex_packet)
    long_domain_binary = DNSpacket.create(long_domain_packet)
    
    IO.puts("Parse Performance Comparison")
    IO.puts("===========================")
    IO.puts("Optimizations applied:")
    IO.puts("- Cached DNS.type/class lookups to avoid double calls")
    IO.puts("- Optimized parse_name with iolist accumulator")
    IO.puts("- Added list reversal for correct ordering")
    IO.puts("- Inlined critical functions")
    IO.puts("")
    
    Benchee.run(%{
      "parse simple query" => fn -> DNSpacket.parse(simple_binary) end,
      "parse complex response" => fn -> DNSpacket.parse(complex_binary) end,
      "parse long domain name" => fn -> DNSpacket.parse(long_domain_binary) end,
      
    },
    time: 3,
    memory_time: 2,
    formatters: [Benchee.Formatters.Console])
    
    IO.puts("\nExpected improvements:")
    IO.puts("- Reduced function calls through caching")
    IO.puts("- Better memory usage with iolist accumulation")
    IO.puts("- Improved parse_name performance for domain names")
  end
end

ParseComparison.run_comparison()