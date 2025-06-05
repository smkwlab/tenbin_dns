defmodule QuickOptimizationComparison do
  @moduledoc """
  Quick performance comparison for EDNS optimization
  """

  # Test packet with EDNS options (Map format - optimized)
  @edns_packet_optimized %DNSpacket{
    id: 0x1234,
    qr: 0,
    opcode: 0,
    rd: 1,
    question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
    additional: [
      %{
        name: "",
        type: :opt,
        payload_size: 1232,
        ex_rcode: 0,
        version: 0,
        dnssec: 0,
        z: 0,
        rdata: %{
          edns_client_subnet: %{
            family: 1,
            client_subnet: {192, 168, 0, 0},
            source_prefix: 24,
            scope_prefix: 0
          },
          cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil},
          nsid: "test-server"
        }
      }
    ]
  }

  # Test packet with EDNS options (legacy keyword list format)
  @edns_packet_legacy %DNSpacket{
    id: 0x1234,
    qr: 0,
    opcode: 0,
    rd: 1,
    question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
    additional: [
      %{
        name: "",
        type: :opt,
        payload_size: 1232,
        ex_rcode: 0,
        version: 0,
        dnssec: 0,
        z: 0,
        rdata: [
          edns_client_subnet: %{
            family: 1,
            client_subnet: {192, 168, 0, 0},
            source_prefix: 24,
            scope_prefix: 0
          },
          cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil},
          nsid: "test-server"
        ]
      }
    ]
  }

  def run_quick_benchmark do
    IO.puts("Quick EDNS Optimization Comparison")
    IO.puts("==================================")
    
    # Create binary packets
    optimized_binary = DNSpacket.create(@edns_packet_optimized)
    
    # Test parse_edns_info performance
    additional_optimized = @edns_packet_optimized.additional
    
    IO.puts("\nTesting parse_edns_info performance...")
    
    # Warm up
    for _ <- 1..1000, do: DNSpacket.parse_edns_info(additional_optimized)
    
    # Benchmark parse_edns_info (current optimized version)
    {time_optimized, _} = :timer.tc(fn ->
      for _ <- 1..100_000, do: DNSpacket.parse_edns_info(additional_optimized)
    end)
    
    time_per_op_optimized = time_optimized / 100_000
    ops_per_sec_optimized = 1_000_000 / time_per_op_optimized
    
    IO.puts("Optimized parse_edns_info:")
    IO.puts("  Time per operation: #{Float.round(time_per_op_optimized, 2)} μs")
    IO.puts("  Operations per second: #{Float.round(ops_per_sec_optimized / 1_000_000, 2)}M ops/sec")
    
    # Test full packet parsing
    IO.puts("\nTesting full packet parsing...")
    
    # Warm up
    for _ <- 1..1000, do: DNSpacket.parse(optimized_binary)
    
    # Benchmark full packet parsing
    {time_parse, _} = :timer.tc(fn ->
      for _ <- 1..50_000, do: DNSpacket.parse(optimized_binary)
    end)
    
    time_per_parse = time_parse / 50_000
    parse_ops_per_sec = 1_000_000 / time_per_parse
    
    IO.puts("Full packet parsing:")
    IO.puts("  Time per operation: #{Float.round(time_per_parse, 2)} μs")
    IO.puts("  Operations per second: #{Float.round(parse_ops_per_sec / 1_000_000, 2)}M ops/sec")
    
    # Test DNS constant lookups
    IO.puts("\nTesting DNS constant lookups...")
    
    {time_dns_type, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000 do
        DNS.type(1)
        DNS.type(28)
        DNS.type(15)
      end
    end)
    
    time_per_dns_lookup = time_dns_type / 3_000_000
    dns_ops_per_sec = 1_000_000 / time_per_dns_lookup
    
    IO.puts("DNS.type/1 lookups:")
    IO.puts("  Time per operation: #{Float.round(time_per_dns_lookup * 1000, 2)} ns")
    IO.puts("  Operations per second: #{Float.round(dns_ops_per_sec / 1_000_000, 2)}M ops/sec")
    
    # parse_opt_rr test skipped due to binary format complexity
    
    %{
      parse_edns_info: %{
        time_us: Float.round(time_per_op_optimized, 2),
        ops_per_sec: Float.round(ops_per_sec_optimized / 1_000_000, 2)
      },
      full_packet_parse: %{
        time_us: Float.round(time_per_parse, 2),
        ops_per_sec: Float.round(parse_ops_per_sec / 1_000_000, 2)
      },
      dns_type_lookup: %{
        time_ns: Float.round(time_per_dns_lookup * 1000, 2),
        ops_per_sec: Float.round(dns_ops_per_sec / 1_000_000, 2)
      }
    }
  end
end

results = QuickOptimizationComparison.run_quick_benchmark()
IO.puts("\nResults Summary:")
IO.inspect(results, pretty: true)