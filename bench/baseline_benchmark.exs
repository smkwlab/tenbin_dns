defmodule BaselineBenchmark do
  @moduledoc """
  Baseline performance measurement before optimizations
  """

  # Test packet with EDNS options (legacy format)
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
          %{code: :edns_client_subnet, family: 1, source: 24, scope: 0, addr: <<192, 168, 0>>},
          %{code: :cookie, cookie: <<1, 2, 3, 4, 5, 6, 7, 8>>},
          %{code: :nsid, data: "test-server"}
        ]
      }
    ]
  }

  def run_baseline_benchmark do
    IO.puts("Baseline Performance Measurement (Before Optimizations)")
    IO.puts("======================================================")
    
    # Create binary packet
    legacy_binary = DNSpacket.create(@edns_packet_legacy)
    
    # Test parse_edns_info performance
    additional_legacy = @edns_packet_legacy.additional
    
    IO.puts("\nTesting parse_edns_info performance...")
    
    # Warm up
    for _ <- 1..1000, do: DNSpacket.parse_edns_info(additional_legacy)
    
    # Benchmark parse_edns_info (legacy version)
    {time_legacy, _} = :timer.tc(fn ->
      for _ <- 1..100_000, do: DNSpacket.parse_edns_info(additional_legacy)
    end)
    
    time_per_op_legacy = time_legacy / 100_000
    ops_per_sec_legacy = 1_000_000 / time_per_op_legacy
    
    IO.puts("Legacy parse_edns_info:")
    IO.puts("  Time per operation: #{Float.round(time_per_op_legacy, 2)} μs")
    IO.puts("  Operations per second: #{Float.round(ops_per_sec_legacy / 1_000_000, 2)}M ops/sec")
    
    # Test full packet parsing
    IO.puts("\nTesting full packet parsing...")
    
    # Warm up
    for _ <- 1..1000, do: DNSpacket.parse(legacy_binary)
    
    # Benchmark full packet parsing
    {time_parse, _} = :timer.tc(fn ->
      for _ <- 1..50_000, do: DNSpacket.parse(legacy_binary)
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
    
    # parse_opt_rr test skipped in baseline due to binary format differences
    
    %{
      parse_edns_info: %{
        time_us: Float.round(time_per_op_legacy, 2),
        ops_per_sec: Float.round(ops_per_sec_legacy / 1_000_000, 2)
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

results = BaselineBenchmark.run_baseline_benchmark()
IO.puts("\nBaseline Results Summary:")
IO.inspect(results, pretty: true)