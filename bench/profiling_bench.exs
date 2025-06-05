defmodule ProfilingBench do
  @moduledoc """
  Comprehensive profiling benchmark to identify performance bottlenecks
  """

  # Real-world DNS packet examples for testing
  defp real_dns_packets do
    [
      # A record query response
      create_a_response(),
      # AAAA record query response
      create_aaaa_response(),
      # Complex DNS response with multiple record types
      create_complex_response(),
      # EDNS-enabled response
      create_edns_response()
    ]
  end

  def run_profiling do
    IO.puts("=== DNS Packet Parsing Performance Profiling ===\n")
    
    # 1. Overall parsing performance
    profile_overall_parsing()
    
    # 2. Break down by operation type
    profile_operation_breakdown()
    
    # 3. Memory allocation patterns
    profile_memory_usage()
    
    # 4. Domain name processing
    profile_domain_names()
  end

  defp profile_overall_parsing do
    IO.puts("1. Overall parsing performance:")
    
    # Test with mixed real-world traffic
    packets = real_dns_packets()
    total_time = :timer.tc(fn ->
      for _ <- 1..10_000 do
        packet = Enum.random(packets)
        DNSpacket.parse(packet)
      end
    end) |> elem(0)
    
    ops_per_sec = 10_000 / total_time * 1_000_000
    IO.puts("  Mixed traffic: #{Float.round(ops_per_sec, 0)} ops/sec")
    IO.puts("  Avg per packet: #{Float.round(total_time / 10_000, 1)}μs")
    IO.puts("")
  end

  defp profile_operation_breakdown do
    IO.puts("2. Operation breakdown:")
    
    packets = real_dns_packets()
    packet = Enum.random(packets)
    iterations = 100_000
    
    # Parse entire packet
    {parse_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.parse(packet)
    end)
    
    # Create packet (reverse operation)
    parsed = DNSpacket.parse(packet)
    {create_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(parsed)
    end)
    
    # Domain name operations
    domain = "www.example.com."
    {domain_create_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create_domain_name(domain)
    end)
    
    IO.puts("  Parse packet:    #{parse_time}μs (#{Float.round(iterations / parse_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Create packet:   #{create_time}μs (#{Float.round(iterations / create_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Domain creation: #{domain_create_time}μs (#{Float.round(iterations / domain_create_time * 1_000_000, 0)} ops/sec)")
    
    IO.puts("\n  Relative performance:")
    IO.puts("    Create/Parse ratio: #{Float.round(create_time / parse_time, 2)}x")
    IO.puts("")
  end

  defp profile_memory_usage do
    IO.puts("3. Memory allocation patterns:")
    
    packets = real_dns_packets()
    packet = Enum.random(packets)
    
    # Measure memory for parsing
    :erlang.garbage_collect()
    parse_memory = :erlang.process_info(self(), :memory) |> elem(1)
    for _ <- 1..1000, do: DNSpacket.parse(packet)
    parse_memory_after = :erlang.process_info(self(), :memory) |> elem(1)
    
    :erlang.garbage_collect()
    
    # Measure memory for creation
    parsed = DNSpacket.parse(packet)
    create_memory = :erlang.process_info(self(), :memory) |> elem(1)
    for _ <- 1..1000, do: DNSpacket.create(parsed)
    create_memory_after = :erlang.process_info(self(), :memory) |> elem(1)
    
    IO.puts("  Parse memory delta:  #{parse_memory_after - parse_memory} bytes")
    IO.puts("  Create memory delta: #{create_memory_after - create_memory} bytes")
    IO.puts("")
  end

  defp profile_domain_names do
    IO.puts("4. Domain name processing bottlenecks:")
    
    domain_types = [
      {"Short", "com."},
      {"Medium", "example.com."},
      {"Long", "subdomain.example.com."},
      {"Very long", "very.long.subdomain.with.many.labels.example.com."},
      {"Max label", String.duplicate("a", 63) <> ".example.com."}
    ]
    
    iterations = 50_000
    
    Enum.each(domain_types, fn {type, domain} ->
      # Test domain creation
      {create_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: DNSpacket.create_domain_name(domain)
      end)
      
      # Test character string creation (component operation)
      labels = String.split(domain, ".")
      {char_string_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations do
          Enum.map(labels, &DNSpacket.create_character_string/1)
        end
      end)
      
      IO.puts("  #{type} domain (#{String.length(domain)} chars):")
      IO.puts("    Full creation: #{create_time}μs (#{Float.round(iterations / create_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Char strings:  #{char_string_time}μs (#{Float.round(iterations / char_string_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Overhead:      #{Float.round((create_time - char_string_time) / create_time * 100, 1)}%")
    end)
    IO.puts("")
  end

  # Helper functions to create realistic test packets
  defp create_a_response do
    DNSpacket.create(%DNSpacket{
      id: 0x1234,
      qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}},
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 217, 34}}}
      ]
    })
  end

  defp create_aaaa_response do
    DNSpacket.create(%DNSpacket{
      id: 0x5678,
      qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :aaaa, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :aaaa, class: :in, ttl: 300, 
          rdata: %{addr: {0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946}}}
      ]
    })
  end

  defp create_complex_response do
    DNSpacket.create(%DNSpacket{
      id: 0x9abc,
      qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :any, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}},
        %{name: "example.com.", type: :aaaa, class: :in, ttl: 300, 
          rdata: %{addr: {0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946}}},
        %{name: "example.com.", type: :mx, class: :in, ttl: 300, 
          rdata: %{preference: 10, name: "mail.example.com."}},
        %{name: "example.com.", type: :txt, class: :in, ttl: 300, 
          rdata: %{txt: "v=spf1 include:_spf.example.com ~all"}}
      ],
      authority: [
        %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns1.example.com."}},
        %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns2.example.com."}}
      ]
    })
  end

  defp create_edns_response do
    DNSpacket.create(%DNSpacket{
      id: 0xdef0,
      qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}}
      ],
      edns_info: %{
        payload_size: 1232,
        ex_rcode: 0,
        version: 0,
        dnssec: 0,
        z: 0,
        options: %{
          edns_client_subnet: %{
            family: 1,
            client_subnet: {192, 168, 1, 0},
            source_prefix: 24,
            scope_prefix: 0
          }
        }
      }
    })
  end
end

ProfilingBench.run_profiling()