defmodule SimpleBaselineBench do
  @moduledoc """
  Simple baseline benchmark using built-in :timer module
  
  Run with: mix run bench/simple_baseline_bench.exs
  """

  def run_benchmarks do
    # Test packets for comparison
    test_packets = %{
      "tiny (A query)" => %DNSpacket{
        id: 0x1234,
        qr: 0,
        rd: 1,
        question: [%{qname: "a.com.", qtype: :a, qclass: :in}]
      },
      
      "small (short domain)" => %DNSpacket{
        id: 0x2345,
        qr: 0,
        rd: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
      },
      
      "medium (long domain)" => %DNSpacket{
        id: 0x3456,
        qr: 0,
        rd: 1,
        question: [%{qname: "very.long.subdomain.example.com.", qtype: :a, qclass: :in}]
      },
      
      "large (5 A records)" => %DNSpacket{
        id: 0x4567,
        qr: 1,
        aa: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: for i <- 1..5 do
          %{name: "example.com.", type: :a, class: :in, ttl: 300, 
            rdata: %{addr: {192, 168, 1, i}}}
        end
      },
      
      "xlarge (20 mixed records)" => %DNSpacket{
        id: 0x5678,
        qr: 1,
        aa: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: [
          %{name: "example.com.", type: :a, class: :in, ttl: 300, 
            rdata: %{addr: {192, 168, 1, 1}}},
          %{name: "example.com.", type: :a, class: :in, ttl: 300, 
            rdata: %{addr: {192, 168, 1, 2}}},
          %{name: "example.com.", type: :aaaa, class: :in, ttl: 300,
            rdata: %{addr: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}}},
          %{name: "example.com.", type: :mx, class: :in, ttl: 3600,
            rdata: %{preference: 10, name: "mail.example.com."}},
          %{name: "example.com.", type: :txt, class: :in, ttl: 3600,
            rdata: %{txt: "v=spf1 include:_spf.google.com ~all"}},
        ],
        authority: for i <- 1..5 do
          %{name: "example.com.", type: :ns, class: :in, ttl: 86400,
            rdata: %{name: "ns#{i}.example.com."}}
        end,
        additional: for i <- 1..10 do
          %{name: "ns#{i}.example.com.", type: :a, class: :in, ttl: 86400,
            rdata: %{addr: {192, 168, 2, i}}}
        end
      }
    }
    
    # Pre-create all binary packets
    binary_packets = test_packets 
                     |> Enum.map(fn {name, packet} -> 
                       {name, DNSpacket.create(packet)} 
                     end)
                     |> Map.new()
    
    IO.puts("BASELINE Performance Measurement (Original Code)")
    IO.puts("===============================================")
    IO.puts("Code version: d3790e2 (before any optimizations)")
    IO.puts("Using :timer.tc/1 for measurement")
    IO.puts("")
    
    # Warm up
    IO.puts("Warming up...")
    Enum.each(1..10000, fn _ ->
      Enum.each(binary_packets, fn {_, binary} ->
        DNSpacket.parse(binary)
      end)
    end)
    
    IO.puts("Running baseline measurements...")
    IO.puts("")
    
    # Measure each packet type
    results = Enum.map(binary_packets, fn {name, binary} ->
      # Measure multiple times for accuracy
      iterations = 100_000
      
      {time_us, _} = :timer.tc(fn ->
        Enum.each(1..iterations, fn _ ->
          DNSpacket.parse(binary)
        end)
      end)
      
      avg_time_ns = (time_us * 1000) / iterations
      
      # Measure memory
      {_, memory_before} = :erlang.process_info(self(), :memory)
      result = DNSpacket.parse(binary)
      {_, memory_after} = :erlang.process_info(self(), :memory)
      memory_used = max(0, memory_after - memory_before)
      
      {name, avg_time_ns, memory_used, result}
    end)
    
    # Component measurements
    component_results = [
      {"DNS.type/1 (A)", measure_function(fn -> DNS.type(1) end, 1_000_000)},
      {"DNS.type/1 (AAAA)", measure_function(fn -> DNS.type(28) end, 1_000_000)},
      {"DNS.type/1 (MX)", measure_function(fn -> DNS.type(15) end, 1_000_000)},
      {"DNS.class/1 (IN)", measure_function(fn -> DNS.class(1) end, 1_000_000)},
      {"create_character_string", measure_function(fn -> DNSpacket.create_character_string("example") end, 500_000)},
      {"concat_binary_list (small)", measure_function(fn -> DNSpacket.concat_binary_list([<<1,2>>, <<3,4>>, <<5,6>>]) end, 100_000)}
    ]
    
    # Display results
    IO.puts("Parse Performance Results:")
    IO.puts("==========================")
    Enum.each(results, fn {name, avg_time_ns, memory_used, _result} ->
      ips = 1_000_000_000 / avg_time_ns
      IO.puts("#{String.pad_trailing(name, 30)} #{Float.round(ips/1_000_000, 2)}M IPS, #{Float.round(avg_time_ns, 2)}ns avg, ~#{memory_used}B memory")
    end)
    
    IO.puts("")
    IO.puts("Component Performance Results:")
    IO.puts("==============================")
    Enum.each(component_results, fn {name, avg_time_ns} ->
      ips = 1_000_000_000 / avg_time_ns
      IO.puts("#{String.pad_trailing(name, 30)} #{Float.round(ips/1_000_000, 2)}M IPS, #{Float.round(avg_time_ns, 2)}ns avg")
    end)
    
    IO.puts("")
    IO.puts("BASELINE Code Characteristics:")
    IO.puts("- No function inlining")
    IO.puts("- Standard compilation (no HiPE)")
    IO.puts("- O(n²) string concatenation in parse_name")
    IO.puts("- Double DNS.type/class lookups")
    IO.puts("- 4-tuple returns from parse functions")
    IO.puts("- Enum.reduce with <> in concat_binary_list")
    IO.puts("- String.length instead of byte_size")
  end
  
  defp measure_function(func, iterations) do
    {time_us, _} = :timer.tc(fn ->
      Enum.each(1..iterations, fn _ -> func.() end)
    end)
    (time_us * 1000) / iterations
  end
end

SimpleBaselineBench.run_benchmarks()