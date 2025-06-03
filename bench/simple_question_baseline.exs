defmodule SimpleQuestionBaseline do
  @moduledoc """
  Simple Question-focused baseline using built-in timer
  Based on commit 28199e3 (after basic optimizations)
  """

  def run_benchmarks do
    # Question-focused test packets with varying domain lengths
    test_packets = %{
      "Q short domain" => %DNSpacket{
        id: 0x1234, qr: 0, rd: 1,
        question: [%{qname: "dns.com.", qtype: :a, qclass: :in}]
      },
      
      "Q medium domain" => %DNSpacket{
        id: 0x2345, qr: 0, rd: 1, 
        question: [%{qname: "example.org.", qtype: :a, qclass: :in}]
      },
      
      "Q long domain" => %DNSpacket{
        id: 0x3456, qr: 0, rd: 1,
        question: [%{qname: "subdomain.example.com.", qtype: :a, qclass: :in}]
      },
      
      "Q very long domain" => %DNSpacket{
        id: 0x4567, qr: 0, rd: 1,
        question: [%{qname: "very.long.subdomain.example.com.", qtype: :a, qclass: :in}]
      },
      
      "Q extremely long domain" => %DNSpacket{
        id: 0x5678, qr: 0, rd: 1,
        question: [%{qname: "extremely.very.long.complex.subdomain.example.com.", qtype: :a, qclass: :in}]
      },
      
      "Q different types" => %DNSpacket{
        id: 0x6789, qr: 0, rd: 1,
        question: [%{qname: "mail.example.com.", qtype: :mx, qclass: :in}]
      }
    }
    
    # Pre-create all binary packets
    binary_packets = test_packets 
                     |> Enum.map(fn {name, packet} -> 
                       {name, DNSpacket.create(packet)} 
                     end)
                     |> Map.new()
    
    IO.puts("Question-Focused BASELINE Performance (28199e3)")
    IO.puts("==============================================")
    IO.puts("Focus: Small packets with 1 Question record")
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
      {"DNS.type/1 (TXT)", measure_function(fn -> DNS.type(16) end, 1_000_000)},
      {"DNS.class/1 (IN)", measure_function(fn -> DNS.class(1) end, 1_000_000)},
      {"create_character_string short", measure_function(fn -> DNSpacket.create_character_string("dns") end, 500_000)},
      {"create_character_string long", measure_function(fn -> DNSpacket.create_character_string("extremely") end, 500_000)},
      {"concat_binary_list", measure_function(fn -> DNSpacket.concat_binary_list([<<1,2>>, <<3,4>>, <<5,6>>]) end, 100_000)}
    ]
    
    # Display results
    IO.puts("Question Parse Performance (BASELINE 28199e3):")
    IO.puts("==============================================")
    Enum.each(results, fn {name, avg_time_ns, memory_used, _result} ->
      ips = 1_000_000_000 / avg_time_ns
      IO.puts("#{String.pad_trailing(name, 35)} #{Float.round(ips/1_000_000, 2)}M IPS, #{Float.round(avg_time_ns, 2)}ns avg, ~#{memory_used}B memory")
    end)
    
    IO.puts("")
    IO.puts("Component Performance (BASELINE 28199e3):")
    IO.puts("=========================================")
    Enum.each(component_results, fn {name, avg_time_ns} ->
      ips = 1_000_000_000 / avg_time_ns
      IO.puts("#{String.pad_trailing(name, 35)} #{Float.round(ips/1_000_000, 2)}M IPS, #{Float.round(avg_time_ns, 2)}ns avg")
    end)
    
    IO.puts("")
    IO.puts("BASELINE (28199e3) Code Characteristics:")
    IO.puts("- O(n²) string concatenation in parse_name")
    IO.puts("- Double DNS.type/class lookups")
    IO.puts("- String.length instead of byte_size")
    IO.puts("- Enum.reduce with <> in concat_binary_list")
    IO.puts("- 4-tuple returns from parse functions")
    IO.puts("- No function inlining or native compilation")
  end
  
  defp measure_function(func, iterations) do
    {time_us, _} = :timer.tc(fn ->
      Enum.each(1..iterations, fn _ -> func.() end)
    end)
    (time_us * 1000) / iterations
  end
end

SimpleQuestionBaseline.run_benchmarks()