defmodule ExtendedSpeedBench do
  @moduledoc """
  Extended benchmark with higher precision for speed optimization
  
  Run with: mix run bench/extended_speed_bench.exs
  """

  def run_benchmarks do
    # Create test packets of various complexities
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
    
    IO.puts("Extended Speed Benchmark")
    IO.puts("=======================")
    IO.puts("High precision measurement with extended run time")
    IO.puts("Focus: Maximum parsing speed (memory efficiency secondary)")
    IO.puts("")
    
    # Create benchmark functions
    benchmarks = binary_packets
                 |> Enum.map(fn {name, binary} -> 
                   {"parse #{name}", fn -> DNSpacket.parse(binary) end}
                 end)
                 |> Map.new()
    
    # Add component benchmarks for detailed analysis
    component_benchmarks = %{
      "DNS.type/1 (A)" => fn -> DNS.type(1) end,
      "DNS.type/1 (AAAA)" => fn -> DNS.type(28) end,
      "DNS.type/1 (MX)" => fn -> DNS.type(15) end,
      "DNS.class/1 (IN)" => fn -> DNS.class(1) end,
      "create_character_string" => fn -> 
        DNSpacket.create_character_string("example")
      end,
      "concat_binary_list (small)" => fn ->
        DNSpacket.concat_binary_list([<<1,2>>, <<3,4>>, <<5,6>>])
      end,
    }
    
    all_benchmarks = Map.merge(benchmarks, component_benchmarks)
    
    Benchee.run(all_benchmarks,
      warmup: 5,        # 5 seconds warmup for stable results
      time: 10,         # 10 seconds measurement time
      memory_time: 5,   # 5 seconds for memory measurement
      reduction_time: 3, # 3 seconds for reduction measurement
      print: [
        benchmarking: true,
        fast_warning: false  # Disable fast function warnings
      ],
      formatters: [
        Benchee.Formatters.Console,
        {Benchee.Formatters.Console, extended_statistics: true}
      ])
    
    IO.puts("\nSpeed Optimization Targets:")
    IO.puts("1. Inline more functions")
    IO.puts("2. Reduce function call overhead")
    IO.puts("3. Optimize binary pattern matching")
    IO.puts("4. Pre-compute common values")
    IO.puts("5. Reduce intermediate allocations")
  end
end

ExtendedSpeedBench.run_benchmarks()