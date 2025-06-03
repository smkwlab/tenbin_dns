defmodule BaselineExtendedBench do
  @moduledoc """
  Baseline extended benchmark for original code (before optimizations)
  
  Run with: mix run bench/baseline_extended_bench.exs
  """

  def run_benchmarks do
    # Same test packets as speed optimization benchmark for accurate comparison
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
    
    IO.puts("BASELINE Extended Benchmark (Original Code)")
    IO.puts("==========================================")
    IO.puts("Code version: d3790e2 (before any optimizations)")
    IO.puts("High precision measurement for accurate comparison")
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
    
    # EXACT same measurement conditions as speed optimization benchmark
    Benchee.run(all_benchmarks,
      warmup: 5,        # 5 seconds warmup
      time: 10,         # 10 seconds measurement time
      memory_time: 5,   # 5 seconds for memory measurement
      reduction_time: 3, # 3 seconds for reduction measurement
      print: [
        benchmarking: true,
        fast_warning: false
      ],
      formatters: [
        Benchee.Formatters.Console,
        {Benchee.Formatters.Console, extended_statistics: true}
      ])
    
    IO.puts("\nBASELINE Code Characteristics:")
    IO.puts("- No function inlining")
    IO.puts("- Standard compilation (no HiPE)")
    IO.puts("- O(n²) string concatenation in parse_name")
    IO.puts("- Double DNS.type/class lookups")
    IO.puts("- 4-tuple returns from parse functions")
    IO.puts("- List reversal after parsing")
  end
end

BaselineExtendedBench.run_benchmarks()