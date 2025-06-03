defmodule SpeedFocusedBench do
  @moduledoc """
  Speed-focused benchmark with aggressive optimizations
  
  Run with: mix run bench/speed_focused_bench.exs
  """

  def run_benchmarks do
    # Test packets of different sizes for speed measurement
    test_packets = [
      {"tiny", %DNSpacket{
        id: 0x1234, qr: 0, rd: 1,
        question: [%{qname: "a.com.", qtype: :a, qclass: :in}]
      }},
      {"small", %DNSpacket{
        id: 0x2345, qr: 0, rd: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
      }},
      {"medium", %DNSpacket{
        id: 0x3456, qr: 1, aa: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: for i <- 1..3 do
          %{name: "example.com.", type: :a, class: :in, ttl: 300, 
            rdata: %{addr: {192, 168, 1, i}}}
        end
      }},
      {"large", %DNSpacket{
        id: 0x4567, qr: 1, aa: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: for i <- 1..10 do
          %{name: "example.com.", type: :a, class: :in, ttl: 300, 
            rdata: %{addr: {192, 168, 1, i}}}
        end,
        additional: for i <- 1..5 do
          %{name: "ns#{i}.example.com.", type: :a, class: :in, ttl: 86400,
            rdata: %{addr: {192, 168, 2, i}}}
        end
      }}
    ]
    
    # Pre-create binaries
    binaries = test_packets
               |> Enum.map(fn {name, packet} -> 
                 {name, DNSpacket.create(packet)}
               end)
               |> Map.new()
    
    IO.puts("Speed-Focused Parse Benchmark")
    IO.puts("============================")
    IO.puts("Optimizations applied:")
    IO.puts("- Aggressive function inlining")
    IO.puts("- Native compilation with HiPE")
    IO.puts("- Reduced function call overhead")
    IO.puts("- Fast parsing paths")
    IO.puts("- Pre-cached DNS lookups")
    IO.puts("")
    
    # Create benchmark suite
    benchmarks = binaries
                 |> Enum.map(fn {name, binary} -> 
                   {"parse #{name}", fn -> DNSpacket.parse(binary) end}
                 end)
                 |> Map.new()
    
    Benchee.run(benchmarks,
      warmup: 3,        # 3 seconds warmup
      time: 5,          # 5 seconds measurement  
      memory_time: 2,   # 2 seconds memory measurement
      print: [
        benchmarking: true,
        fast_warning: false
      ],
      formatters: [Benchee.Formatters.Console])
    
    IO.puts("\nSpeed Optimizations Summary:")
    IO.puts("1. ✅ Aggressive function inlining")
    IO.puts("2. ✅ Native compilation (HiPE)")
    IO.puts("3. ✅ Fast parsing paths (_fast functions)")
    IO.puts("4. ✅ Reduced 4-tuple returns to 2-tuple returns")
    IO.puts("5. ✅ Pre-cached DNS type/class lookups")
    IO.puts("6. ✅ No list reversal overhead")
    IO.puts("")
    IO.puts("Trade-offs:")
    IO.puts("- Higher memory usage due to aggressive inlining")
    IO.puts("- Larger compiled module size")
    IO.puts("- Records returned in reverse order")
  end
end

SpeedFocusedBench.run_benchmarks()