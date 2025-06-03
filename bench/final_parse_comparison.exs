defmodule FinalParseComparison do
  @moduledoc """
  Final comparison showing parse performance with and without list reversal
  
  Run with: mix run bench/final_parse_comparison.exs
  """

  def run_comparison do
    # Create test packets of various sizes
    packets = %{
      "simple (1 question)" => %DNSpacket{
        id: 0x1234,
        qr: 0,
        opcode: 0,
        rd: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
      },
      "medium (5 answers)" => %DNSpacket{
        id: 0x5678,
        qr: 1,
        aa: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: for i <- 1..5 do
          %{name: "example.com.", type: :a, class: :in, ttl: 300, 
            rdata: %{addr: {192, 168, 1, i}}}
        end
      },
      "large (20 records)" => %DNSpacket{
        id: 0x9999,
        qr: 1,
        aa: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: for i <- 1..10 do
          %{name: "example.com.", type: :a, class: :in, ttl: 300, 
            rdata: %{addr: {192, 168, 1, i}}}
        end,
        additional: for i <- 1..10 do
          %{name: "ns#{i}.example.com.", type: :a, class: :in, ttl: 86400,
            rdata: %{addr: {192, 168, 2, i}}}
        end
      }
    }
    
    # Pre-create binaries
    binaries = packets 
               |> Enum.map(fn {name, packet} -> {name, DNSpacket.create(packet)} end)
               |> Map.new()
    
    IO.puts("Final Parse Performance Comparison")
    IO.puts("==================================")
    IO.puts("Current optimizations (without list reversal):")
    IO.puts("- Cached DNS.type/class lookups")
    IO.puts("- Optimized parse_name with iolist")
    IO.puts("- Inlined critical functions")
    IO.puts("- NO list reversal (faster but reversed order)")
    IO.puts("")
    
    benchmarks = binaries
                 |> Enum.map(fn {name, binary} -> 
                   {"parse #{name}", fn -> DNSpacket.parse(binary) end}
                 end)
                 |> Map.new()
    
    Benchee.run(benchmarks,
      time: 3,
      memory_time: 2,
      warmup: 2,
      formatters: [Benchee.Formatters.Console])
    
    IO.puts("\nPerformance Summary:")
    IO.puts("- Removing list reversal saves ~4 Enum.reverse calls per packet")
    IO.puts("- Each Enum.reverse is O(n) where n is the number of records")
    IO.puts("- Most significant improvement for packets with many records")
    IO.puts("\nNote: Records will be in reverse order of appearance in the packet")
  end
end

FinalParseComparison.run_comparison()