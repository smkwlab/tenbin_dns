defmodule QuickBench do
  @moduledoc """
  Quick performance benchmarks for TenbinDns library
  
  Run with: mix run bench/quick_bench.exs
  """

  def run_quick_benchmarks do
    # Sample data
    simple_packet = %DNSpacket{
      id: 0x1234,
      qr: 0,
      opcode: 0,
      rd: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
    }

    simple_binary = DNSpacket.create(simple_packet)

    Benchee.run(%{
      # Most critical bottlenecks
      "DNS.type/1" => fn -> DNS.type(1) end,
      "concat_binary_list" => fn -> 
        DNSpacket.concat_binary_list([<<1, 2>>, <<3, 4>>, <<5, 6>>, <<7, 8>>])
      end,
      "create_domain_name" => fn ->
        DNSpacket.create_domain_name("example.com")
      end,
      "create_rdata A" => fn ->
        DNSpacket.create_rdata(%{addr: {192, 168, 1, 1}}, :a, :in)
      end,
      "create_packet" => fn ->
        DNSpacket.create(simple_packet)
      end,
      "parse_packet" => fn ->
        DNSpacket.parse(simple_binary)
      end,
    },
    time: 2,
    memory_time: 1,
    formatters: [Benchee.Formatters.Console])
  end
end

IO.puts("Running Quick DNS Performance Benchmarks...")
IO.puts("==========================================")
QuickBench.run_quick_benchmarks()