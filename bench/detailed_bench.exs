defmodule DetailedBench do
  @moduledoc """
  Detailed performance analysis to identify further optimization opportunities
  
  Run with: mix run bench/detailed_bench.exs
  """

  def run_detailed_benchmarks do
    # More complex scenarios to identify bottlenecks
    large_packet = create_large_packet()
    complex_domain = "very.long.subdomain.with.many.labels.example.com."
    
    Benchee.run(%{
      # Current bottlenecks analysis
      "create_packet (large)" => fn ->
        DNSpacket.create(large_packet)
      end,
      "parse_packet (large)" => fn ->
        binary = DNSpacket.create(large_packet)
        DNSpacket.parse(binary)
      end,
      
      # Domain name operations scaling
      "create_domain_name (complex)" => fn ->
        DNSpacket.create_domain_name(complex_domain)
      end,
      "create_domain_name (batch)" => fn ->
        domains = ["a.com", "b.org", "c.net", "d.info"]
        Enum.map(domains, &DNSpacket.create_domain_name/1)
      end,
      
      # Memory allocation patterns
      "create_question (multiple)" => fn ->
        questions = [
          %{qname: "test1.com.", qtype: :a, qclass: :in},
          %{qname: "test2.org.", qtype: :aaaa, qclass: :in},
          %{qname: "test3.net.", qtype: :mx, qclass: :in},
          %{qname: "test4.info.", qtype: :txt, qclass: :in}
        ]
        DNSpacket.create_question(questions)
      end,
      
      # Resource record creation scaling
      "create_answer (multiple A)" => fn ->
        answers = for i <- 1..10 do
          %{name: "host#{i}.example.com.", type: :a, class: :in, ttl: 300,
            rdata: %{addr: {192, 168, 1, i}}}
        end
        DNSpacket.create_answer(answers)
      end,
      
      # SOA record (complex structure)
      "create_rdata SOA" => fn ->
        rdata = %{
          mname: "ns1.example.com",
          rname: "admin.example.com",
          serial: 2023010101,
          refresh: 7200,
          retry: 3600,
          expire: 604800,
          minimum: 86400
        }
        DNSpacket.create_rdata(rdata, :soa, :in)
      end,
      
      # Name parsing operations
      "parse_name (simple)" => fn ->
        # This is an internal function, but we can test indirectly
        simple_packet = %DNSpacket{
          id: 0x1234,
          question: [%{qname: "test.com.", qtype: :a, qclass: :in}]
        }
        binary = DNSpacket.create(simple_packet)
        DNSpacket.parse(binary)
      end,
      
      # Map lookup vs pattern matching comparison
      "DNS.type (common)" => fn -> DNS.type(1) end,
      "DNS.type (fallback)" => fn -> DNS.type(999) end,
      "DNS.type_code (common)" => fn -> DNS.type_code(:a) end,
      "DNS.type_code (fallback)" => fn -> DNS.type_code(:unknown_type) end,
    },
    time: 3,
    memory_time: 2,
    reduction_time: 1,
    formatters: [Benchee.Formatters.Console])
  end

  defp create_large_packet do
    # Create a complex packet with many records
    %DNSpacket{
      id: 0x1234,
      qr: 1,
      aa: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: for i <- 1..20 do
        %{name: "host#{i}.example.com.", type: :a, class: :in, ttl: 300,
          rdata: %{addr: {192, 168, div(i, 256), rem(i, 256)}}}
      end,
      authority: for i <- 1..5 do
        %{name: "example.com.", type: :ns, class: :in, ttl: 86400,
          rdata: %{name: "ns#{i}.example.com."}}
      end,
      additional: for i <- 1..10 do
        %{name: "ns#{i}.example.com.", type: :a, class: :in, ttl: 86400,
          rdata: %{addr: {192, 168, 100, i}}}
      end
    }
  end
end

IO.puts("Running Detailed DNS Performance Analysis...")
IO.puts("=============================================")
DetailedBench.run_detailed_benchmarks()