defmodule PerformanceBench do
  @moduledoc """
  Performance benchmarks for TenbinDns library
  
  Run with: mix run bench/performance_bench.exs
  """

  # Sample DNS packets for benchmarking
  @simple_query_packet %DNSpacket{
    id: 0x1234,
    qr: 0,
    opcode: 0,
    rd: 1,
    question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
  }

  @complex_response_packet %DNSpacket{
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
    authority: [
      %{name: "example.com.", type: :ns, class: :in, ttl: 86400,
        rdata: %{name: "ns1.example.com."}},
      %{name: "example.com.", type: :ns, class: :in, ttl: 86400,
        rdata: %{name: "ns2.example.com."}},
    ],
    additional: [
      %{name: "ns1.example.com.", type: :a, class: :in, ttl: 86400,
        rdata: %{addr: {192, 168, 1, 10}}},
      %{name: "ns2.example.com.", type: :a, class: :in, ttl: 86400,
        rdata: %{addr: {192, 168, 1, 11}}},
    ]
  }

  def run_benchmarks do
    # Pre-create binary packets for parsing benchmarks
    simple_binary = DNSpacket.create(@simple_query_packet)
    complex_binary = DNSpacket.create(@complex_response_packet)

    Benchee.run(%{
      # DNS constant lookups (very frequent operations)
      "DNS.type/1 (common)" => fn -> DNS.type(1) end,
      "DNS.type/1 (uncommon)" => fn -> DNS.type(257) end,
      "DNS.type_code/1 (common)" => fn -> DNS.type_code(:a) end,
      "DNS.type_code/1 (uncommon)" => fn -> DNS.type_code(:caa) end,
      
      # Binary concatenation (bottleneck identified)
      "concat_binary_list (small)" => fn -> 
        DNSpacket.concat_binary_list([<<1, 2>>, <<3, 4>>, <<5, 6>>])
      end,
      "concat_binary_list (medium)" => fn ->
        list = for i <- 1..20, do: <<i::8, i+1::8>>
        DNSpacket.concat_binary_list(list)
      end,
      "concat_binary_list (large)" => fn ->
        list = for i <- 1..100, do: <<i::8, i+1::8, i+2::8, i+3::8>>
        DNSpacket.concat_binary_list(list)
      end,

      # Domain name operations
      "create_domain_name (simple)" => fn ->
        DNSpacket.create_domain_name("example.com")
      end,
      "create_domain_name (complex)" => fn ->
        DNSpacket.create_domain_name("very.long.subdomain.example.com")
      end,
      "create_character_string (short)" => fn ->
        DNSpacket.create_character_string("test")
      end,
      "create_character_string (long)" => fn ->
        DNSpacket.create_character_string("this-is-a-very-long-dns-label-for-testing-performance")
      end,

      # Address conversion operations
      "create_rdata A record" => fn ->
        DNSpacket.create_rdata(%{addr: {192, 168, 1, 1}}, :a, :in)
      end,
      "create_rdata AAAA record" => fn ->
        DNSpacket.create_rdata(%{addr: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}}, :aaaa, :in)
      end,

      # Packet creation (end-to-end)
      "create_packet (simple query)" => fn ->
        DNSpacket.create(@simple_query_packet)
      end,
      "create_packet (complex response)" => fn ->
        DNSpacket.create(@complex_response_packet)
      end,

      # Packet parsing (end-to-end)
      "parse_packet (simple query)" => fn ->
        DNSpacket.parse(simple_binary)
      end,
      "parse_packet (complex response)" => fn ->
        DNSpacket.parse(complex_binary)
      end,

      # Resource record parsing
      "parse_rdata A record" => fn ->
        DNSpacket.parse_rdata(<<192, 168, 1, 1>>, :a, :in, <<>>)
      end,
      "parse_rdata AAAA record" => fn ->
        rdata = <<0x2001::16, 0xdb8::16, 0::16, 0::16, 0::16, 0::16, 0::16, 1::16>>
        DNSpacket.parse_rdata(rdata, :aaaa, :in, <<>>)
      end,

      # check_ecs function (identified as inefficient)
      "check_ecs (empty)" => fn ->
        DNSpacket.check_ecs([])
      end,
      "check_ecs (with ECS)" => fn ->
        additional = [
          %{type: :opt, rdata: [
            %{code: :edns_client_subnet, family: 1, source: 24, scope: 0, addr: <<192, 168, 1>>}
          ]}
        ]
        DNSpacket.check_ecs(additional)
      end,
      "check_ecs (no ECS)" => fn ->
        additional = [
          %{type: :opt, rdata: [%{code: :cookie, cookie: <<1, 2, 3, 4>>}]},
          %{type: :a, rdata: %{addr: {192, 168, 1, 1}}}
        ]
        DNSpacket.check_ecs(additional)
      end,
    },
    time: 5,
    memory_time: 2,
    formatters: [
      Benchee.Formatters.HTML,
      Benchee.Formatters.Console
    ])
  end

  def run_memory_benchmarks do
    """
    Additional memory-focused benchmarks for specific bottlenecks
    """
    large_domain_list = for i <- 1..1000, do: "label#{i}.example.com"
    
    Benchee.run(%{
      "batch domain creation" => fn ->
        Enum.map(large_domain_list, &DNSpacket.create_domain_name/1)
      end,
      "batch type lookups" => fn ->
        types = [1, 2, 5, 15, 16, 28, 255, 257] # Common DNS types
        Enum.map(types, &DNS.type/1)
      end,
    },
    time: 3,
    memory_time: 3,
    formatters: [Benchee.Formatters.Console])
  end
end

IO.puts("Running DNS Performance Benchmarks...")
IO.puts("====================================")
PerformanceBench.run_benchmarks()

IO.puts("\n\nRunning Memory Benchmarks...")
IO.puts("============================")
PerformanceBench.run_memory_benchmarks()