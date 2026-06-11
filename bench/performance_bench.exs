defmodule PerformanceBench do
  @moduledoc """
  Performance benchmarks for the TenbinDns public API.

  Run with: mix run bench/performance_bench.exs

  Only the supported public surface is exercised (DNSpacket.create/1,
  DNSpacket.parse/1 and the DNS constant lookups), so this script keeps
  working across internal refactorings. Use it to compare before/after
  numbers when touching the create/parse hot paths.
  """

  @simple_query %DNSpacket{
    id: 0x1234,
    rd: 1,
    question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
  }

  @complex_response %DNSpacket{
    id: 0x5678,
    qr: 1,
    aa: 1,
    question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
    answer: [
      %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, 1}}},
      %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, 2}}},
      %{
        name: "example.com.",
        type: :aaaa,
        class: :in,
        ttl: 300,
        rdata: %{addr: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}}
      },
      %{
        name: "example.com.",
        type: :mx,
        class: :in,
        ttl: 3600,
        rdata: %{preference: 10, name: "mail.example.com."}
      },
      %{
        name: "example.com.",
        type: :txt,
        class: :in,
        ttl: 3600,
        rdata: %{txt: "v=spf1 include:_spf.example.com ~all"}
      }
    ]
  }

  @edns_response %DNSpacket{
    id: 0x9ABC,
    qr: 1,
    question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
    answer: [
      %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 0, 2, 1}}}
    ],
    edns_info: %{
      payload_size: 1232,
      ecs_family: 1,
      ecs_subnet: {192, 168, 1, 0},
      ecs_source_prefix: 24,
      ecs_scope_prefix: 0,
      cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
      cookie_server: nil,
      unknown_options: %{65_001 => <<1, 2, 3>>}
    }
  }

  def run do
    simple_query_bin = DNSpacket.create(@simple_query)
    complex_response_bin = DNSpacket.create(@complex_response)
    edns_response_bin = DNSpacket.create(@edns_response)

    Benchee.run(
      %{
        "create simple query" => fn -> DNSpacket.create(@simple_query) end,
        "create complex response" => fn -> DNSpacket.create(@complex_response) end,
        "create EDNS response" => fn -> DNSpacket.create(@edns_response) end,
        "parse simple query" => fn -> DNSpacket.parse(simple_query_bin) end,
        "parse complex response" => fn -> DNSpacket.parse(complex_response_bin) end,
        "parse EDNS response" => fn -> DNSpacket.parse(edns_response_bin) end,
        "DNS constant lookups" => fn ->
          DNS.type(1)
          DNS.type(28)
          DNS.type_code(:a)
          DNS.type_code(:aaaa)
          DNS.class(1)
          DNS.class_code(:in)
        end
      },
      warmup: 1,
      time: 3,
      memory_time: 1,
      formatters: [Benchee.Formatters.Console]
    )
  end
end

PerformanceBench.run()
