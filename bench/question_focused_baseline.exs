defmodule QuestionFocusedBaseline do
  @moduledoc """
  Question-focused baseline benchmark for small packets with various domain lengths
  Based on commit 28199e3 (after basic optimizations)
  
  Run with: mix run bench/question_focused_baseline.exs
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
      
      "Q different types short" => %DNSpacket{
        id: 0x6789, qr: 0, rd: 1,
        question: [%{qname: "test.com.", qtype: :aaaa, qclass: :in}]
      },
      
      "Q different types long" => %DNSpacket{
        id: 0x789A, qr: 0, rd: 1,
        question: [%{qname: "mail.example.com.", qtype: :mx, qclass: :in}]
      },
      
      "Q txt record long domain" => %DNSpacket{
        id: 0x89AB, qr: 0, rd: 1,
        question: [%{qname: "verification.subdomain.example.com.", qtype: :txt, qclass: :in}]
      }
    }
    
    # Pre-create all binary packets
    binary_packets = test_packets 
                     |> Enum.map(fn {name, packet} -> 
                       {name, DNSpacket.create(packet)} 
                     end)
                     |> Map.new()
    
    IO.puts("Question-Focused BASELINE Benchmark (28199e3)")
    IO.puts("=============================================")
    IO.puts("Focus: Small packets with 1 Question record")
    IO.puts("Domain length variation: short to extremely long")
    IO.puts("High precision measurement")
    IO.puts("")
    
    # Create benchmark functions
    benchmarks = binary_packets
                 |> Enum.map(fn {name, binary} -> 
                   {"parse #{name}", fn -> DNSpacket.parse(binary) end}
                 end)
                 |> Map.new()
    
    # Add component benchmarks relevant to Question parsing
    component_benchmarks = %{
      "DNS.type/1 (A)" => fn -> DNS.type(1) end,
      "DNS.type/1 (AAAA)" => fn -> DNS.type(28) end,
      "DNS.type/1 (MX)" => fn -> DNS.type(15) end,
      "DNS.type/1 (TXT)" => fn -> DNS.type(16) end,
      "DNS.class/1 (IN)" => fn -> DNS.class(1) end,
      "create_character_string short" => fn -> 
        DNSpacket.create_character_string("dns")
      end,
      "create_character_string long" => fn -> 
        DNSpacket.create_character_string("extremely")
      end,
      "parse_name short domain" => fn ->
        body = <<3, "dns", 3, "com", 0>>
        elem(DNSpacket.parse_name(body, body, ""), 2)
      end,
      "parse_name long domain" => fn ->
        body = <<9, "extremely", 4, "very", 4, "long", 7, "complex", 9, "subdomain", 7, "example", 3, "com", 0>>
        elem(DNSpacket.parse_name(body, body, ""), 2)
      end
    }
    
    all_benchmarks = Map.merge(benchmarks, component_benchmarks)
    
    # High precision measurement settings
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
    
    IO.puts("\nBASELINE (28199e3) Code Characteristics:")
    IO.puts("- O(n²) string concatenation in parse_name (result <> name <> \".\")")
    IO.puts("- Double DNS.type/class lookups in parse_answer_checkopt") 
    IO.puts("- String.length instead of byte_size in create_character_string")
    IO.puts("- Enum.reduce with <> in concat_binary_list")
    IO.puts("- 4-tuple returns from parse functions")
    IO.puts("- No function inlining")
    IO.puts("- Standard compilation (no HiPE/native)")
  end
end

QuestionFocusedBaseline.run_benchmarks()