# Lazy Parsing Performance Benchmark
# Compares eager vs lazy parsing performance and memory usage

# Create test data
test_packet = %DNSpacket{
  id: 0x1234,
  qr: 1,
  rd: 1,
  ra: 1,
  question: [
    %{qname: "example.com.", qtype: :a, qclass: :in},
    %{qname: "google.com.", qtype: :aaaa, qclass: :in}
  ],
  answer: [
    %{
      name: "example.com.",
      type: :a,
      class: :in,
      ttl: 300,
      rdata: %{addr: {192, 168, 1, 1}}
    },
    %{
      name: "google.com.",
      type: :aaaa,
      class: :in,
      ttl: 300,
      rdata: %{addr: {0x2001, 0x4860, 0x4860, 0x0, 0x0, 0x0, 0x0, 0x8888}}
    }
  ],
  authority: [
    %{
      name: "example.com.",
      type: :ns,
      class: :in,
      ttl: 86400,
      rdata: %{name: "ns1.example.com."}
    }
  ],
  additional: [
    %{
      name: "ns1.example.com.",
      type: :a,
      class: :in,
      ttl: 86400,
      rdata: %{addr: {192, 168, 1, 2}}
    }
  ]
}

test_binary = DNSpacket.create(test_packet)

IO.puts("Lazy Parsing Performance Benchmark")
IO.puts("==================================")
IO.puts("Test packet size: #{byte_size(test_binary)} bytes")
IO.puts("Sections: #{length(test_packet.question)} questions, #{length(test_packet.answer)} answers")
IO.puts("          #{length(test_packet.authority)} authority, #{length(test_packet.additional)} additional")
IO.puts("")

Benchee.run(
  %{
    # Parsing benchmarks
    "eager_parse (full)" => fn -> DNSpacket.parse(test_binary) end,
    "lazy_parse (header only)" => fn -> DNSpacket.parse_lazy(test_binary) end,
    
    # Access patterns
    "eager_parse + access_question" => fn -> 
      packet = DNSpacket.parse(test_binary)
      packet.question
    end,
    "lazy_parse + access_question" => fn ->
      packet = DNSpacket.parse_lazy(test_binary)
      updated_packet = DNSpacket.get_questions(packet)
      updated_packet.question
    end,
    
    "eager_parse + access_answer" => fn ->
      packet = DNSpacket.parse(test_binary)
      packet.answer
    end,
    "lazy_parse + access_answer" => fn ->
      packet = DNSpacket.parse_lazy(test_binary)
      updated_packet = DNSpacket.get_answers(packet)
      updated_packet.answer
    end,
    
    # Full access patterns
    "eager_parse + access_all" => fn ->
      packet = DNSpacket.parse(test_binary)
      {packet.question, packet.answer, packet.authority, packet.additional}
    end,
    "lazy_parse + access_all" => fn ->
      packet = DNSpacket.parse_lazy(test_binary)
      packet = packet
               |> DNSpacket.get_questions()
               |> DNSpacket.get_answers()
               |> DNSpacket.get_authority()
               |> DNSpacket.get_additional()
      {packet.question, packet.answer, packet.authority, packet.additional}
    end,
    
    # Partial access patterns (common use case)
    "eager_parse + question_only" => fn ->
      packet = DNSpacket.parse(test_binary)
      packet.question  # Only need questions, but parsed everything
    end,
    "lazy_parse + question_only" => fn ->
      packet = DNSpacket.parse_lazy(test_binary)
      updated_packet = DNSpacket.get_questions(packet)
      updated_packet.question  # Only parse what we need
    end
  },
  time: 2,
  memory_time: 1,
  formatters: [
    Benchee.Formatters.Console
  ]
)

IO.puts("\n=== Memory Usage Analysis ===")

# Memory usage comparison
eager_parsed = DNSpacket.parse(test_binary)
lazy_parsed = DNSpacket.parse_lazy(test_binary)

eager_size = :erts_debug.size(eager_parsed) * :erlang.system_info(:wordsize)
lazy_size = :erts_debug.size(lazy_parsed) * :erlang.system_info(:wordsize)
binary_size = byte_size(test_binary)

IO.puts("Original binary: #{binary_size} bytes")
IO.puts("Eager parsed: #{eager_size} bytes (#{Float.round(eager_size / binary_size, 1)}x expansion)")
IO.puts("Lazy parsed (header only): #{lazy_size} bytes (#{Float.round(lazy_size / binary_size, 1)}x expansion)")
IO.puts("Memory savings: #{eager_size - lazy_size} bytes (#{Float.round((eager_size - lazy_size) / eager_size * 100, 1)}%)")

# Test progressive parsing memory usage
lazy_with_questions = DNSpacket.get_questions(lazy_parsed)
lazy_with_answers = DNSpacket.get_answers(lazy_with_questions)
lazy_fully_parsed = lazy_with_answers
                   |> DNSpacket.get_authority()
                   |> DNSpacket.get_additional()

questions_size = :erts_debug.size(lazy_with_questions) * :erlang.system_info(:wordsize)
answers_size = :erts_debug.size(lazy_with_answers) * :erlang.system_info(:wordsize)
fully_parsed_size = :erts_debug.size(lazy_fully_parsed) * :erlang.system_info(:wordsize)

IO.puts("\nProgressive parsing memory usage:")
IO.puts("Header only: #{lazy_size} bytes")
IO.puts("+ Questions: #{questions_size} bytes")
IO.puts("+ Answers: #{answers_size} bytes") 
IO.puts("+ All sections: #{fully_parsed_size} bytes")

IO.puts("\n=== Use Case Recommendations ===")
IO.puts("• Header inspection only: Use lazy parsing (#{Float.round((eager_size - lazy_size) / eager_size * 100, 1)}% memory savings)")
IO.puts("• Question section only: Use lazy parsing for better memory efficiency")
IO.puts("• Full packet processing: Eager parsing may be faster for complete access")
IO.puts("• Large response handling: Lazy parsing recommended for memory-constrained environments")