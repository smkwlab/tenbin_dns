defmodule CreateOptimizationBench do
  @moduledoc """
  Detailed analysis of DNS packet creation performance bottlenecks
  """

  def run_analysis do
    IO.puts("=== DNS Packet Creation Performance Analysis ===\n")
    
    # 1. Break down create operation into components
    analyze_create_components()
    
    # 2. Compare different packet types
    analyze_packet_types()
    
    # 3. Identify specific bottlenecks
    analyze_bottlenecks()
    
    # 4. Test optimization opportunities
    test_optimizations()
  end

  defp analyze_create_components do
    IO.puts("1. Breaking down create operation components:")
    
    # Create test packet
    packet = create_test_packet()
    iterations = 50_000
    
    # Measure individual components
    
    # 1. Header creation
    {header_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        create_header_only(packet)
      end
    end)
    
    # 2. Question section creation
    {question_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        DNSpacket.create_question(packet.question)
      end
    end)
    
    # 3. Answer section creation
    {answer_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        DNSpacket.create_answer(packet.answer)
      end
    end)
    
    # 4. Full packet creation
    {full_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        DNSpacket.create(packet)
      end
    end)
    
    # 5. Final IO.iodata_to_binary call
    header = create_header_only(packet)
    question_bin = DNSpacket.create_question(packet.question)
    answer_bin = DNSpacket.create_answer(packet.answer)
    
    {binary_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        IO.iodata_to_binary([header, question_bin, answer_bin, <<>>, <<>>])
      end
    end)
    
    component_total = header_time + question_time + answer_time + binary_time
    overhead = full_time - component_total
    
    IO.puts("  Header creation:     #{header_time}μs (#{Float.round(iterations / header_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Question creation:   #{question_time}μs (#{Float.round(iterations / question_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Answer creation:     #{answer_time}μs (#{Float.round(iterations / answer_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Binary conversion:   #{binary_time}μs (#{Float.round(iterations / binary_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Full packet:         #{full_time}μs (#{Float.round(iterations / full_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Component sum:       #{component_total}μs")
    IO.puts("  Overhead:            #{overhead}μs (#{Float.round(overhead / full_time * 100, 1)}%)")
    IO.puts("")
  end

  defp analyze_packet_types do
    IO.puts("2. Performance by packet type:")
    
    packets = [
      {"Simple A record", create_simple_a_packet()},
      {"Multiple A records", create_multi_a_packet()},
      {"Mixed record types", create_mixed_packet()},
      {"EDNS packet", create_edns_packet()},
      {"Large packet", create_large_packet()}
    ]
    
    iterations = 20_000
    
    Enum.each(packets, fn {name, packet} ->
      {create_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: DNSpacket.create(packet)
      end)
      
      {parse_time, _} = :timer.tc(fn ->
        binary = DNSpacket.create(packet)
        for _ <- 1..iterations, do: DNSpacket.parse(binary)
      end)
      
      ratio = create_time / parse_time
      packet_size = byte_size(DNSpacket.create(packet))
      
      IO.puts("  #{name}:")
      IO.puts("    Create: #{create_time}μs (#{Float.round(iterations / create_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Parse:  #{parse_time}μs (#{Float.round(iterations / parse_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Ratio:  #{Float.round(ratio, 2)}x slower")
      IO.puts("    Size:   #{packet_size} bytes")
    end)
    IO.puts("")
  end

  defp analyze_bottlenecks do
    IO.puts("3. Specific bottleneck analysis:")
    
    packet = create_test_packet()
    iterations = 30_000
    
    # Test domain name creation overhead
    domains = Enum.map(packet.answer, &(&1.name))
    {domain_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.each(domains, &DNSpacket.create_domain_name/1)
      end
    end)
    
    # Test rdata creation overhead
    rdata_list = Enum.map(packet.answer, fn rr -> {rr.rdata, rr.type, rr.class} end)
    {rdata_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.each(rdata_list, fn {rdata, type, class} ->
          DNSpacket.create_rdata(rdata, type, class)
        end)
      end
    end)
    
    # Test Enum.map vs for comprehension
    {enum_map_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.map(packet.answer, &DNSpacket.create_rr/1)
      end
    end)
    
    {comprehension_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        for rr <- packet.answer, do: DNSpacket.create_rr(rr)
      end
    end)
    
    IO.puts("  Domain name creation: #{domain_time}μs (#{Float.round(iterations / domain_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  RDATA creation:       #{rdata_time}μs (#{Float.round(iterations / rdata_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Enum.map RR:          #{enum_map_time}μs (#{Float.round(iterations / enum_map_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Comprehension RR:     #{comprehension_time}μs (#{Float.round(iterations / comprehension_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Map vs comprehension: #{Float.round((enum_map_time - comprehension_time) / enum_map_time * 100, 1)}% overhead")
    IO.puts("")
  end

  defp test_optimizations do
    IO.puts("4. Testing optimization opportunities:")
    
    packet = create_test_packet()
    iterations = 25_000
    
    # Test pre-calculated lengths
    {original_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(packet)
    end)
    
    {optimized_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: create_optimized(packet)
    end)
    
    # Test binary concatenation vs iodata
    question_bin = DNSpacket.create_question(packet.question)
    answer_bin = DNSpacket.create_answer(packet.answer)
    header = create_header_only(packet)
    
    {iodata_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        IO.iodata_to_binary([header, question_bin, answer_bin, <<>>, <<>>])
      end
    end)
    
    {concat_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        header <> question_bin <> answer_bin <> <<>> <> <<>>
      end
    end)
    
    improvement = Float.round((original_time - optimized_time) / original_time * 100, 1)
    binary_improvement = Float.round((concat_time - iodata_time) / concat_time * 100, 1)
    
    IO.puts("  Original create:      #{original_time}μs (#{Float.round(iterations / original_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Optimized create:     #{optimized_time}μs (#{Float.round(iterations / optimized_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Improvement:          #{improvement}%")
    IO.puts("")
    IO.puts("  IO.iodata_to_binary:  #{iodata_time}μs (#{Float.round(iterations / iodata_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Binary concatenation: #{concat_time}μs (#{Float.round(iterations / concat_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Iodata advantage:     #{binary_improvement}%")
  end

  # Optimized create function for testing
  defp create_optimized(packet) do
    # Pre-calculate lengths to avoid multiple length() calls
    question_count = length(packet.question)
    answer_count = length(packet.answer)
    authority_count = length(packet.authority)
    additional_count = length(packet.additional)
    
    # Create sections
    question_bin = DNSpacket.create_question(packet.question)
    answer_bin = DNSpacket.create_answer(packet.answer)
    authority_bin = DNSpacket.create_answer(packet.authority)
    additional_bin = DNSpacket.create_answer(packet.additional)
    
    # Create header with pre-calculated counts
    header = <<packet.id                     ::16,
               packet.qr                     ::1,
               packet.opcode                 ::4,
               packet.aa                     ::1,
               packet.tc                     ::1,
               packet.rd                     ::1,
               packet.ra                     ::1,
               packet.z                      ::1,
               packet.ad                     ::1,
               packet.cd                     ::1,
               packet.rcode                  ::4,
               question_count                ::16,
               answer_count                  ::16,
               authority_count               ::16,
               additional_count              ::16>>
    
    # Use iodata for efficient concatenation
    IO.iodata_to_binary([header, question_bin, answer_bin, authority_bin, additional_bin])
  end

  defp create_header_only(packet) do
    <<packet.id                     ::16,
      packet.qr                     ::1,
      packet.opcode                 ::4,
      packet.aa                     ::1,
      packet.tc                     ::1,
      packet.rd                     ::1,
      packet.ra                     ::1,
      packet.z                      ::1,
      packet.ad                     ::1,
      packet.cd                     ::1,
      packet.rcode                  ::4,
      length(packet.question)       ::16,
      length(packet.answer)         ::16,
      length(packet.authority)      ::16,
      length(packet.additional)     ::16>>
  end

  # Test packet generators
  defp create_test_packet do
    %DNSpacket{
      id: 0x1234,
      qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}},
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 217, 34}}}
      ]
    }
  end

  defp create_simple_a_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "test.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "test.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}]
    }
  end

  defp create_multi_a_packet do
    answers = for i <- 1..5 do
      %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, i}}}
    end
    
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: answers
    }
  end

  defp create_mixed_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :any, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}},
        %{name: "example.com.", type: :aaaa, class: :in, ttl: 300, 
          rdata: %{addr: {0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946}}},
        %{name: "example.com.", type: :mx, class: :in, ttl: 300, 
          rdata: %{preference: 10, name: "mail.example.com."}}
      ]
    }
  end

  defp create_edns_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}],
      edns_info: %{
        payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0,
        options: %{}
      }
    }
  end

  defp create_large_packet do
    answers = for i <- 1..20 do
      %{name: "example#{i}.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, div(i, 256), rem(i, 256)}}}
    end
    
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: answers
    }
  end
end

CreateOptimizationBench.run_analysis()