defmodule BinaryConcatTest do
  @moduledoc """
  Test binary concatenation optimization for DNS packet creation
  """

  def run_test do
    IO.puts("=== Binary Concatenation Optimization Test ===\n")
    
    # Test with different approaches
    test_concatenation_methods()
    test_real_world_impact()
  end

  defp test_concatenation_methods do
    IO.puts("1. Testing different binary concatenation methods:")
    
    # Create test data
    header = <<0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00>>
    question = <<7, "example", 3, "com", 0, 0x00, 0x01, 0x00, 0x01>>
    answer1 = <<7, "example", 3, "com", 0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 192, 168, 1, 1>>
    answer2 = <<7, "example", 3, "com", 0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 192, 168, 1, 2>>
    
    iterations = 100_000
    
    # Method 1: IO.iodata_to_binary (current)
    {iodata_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        IO.iodata_to_binary([header, question, answer1, answer2])
      end
    end)
    
    # Method 2: Binary concatenation with <>
    {concat_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        header <> question <> answer1 <> answer2
      end
    end)
    
    # Method 3: Single iolist_to_binary call
    {iolist_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        :erlang.iolist_to_binary([header, question, answer1, answer2])
      end
    end)
    
    # Method 4: Nested binary building
    {nested_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        (header <> question) <> (answer1 <> answer2)
      end
    end)
    
    improvement_iodata = Float.round((iodata_time - concat_time) / iodata_time * 100, 1)
    improvement_iolist = Float.round((iolist_time - concat_time) / iolist_time * 100, 1)
    
    IO.puts("  IO.iodata_to_binary: #{iodata_time}μs (#{Float.round(iterations / iodata_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Binary concat (<>):  #{concat_time}μs (#{Float.round(iterations / concat_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  iolist_to_binary:    #{iolist_time}μs (#{Float.round(iterations / iolist_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Nested concat:       #{nested_time}μs (#{Float.round(iterations / nested_time * 1_000_000, 0)} ops/sec)")
    IO.puts("")
    IO.puts("  Improvement vs iodata: #{improvement_iodata}%")
    IO.puts("  Improvement vs iolist: #{improvement_iolist}%")
    IO.puts("")
  end

  defp test_real_world_impact do
    IO.puts("2. Real-world DNS packet creation impact:")
    
    packet = create_test_packet()
    iterations = 50_000
    
    # Current implementation
    {current_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        DNSpacket.create(packet)
      end
    end)
    
    # Optimized with binary concatenation
    {optimized_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        create_optimized_concat(packet)
      end
    end)
    
    improvement = Float.round((current_time - optimized_time) / current_time * 100, 1)
    
    IO.puts("  Current implementation: #{current_time}μs (#{Float.round(iterations / current_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Binary concat optimized: #{optimized_time}μs (#{Float.round(iterations / optimized_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Real-world improvement: #{improvement}%")
    
    # Verify correctness
    current_result = DNSpacket.create(packet)
    optimized_result = create_optimized_concat(packet)
    
    IO.puts("  Results match: #{current_result == optimized_result}")
  end

  # Optimized create function using binary concatenation
  defp create_optimized_concat(packet) do
    # If edns_info exists, create OPT record from it and add to additional section
    additional_with_edns = merge_edns_info_to_additional(packet.additional, packet.edns_info)

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
               length(packet.question)       ::16,
               length(packet.answer)         ::16,
               length(packet.authority)      ::16,
               length(additional_with_edns)  ::16>>

    # Use binary concatenation instead of IO.iodata_to_binary
    header <>
    create_question_concat(packet.question) <>
    create_answer_concat(packet.answer) <>
    create_answer_concat(packet.authority) <>
    create_answer_concat(additional_with_edns)
  end

  defp create_question_concat(question) do
    question
    |> Enum.map(&DNSpacket.create_question_item/1)
    |> Enum.reduce(<<>>, fn item, acc -> acc <> item end)
  end

  defp create_answer_concat(answer) do
    answer
    |> Enum.map(&DNSpacket.create_rr/1)
    |> Enum.reduce(<<>>, fn item, acc -> acc <> item end)
  end

  # Copy of merge_edns_info_to_additional for standalone testing
  defp merge_edns_info_to_additional(additional, nil), do: additional

  defp merge_edns_info_to_additional(additional, edns_info) do
    # Remove any existing OPT records from additional section
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))

    # Create new OPT record from edns_info
    opt_record = create_edns_info_record(edns_info)

    # Add the new OPT record to the additional section
    [opt_record | non_opt_records]
  end

  defp create_edns_info_record(%{} = edns_info) do
    payload_size = Map.get(edns_info, :payload_size, 1232)
    ex_rcode = Map.get(edns_info, :ex_rcode, 0)
    version = Map.get(edns_info, :version, 0)
    dnssec = Map.get(edns_info, :dnssec, 0)
    z = Map.get(edns_info, :z, 0)
    options = Map.get(edns_info, :options, %{})

    %{
      name: "",
      type: :opt,
      payload_size: payload_size,
      ex_rcode: ex_rcode,
      version: version,
      dnssec: dnssec,
      z: z,
      rdata: convert_options_to_rdata(options)
    }
  end

  defp convert_options_to_rdata(%{} = _options) do
    # Simplified for testing
    []
  end

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
end

BinaryConcatTest.run_test()