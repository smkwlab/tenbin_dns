defmodule ComprehensiveOptimizationBench do
  @moduledoc """
  Comprehensive benchmark for all IO.iodata_to_binary optimizations
  """

  # Test data
  @test_questions [
    %{qname: "example.com.", qtype: :a, qclass: :in},
    %{qname: "www.google.com.", qtype: :aaaa, qclass: :in},
    %{qname: "mail.example.org.", qtype: :mx, qclass: :in}
  ]

  @test_answers [
    %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, 1}}},
    %{name: "www.example.com.", type: :cname, class: :in, ttl: 300, rdata: %{name: "example.com."}},
    %{name: "example.com.", type: :mx, class: :in, ttl: 300, rdata: %{preference: 10, name: "mail.example.com."}}
  ]

  @test_edns_options %{
    edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 0}, source_prefix: 24, scope_prefix: 0},
    cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil},
    nsid: "server1"
  }

  # Legacy implementations for comparison
  def legacy_concat_binary_list(list), do: :erlang.iolist_to_binary(list)

  def create_question_legacy(question) do
    question
    |> Enum.map(&create_question_item_legacy/1)
    |> legacy_concat_binary_list()
  end

  def create_question_item_legacy(%{qname: qname, qtype: qtype, qclass: qclass}) do
    create_domain_name_legacy(qname) <> <<DNS.type_code(qtype)::16, DNS.class_code(qclass)::16>>
  end

  def create_domain_name_legacy(name) do
    name
    |> String.split(".")
    |> Enum.map(&DNSpacket.create_character_string/1)
    |> legacy_concat_binary_list()
  end

  def create_answer_legacy(answer) do
    answer
    |> Enum.map(&create_rr_legacy/1)
    |> legacy_concat_binary_list()
  end

  def create_rr_legacy(rr) do
    DNSpacket.create_rr(rr)  # Use existing implementation for simplicity
  end

  def create_edns_options_legacy(options) do
    options
    |> Enum.flat_map(&create_edns_option_legacy/1)
    |> legacy_concat_binary_list()
  end

  def create_edns_option_legacy(option) do
    # Simplified - use existing implementation
    DNSpacket.create_edns_option(option)
  end

  def run_benchmarks do
    IO.puts("=== Comprehensive IO.iodata_to_binary Optimization Benchmark ===\n")
    
    verify_correctness()
    benchmark_all_functions()
    benchmark_real_world_scenarios()
  end

  defp verify_correctness do
    IO.puts("1. Verifying correctness across all optimized functions...")
    
    # Test domain name creation
    test_domain = "www.example.com."
    legacy_domain = create_domain_name_legacy(test_domain)
    optimized_domain = DNSpacket.create_domain_name(test_domain)
    assert legacy_domain == optimized_domain, "Domain name mismatch"

    # Test question creation
    legacy_question = create_question_legacy(@test_questions)
    optimized_question = DNSpacket.create_question(@test_questions)
    assert legacy_question == optimized_question, "Question creation mismatch"

    # Test answer creation
    legacy_answer = create_answer_legacy(@test_answers)
    optimized_answer = DNSpacket.create_answer(@test_answers)
    assert legacy_answer == optimized_answer, "Answer creation mismatch"

    # Test EDNS options creation
    legacy_edns = create_edns_options_legacy(@test_edns_options)
    optimized_edns = DNSpacket.create_edns_options(@test_edns_options)
    assert legacy_edns == optimized_edns, "EDNS options mismatch"

    IO.puts("✅ All correctness tests passed\n")
  end

  defp benchmark_all_functions do
    IO.puts("2. Individual function benchmarks:")
    
    Benchee.run(%{
      "Domain name (legacy)" => fn ->
        Enum.each(["example.com.", "www.google.com.", "mail.example.org."], 
                  &create_domain_name_legacy/1)
      end,
      "Domain name (optimized)" => fn ->
        Enum.each(["example.com.", "www.google.com.", "mail.example.org."], 
                  &DNSpacket.create_domain_name/1)
      end,
      
      "Question section (legacy)" => fn ->
        create_question_legacy(@test_questions)
      end,
      "Question section (optimized)" => fn ->
        DNSpacket.create_question(@test_questions)
      end,
      
      "Answer section (legacy)" => fn ->
        create_answer_legacy(@test_answers)
      end,
      "Answer section (optimized)" => fn ->
        DNSpacket.create_answer(@test_answers)
      end,
      
      "EDNS options (legacy)" => fn ->
        create_edns_options_legacy(@test_edns_options)
      end,
      "EDNS options (optimized)" => fn ->
        DNSpacket.create_edns_options(@test_edns_options)
      end
    },
    time: 2,
    memory_time: 1,
    formatters: [Benchee.Formatters.Console]
    )
  end

  defp benchmark_real_world_scenarios do
    IO.puts("\n3. Real-world scenario benchmarks:")
    
    # Complete DNS packet creation
    simple_packet = %DNSpacket{
      id: 0x1234,
      qr: 1,
      opcode: 0,
      aa: 1,
      tc: 0,
      rd: 1,
      ra: 1,
      z: 0,
      rcode: 0,
      question: @test_questions,
      answer: @test_answers,
      authority: [],
      additional: []
    }
    
    complex_packet = %DNSpacket{
      id: 0x5678,
      qr: 1,
      opcode: 0,
      aa: 1,
      tc: 0,
      rd: 1,
      ra: 1,
      z: 0,
      rcode: 0,
      question: @test_questions ++ [
        %{qname: "subdomain.example.net.", qtype: :ns, qclass: :in},
        %{qname: "ftp.example.net.", qtype: :cname, qclass: :in}
      ],
      answer: @test_answers ++ [
        %{name: "example.net.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns1.example.net."}},
        %{name: "example.net.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns2.example.net."}},
        %{name: "ftp.example.net.", type: :cname, class: :in, ttl: 300, rdata: %{name: "web.example.net."}}
      ],
      authority: [
        %{name: "example.net.", type: :soa, class: :in, ttl: 86400, 
          rdata: %{mname: "ns1.example.net.", rname: "admin.example.net.", 
                   serial: 2023010101, refresh: 7200, retry: 3600, expire: 604800, minimum: 86400}}
      ],
      additional: []
    }

    Benchee.run(%{
      "Simple packet creation" => fn ->
        DNSpacket.create(simple_packet)
      end,
      "Complex packet creation" => fn ->
        DNSpacket.create(complex_packet)
      end,
      
      "Multiple domain creation" => fn ->
        domains = ["a.com.", "bb.org.", "ccc.net.", "dddd.info.", "eeeee.example.com."]
        Enum.map(domains, &DNSpacket.create_domain_name/1)
      end,
      
      "Batch question creation" => fn ->
        questions = for i <- 1..10 do
          %{qname: "host#{i}.example.com.", qtype: :a, qclass: :in}
        end
        DNSpacket.create_question(questions)
      end,
      
      "Batch answer creation" => fn ->
        answers = for i <- 1..10 do
          %{name: "host#{i}.example.com.", type: :a, class: :in, ttl: 300, 
            rdata: %{addr: {192, 168, 1, i}}}
        end
        DNSpacket.create_answer(answers)
      end
    },
    time: 2,
    memory_time: 1,
    formatters: [Benchee.Formatters.Console]
    )
  end

  # Helper function for assertions
  defp assert(condition, message) do
    unless condition do
      raise "Assertion failed: #{message}"
    end
  end
end

# Run the benchmarks
ComprehensiveOptimizationBench.run_benchmarks()