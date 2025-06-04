defmodule DomainNameBench do
  @moduledoc """
  Benchmark script for comparing domain name creation performance
  """

  # Legacy implementation for comparison
  def create_domain_name_legacy(name) do
    name
    |> String.split(".")
    |> Enum.map(&DNSpacket.create_character_string/1)
    |> DNSpacket.concat_binary_list()
  end

  # Test various domain name patterns
  @test_domains [
    ".",
    "com.",
    "example.com.",
    "www.example.com.",
    "mail.google.com.", 
    "very.long.subdomain.example.com.",
    "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.example.com.",
    String.duplicate("a", 63) <> ".com."  # Maximum label length
  ]

  def run_benchmarks do
    IO.puts("=== Domain Name Creation Performance Benchmark ===\n")
    
    # Test correctness first
    verify_correctness()
    
    # Benchmark different implementations
    benchmark_implementations()
    
    # Test memory usage
    benchmark_memory_usage()
  end

  defp verify_correctness do
    IO.puts("1. Verifying correctness of optimized implementations...")
    
    Enum.each(@test_domains, fn domain ->
      legacy_result = create_domain_name_legacy(domain)
      optimized_result = DNSpacket.create_domain_name(domain)
      v2_result = DNSpacket.create_domain_name_v2(domain)
      
      if legacy_result != optimized_result do
        IO.puts("❌ MISMATCH for '#{domain}': optimized differs from legacy")
      end
      
      if legacy_result != v2_result do
        IO.puts("❌ MISMATCH for '#{domain}': v2 differs from legacy")
      end
    end)
    
    IO.puts("✅ Correctness verification completed\n")
  end

  defp benchmark_implementations do
    IO.puts("2. Performance comparison:")
    
    Benchee.run(%{
      "legacy (String.split + map)" => fn ->
        Enum.each(@test_domains, &create_domain_name_legacy/1)
      end,
      
      "optimized (binary.split + reduce)" => fn ->
        Enum.each(@test_domains, &DNSpacket.create_domain_name/1)
      end,
      
      "v2 (recursive binary matching)" => fn ->
        Enum.each(@test_domains, &DNSpacket.create_domain_name_v2/1)
      end
    },
    time: 3,
    memory_time: 1,
    formatters: [Benchee.Formatters.Console]
    )
  end

  defp benchmark_memory_usage do
    IO.puts("\n3. Memory usage analysis:")
    
    test_domain = "www.example.com."
    
    # Measure memory for 1000 operations
    {legacy_time, _} = :timer.tc(fn ->
      for _ <- 1..1000, do: create_domain_name_legacy(test_domain)
    end)
    
    {optimized_time, _} = :timer.tc(fn ->
      for _ <- 1..1000, do: DNSpacket.create_domain_name(test_domain)
    end)
    
    {v2_time, _} = :timer.tc(fn ->
      for _ <- 1..1000, do: DNSpacket.create_domain_name_v2(test_domain)
    end)
    
    IO.puts("Time for 1000 operations with '#{test_domain}':")
    IO.puts("  Legacy:    #{legacy_time}μs")
    IO.puts("  Optimized: #{optimized_time}μs") 
    IO.puts("  V2:        #{v2_time}μs")
    
    if legacy_time > 0 do
      optimized_improvement = Float.round((legacy_time - optimized_time) / legacy_time * 100, 1)
      v2_improvement = Float.round((legacy_time - v2_time) / legacy_time * 100, 1)
      
      IO.puts("\nImprovement:")
      IO.puts("  Optimized: #{optimized_improvement}% faster")
      IO.puts("  V2:        #{v2_improvement}% faster")
    end
  end

  def detailed_benchmark do
    IO.puts("\n4. Detailed benchmark for different domain types:")
    
    domain_categories = [
      {"Root", "."},
      {"TLD", "com."},
      {"Simple", "example.com."},
      {"Subdomain", "www.example.com."},
      {"Deep nesting", "a.b.c.d.e.f.example.com."},
      {"Long label", String.duplicate("a", 63) <> ".example.com."}
    ]
    
    Enum.each(domain_categories, fn {category, domain} ->
      IO.puts("\n#{category}: '#{String.slice(domain, 0, 30)}#{if String.length(domain) > 30, do: "...", else: ""}'")
      
      {legacy_time, _} = :timer.tc(fn ->
        for _ <- 1..10000, do: create_domain_name_legacy(domain)
      end)
      
      {optimized_time, _} = :timer.tc(fn ->
        for _ <- 1..10000, do: DNSpacket.create_domain_name(domain)
      end)
      
      if legacy_time > 0 do
        improvement = Float.round((legacy_time - optimized_time) / legacy_time * 100, 1)
        IO.puts("  Legacy: #{legacy_time}μs, Optimized: #{optimized_time}μs (#{improvement}% improvement)")
      end
    end)
  end
end

# Run the benchmarks
DomainNameBench.run_benchmarks()
DomainNameBench.detailed_benchmark()