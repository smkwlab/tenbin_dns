defmodule LengthAlternativesBench do
  @moduledoc """
  Benchmark different approaches to getting list length in Elixir
  """

  def run_benchmark do
    IO.puts("=== Length Function Alternatives Benchmark ===\n")
    
    test_length_functions()
    test_with_different_sizes()
    test_real_world_scenario()
  end

  defp test_length_functions do
    IO.puts("1. Comparing length calculation methods:")
    
    lists = [
      {"Empty list", []},
      {"Small list (1)", [%{name: "test.com.", type: :a}]},
      {"Medium list (5)", create_list(5)},
      {"Large list (20)", create_list(20)},
      {"Very large list (100)", create_list(100)}
    ]
    
    iterations = 100_000
    
    Enum.each(lists, fn {name, list} ->
      IO.puts("\n  #{name} (#{length(list)} items):")
      
      # Standard length/1
      {length_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: length(list)
      end)
      
      # Kernel.length/1 (explicit)
      {kernel_length_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: Kernel.length(list)
      end)
      
      # Enum.count/1
      {enum_count_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: Enum.count(list)
      end)
      
      # Pattern matching approach (for known sizes)
      {pattern_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: get_length_pattern(list)
      end)
      
      IO.puts("    length/1:        #{length_time}μs (#{Float.round(iterations / length_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Kernel.length/1: #{kernel_length_time}μs (#{Float.round(iterations / kernel_length_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Enum.count/1:    #{enum_count_time}μs (#{Float.round(iterations / enum_count_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Pattern match:   #{pattern_time}μs (#{Float.round(iterations / pattern_time * 1_000_000, 0)} ops/sec)")
      
      # Calculate relative performance
      if length_time > 0 do
        enum_overhead = Float.round((enum_count_time - length_time) / length_time * 100, 1)
        pattern_overhead = Float.round((pattern_time - length_time) / length_time * 100, 1)
        IO.puts("    Enum.count overhead: #{enum_overhead}%")
        IO.puts("    Pattern overhead:    #{pattern_overhead}%")
      end
    end)
  end

  defp test_with_different_sizes do
    IO.puts("\n\n2. Performance scaling with list size:")
    
    sizes = [0, 1, 2, 3, 4, 5, 10, 20, 50, 100]
    iterations = 50_000
    
    length_times = Enum.map(sizes, fn size ->
      list = create_list(size)
      {time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: length(list)
      end)
      time / iterations  # Average time per operation
    end)
    
    IO.puts("  Size | Avg time per op (μs) | Ops/sec")
    IO.puts("  -----|---------------------|----------")
    Enum.zip(sizes, length_times)
    |> Enum.each(fn {size, avg_time} ->
      ops_per_sec = if avg_time > 0, do: Float.round(1_000_000 / avg_time, 0), else: 0
      IO.puts("  #{String.pad_leading(Integer.to_string(size), 4)} | #{String.pad_leading(Float.to_string(Float.round(avg_time, 3)), 19)} | #{ops_per_sec}")
    end)
    
    # Check if it's O(n)
    if length(sizes) > 1 do
      [first_time | rest_times] = length_times
      [first_size | rest_sizes] = sizes
      
      is_constant = Enum.all?(rest_times, fn time ->
        abs(time - first_time) < 0.1  # Within 0.1 microsecond
      end)
      
      if is_constant do
        IO.puts("\n  ✅ length/1 appears to be O(1) - constant time!")
      else
        IO.puts("\n  ⚠️  length/1 appears to be O(n) - linear time!")
      end
    end
  end

  defp test_real_world_scenario do
    IO.puts("\n\n3. Real-world DNS packet scenario:")
    
    packet = %{
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: create_list(5),
      authority: [],
      additional: []
    }
    
    iterations = 100_000
    
    # Test current approach (multiple length calls)
    {multiple_calls_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        _ = length(packet.question)
        _ = length(packet.answer)
        _ = length(packet.authority)
        _ = length(packet.additional)
      end
    end)
    
    # Test with pre-calculation
    {precalc_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        q_len = length(packet.question)
        a_len = length(packet.answer)
        au_len = length(packet.authority)
        ad_len = length(packet.additional)
        _ = {q_len, a_len, au_len, ad_len}
      end
    end)
    
    # Test with tuple storage (alternative data structure)
    packet_with_counts = {
      packet.question, 1,
      packet.answer, 5,
      packet.authority, 0,
      packet.additional, 0
    }
    
    {tuple_access_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        {_, q_len, _, a_len, _, au_len, _, ad_len} = packet_with_counts
        _ = {q_len, a_len, au_len, ad_len}
      end
    end)
    
    IO.puts("  Multiple length calls: #{multiple_calls_time}μs (#{Float.round(iterations / multiple_calls_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Pre-calculated:        #{precalc_time}μs (#{Float.round(iterations / precalc_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Tuple with counts:     #{tuple_access_time}μs (#{Float.round(iterations / tuple_access_time * 1_000_000, 0)} ops/sec)")
    
    IO.puts("\n  Pre-calc improvement: #{Float.round((multiple_calls_time - precalc_time) / multiple_calls_time * 100, 1)}%")
    IO.puts("  Tuple improvement:    #{Float.round((multiple_calls_time - tuple_access_time) / multiple_calls_time * 100, 1)}%")
  end

  # Helper functions
  defp create_list(n) do
    for i <- 1..n do
      %{name: "example#{i}.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, i}}}
    end
  end

  defp get_length_pattern([]), do: 0
  defp get_length_pattern([_]), do: 1
  defp get_length_pattern([_, _]), do: 2
  defp get_length_pattern([_, _, _]), do: 3
  defp get_length_pattern([_, _, _, _]), do: 4
  defp get_length_pattern([_, _, _, _, _]), do: 5
  defp get_length_pattern(list), do: length(list)
end

LengthAlternativesBench.run_benchmark()