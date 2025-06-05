defmodule EdnsInfoAccessTest do
  @moduledoc """
  Test different approaches to accessing EDNS Client Subnet information
  """

  def run_test do
    IO.puts("=== EDNS Info Access Pattern Test ===\n")
    
    test_access_patterns()
    test_edge_cases()
    test_performance()
  end

  defp test_access_patterns do
    IO.puts("1. Testing different access patterns:")
    
    # Test cases with different EDNS structures
    test_cases = [
      {"No EDNS", nil},
      {"Empty EDNS", %{options: %{}}},
      {"EDNS with ECS", create_edns_with_ecs()},
      {"EDNS with other options", create_edns_with_other_options()},
      {"EDNS with multiple options", create_edns_with_multiple_options()}
    ]
    
    Enum.each(test_cases, fn {name, edns_info} ->
      IO.puts("\n  #{name}:")
      
      # Test the user's proposed pattern
      result1 = test_user_pattern(edns_info)
      IO.puts("    User pattern result: #{inspect(result1)}")
      
      # Test improved patterns
      result2 = test_safe_pattern(edns_info)
      IO.puts("    Safe pattern result: #{inspect(result2)}")
      
      result3 = test_with_pattern(edns_info)
      IO.puts("    With pattern result: #{inspect(result3)}")
      
      result4 = test_get_in_pattern(edns_info)
      IO.puts("    get_in pattern result: #{inspect(result4)}")
    end)
  end

  defp test_edge_cases do
    IO.puts("\n\n2. Edge case handling:")
    
    edge_cases = [
      {"Nil options", %{options: nil}},
      {"String instead of map", %{options: "invalid"}},
      {"ECS with missing fields", %{options: %{edns_client_subnet: %{family: 1}}}},
      {"ECS with nil values", %{options: %{edns_client_subnet: %{family: 1, client_subnet: nil}}}},
      {"Deep nesting issue", %{options: %{other: %{nested: %{edns_client_subnet: %{family: 1}}}}}},
    ]
    
    Enum.each(edge_cases, fn {name, edns_info} ->
      IO.puts("\n  #{name}:")
      
      try do
        result = test_user_pattern(edns_info)
        IO.puts("    User pattern: #{inspect(result)} ✅")
      rescue
        e -> IO.puts("    User pattern: ERROR - #{Exception.message(e)} ❌")
      end
      
      try do
        result = test_safe_pattern(edns_info)
        IO.puts("    Safe pattern: #{inspect(result)} ✅")
      rescue
        e -> IO.puts("    Safe pattern: ERROR - #{Exception.message(e)} ❌")
      end
    end)
  end

  defp test_performance do
    IO.puts("\n\n3. Performance comparison:")
    
    edns_with_ecs = create_edns_with_ecs()
    edns_without_ecs = %{options: %{}}
    iterations = 100_000
    
    # Test with ECS present
    {user_time_with, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: test_user_pattern(edns_with_ecs)
    end)
    
    {safe_time_with, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: test_safe_pattern(edns_with_ecs)
    end)
    
    {with_time_with, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: test_with_pattern(edns_with_ecs)
    end)
    
    # Test without ECS
    {user_time_without, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: test_user_pattern(edns_without_ecs)
    end)
    
    {safe_time_without, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: test_safe_pattern(edns_without_ecs)
    end)
    
    IO.puts("  With ECS present:")
    IO.puts("    User pattern:  #{user_time_with}μs (#{Float.round(iterations / user_time_with * 1_000_000, 0)} ops/sec)")
    IO.puts("    Safe pattern:  #{safe_time_with}μs (#{Float.round(iterations / safe_time_with * 1_000_000, 0)} ops/sec)")
    IO.puts("    With pattern:  #{with_time_with}μs (#{Float.round(iterations / with_time_with * 1_000_000, 0)} ops/sec)")
    
    IO.puts("\n  Without ECS:")
    IO.puts("    User pattern:  #{user_time_without}μs (#{Float.round(iterations / user_time_without * 1_000_000, 0)} ops/sec)")
    IO.puts("    Safe pattern:  #{safe_time_without}μs (#{Float.round(iterations / safe_time_without * 1_000_000, 0)} ops/sec)")
  end

  # User's proposed pattern
  defp test_user_pattern(edns_info) do
    case edns_info do
      %{options: %{edns_client_subnet: ecs}} ->
        family = ecs.family
        addr = ecs.client_subnet
        source = ecs.source_prefix
        scope = ecs.scope_prefix
        
        {:ecs, family, addr, source, scope}
        
      _ ->
        :no_ecs
    end
  end

  # Safer pattern with additional checks
  defp test_safe_pattern(edns_info) do
    case edns_info do
      %{options: %{edns_client_subnet: %{family: family, client_subnet: addr, 
                                        source_prefix: source, scope_prefix: scope}}} ->
        {:ecs, family, addr, source, scope}
        
      _ ->
        :no_ecs
    end
  end

  # Using with pattern for safer access
  defp test_with_pattern(edns_info) do
    with %{options: options} <- edns_info,
         %{edns_client_subnet: ecs} <- options,
         %{family: family, client_subnet: addr, source_prefix: source, scope_prefix: scope} <- ecs do
      {:ecs, family, addr, source, scope}
    else
      _ -> :no_ecs
    end
  end

  # Using get_in for safer nested access
  defp test_get_in_pattern(edns_info) do
    case get_in(edns_info, [:options, :edns_client_subnet]) do
      %{family: family, client_subnet: addr, source_prefix: source, scope_prefix: scope} ->
        {:ecs, family, addr, source, scope}
      _ ->
        :no_ecs
    end
  end

  # Test data generators
  defp create_edns_with_ecs do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      options: %{
        edns_client_subnet: %{
          family: 1,
          client_subnet: {192, 168, 1, 0},
          source_prefix: 24,
          scope_prefix: 0
        }
      }
    }
  end

  defp create_edns_with_other_options do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      options: %{
        cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil},
        nsid: "ns1.example.com"
      }
    }
  end

  defp create_edns_with_multiple_options do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      options: %{
        edns_client_subnet: %{
          family: 1,
          client_subnet: {192, 168, 1, 0},
          source_prefix: 24,
          scope_prefix: 0
        },
        cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil},
        nsid: "ns1.example.com"
      }
    }
  end
end

EdnsInfoAccessTest.run_test()