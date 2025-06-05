defmodule EdnsStructureRedesign do
  @moduledoc """
  Analyze current EDNS structure and propose simpler alternatives
  """

  def run_analysis do
    IO.puts("=== EDNS Structure Redesign Analysis ===\n")
    
    analyze_current_structure()
    propose_flat_structure()
    propose_grouped_structure()
    test_access_patterns()
    test_performance_comparison()
  end

  defp analyze_current_structure do
    IO.puts("1. Current EDNS structure analysis:")
    
    current = create_current_edns()
    IO.puts("  Current structure:")
    IO.puts("    #{inspect(current, pretty: true, limit: :infinity)}")
    
    IO.puts("\n  Access patterns required:")
    IO.puts("    ECS: edns_info[:options][:edns_client_subnet][:family]")
    IO.puts("    Cookie: edns_info[:options][:cookie][:client]")
    IO.puts("    NSID: edns_info[:options][:nsid]")
    IO.puts("    Nested depth: 3 levels")
    IO.puts("    Problems: Deep nesting, complex pattern matching")
  end

  defp propose_flat_structure do
    IO.puts("\n\n2. Proposed flat structure:")
    
    flat = create_flat_edns()
    IO.puts("  Flat structure:")
    IO.puts("    #{inspect(flat, pretty: true, limit: :infinity)}")
    
    IO.puts("\n  Access patterns:")
    IO.puts("    ECS: edns_info[:ecs_family], edns_info[:ecs_subnet]")
    IO.puts("    Cookie: edns_info[:cookie_client]")
    IO.puts("    NSID: edns_info[:nsid]")
    IO.puts("    Nested depth: 1 level")
    IO.puts("    Benefits: Simple access, no deep nesting")
    
    # Show access examples
    IO.puts("\n  Code examples:")
    IO.puts("    # Check for ECS")
    IO.puts("    if edns_info[:ecs_family] do")
    IO.puts("      family = edns_info[:ecs_family]")
    IO.puts("      subnet = edns_info[:ecs_subnet]")
    IO.puts("    end")
    IO.puts("")
    IO.puts("    # Pattern matching")
    IO.puts("    case edns_info do")
    IO.puts("      %{ecs_family: family, ecs_subnet: subnet} -> # with ECS")
    IO.puts("      _ -> # without ECS")
    IO.puts("    end")
  end

  defp propose_grouped_structure do
    IO.puts("\n\n3. Proposed grouped structure:")
    
    grouped = create_grouped_edns()
    IO.puts("  Grouped structure:")
    IO.puts("    #{inspect(grouped, pretty: true, limit: :infinity)}")
    
    IO.puts("\n  Access patterns:")
    IO.puts("    ECS: edns_info[:ecs][:family], edns_info[:ecs][:subnet]")
    IO.puts("    Cookie: edns_info[:cookie][:client]")
    IO.puts("    NSID: edns_info[:nsid]")
    IO.puts("    Nested depth: 2 levels")
    IO.puts("    Benefits: Logical grouping, still simple access")
    
    # Show access examples
    IO.puts("\n  Code examples:")
    IO.puts("    # Check for ECS")
    IO.puts("    case edns_info[:ecs] do")
    IO.puts("      %{family: family, subnet: subnet} -> # with ECS")
    IO.puts("      nil -> # without ECS")
    IO.puts("    end")
    IO.puts("")
    IO.puts("    # With pattern")
    IO.puts("    with %{family: family, subnet: subnet} <- edns_info[:ecs] do")
    IO.puts("      # ECS processing")
    IO.puts("    end")
  end

  defp test_access_patterns do
    IO.puts("\n\n4. Access pattern comparison:")
    
    current = create_current_edns()
    flat = create_flat_edns()
    grouped = create_grouped_edns()
    
    IO.puts("  Current structure access:")
    try do
      result = access_current_ecs(current)
      IO.puts("    ECS access: #{inspect(result)} ✅")
    rescue
      e -> IO.puts("    ECS access: ERROR - #{Exception.message(e)} ❌")
    end
    
    IO.puts("\n  Flat structure access:")
    result = access_flat_ecs(flat)
    IO.puts("    ECS access: #{inspect(result)} ✅")
    
    IO.puts("\n  Grouped structure access:")
    result = access_grouped_ecs(grouped)
    IO.puts("    ECS access: #{inspect(result)} ✅")
    
    # Test with missing data
    IO.puts("\n  Missing ECS data handling:")
    
    current_empty = %{payload_size: 1232, options: %{}}
    flat_empty = %{payload_size: 1232}
    grouped_empty = %{payload_size: 1232}
    
    IO.puts("    Current: #{inspect(access_current_ecs(current_empty))}")
    IO.puts("    Flat:    #{inspect(access_flat_ecs(flat_empty))}")
    IO.puts("    Grouped: #{inspect(access_grouped_ecs(grouped_empty))}")
  end

  defp test_performance_comparison do
    IO.puts("\n\n5. Performance comparison:")
    
    current = create_current_edns()
    flat = create_flat_edns()
    grouped = create_grouped_edns()
    iterations = 100_000
    
    # Test ECS access performance
    {current_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: access_current_ecs(current)
    end)
    
    {flat_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: access_flat_ecs(flat)
    end)
    
    {grouped_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: access_grouped_ecs(grouped)
    end)
    
    IO.puts("  ECS access performance:")
    IO.puts("    Current:  #{current_time}μs (#{Float.round(iterations / current_time * 1_000_000, 0)} ops/sec)")
    IO.puts("    Flat:     #{flat_time}μs (#{Float.round(iterations / flat_time * 1_000_000, 0)} ops/sec)")
    IO.puts("    Grouped:  #{grouped_time}μs (#{Float.round(iterations / grouped_time * 1_000_000, 0)} ops/sec)")
    
    flat_improvement = Float.round((current_time - flat_time) / current_time * 100, 1)
    grouped_improvement = Float.round((current_time - grouped_time) / current_time * 100, 1)
    
    IO.puts("\n  Performance improvements:")
    IO.puts("    Flat:    #{flat_improvement}%")
    IO.puts("    Grouped: #{grouped_improvement}%")
  end

  # Current structure (existing)
  defp create_current_edns do
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
        cookie: %{
          client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
          server: nil
        },
        nsid: "ns1.example.com"
      }
    }
  end

  # Proposed flat structure
  defp create_flat_edns do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      # ECS fields flattened
      ecs_family: 1,
      ecs_subnet: {192, 168, 1, 0},
      ecs_source_prefix: 24,
      ecs_scope_prefix: 0,
      # Cookie fields flattened
      cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
      cookie_server: nil,
      # Other options
      nsid: "ns1.example.com"
    }
  end

  # Proposed grouped structure
  defp create_grouped_edns do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      # Grouped options
      ecs: %{
        family: 1,
        subnet: {192, 168, 1, 0},
        source_prefix: 24,
        scope_prefix: 0
      },
      cookie: %{
        client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        server: nil
      },
      nsid: "ns1.example.com"
    }
  end

  # Access pattern functions
  defp access_current_ecs(edns_info) do
    case edns_info do
      %{options: %{edns_client_subnet: %{family: family, client_subnet: subnet}}} ->
        {:ecs, family, subnet}
      _ ->
        :no_ecs
    end
  end

  defp access_flat_ecs(edns_info) do
    case edns_info do
      %{ecs_family: family, ecs_subnet: subnet} ->
        {:ecs, family, subnet}
      _ ->
        :no_ecs
    end
  end

  defp access_grouped_ecs(edns_info) do
    case edns_info[:ecs] do
      %{family: family, subnet: subnet} ->
        {:ecs, family, subnet}
      _ ->
        :no_ecs
    end
  end
end

EdnsStructureRedesign.run_analysis()