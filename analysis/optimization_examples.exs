defmodule OptimizationExamples do
  @moduledoc """
  Specific implementation examples for DNS library optimizations
  """

  # Example 1: Optimized Domain Name Processing
  def create_domain_name_current(name) do
    name
    |> String.split(".")
    |> Enum.map(&create_character_string/1)
    |> DNSpacket.concat_binary_list()
  end

  def create_domain_name_optimized_v1(name) do
    # Use :binary.split instead of String.split (faster for simple cases)
    name
    |> :binary.split(".", [:global])
    |> Enum.reduce([], fn label, acc ->
      [acc, <<byte_size(label)::8>>, label]
    end)
    |> :erlang.iolist_to_binary()
  end

  def create_domain_name_optimized_v2(name) do
    # Even more optimized - direct binary construction
    do_create_domain_name(name, 0, byte_size(name), [])
  end

  defp do_create_domain_name(binary, pos, size, acc) when pos >= size do
    :erlang.iolist_to_binary(acc)
  end

  defp do_create_domain_name(binary, pos, size, acc) do
    case :binary.match(binary, ".", scope: {pos, size - pos}) do
      {dot_pos, 1} ->
        label_len = dot_pos - pos
        label = :binary.part(binary, pos, label_len)
        new_acc = [acc, <<label_len::8>>, label]
        do_create_domain_name(binary, dot_pos + 1, size, new_acc)
      
      :nomatch ->
        label_len = size - pos
        label = :binary.part(binary, pos, label_len)
        :erlang.iolist_to_binary([acc, <<label_len::8>>, label])
    end
  end

  # Example 2: Specialized Record Creation Functions
  @compile {:inline, [
    create_a_record_fast: 1,
    create_aaaa_record_fast: 1,
    create_mx_record_fast: 2,
    create_ns_record_fast: 1
  ]}

  def create_a_record_fast({a, b, c, d}) do
    <<a::8, b::8, c::8, d::8>>
  end

  def create_aaaa_record_fast({a1, a2, a3, a4, a5, a6, a7, a8}) do
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
  end

  def create_mx_record_fast(preference, name) do
    [<<preference::16>>, create_domain_name_optimized_v2(name)]
  end

  def create_ns_record_fast(name) do
    create_domain_name_optimized_v2(name)
  end

  # Example 3: Optimized Packet Creation with IO Lists
  def create_packet_optimized(packet) do
    header = create_header_iolist(packet)
    
    [
      header,
      create_questions_iolist(packet.question),
      create_records_iolist(packet.answer),
      create_records_iolist(packet.authority),
      create_records_iolist(packet.additional)
    ]
    |> :erlang.iolist_to_binary()
  end

  defp create_header_iolist(packet) do
    <<packet.id::16,
      packet.qr::1,
      packet.opcode::4,
      packet.aa::1,
      packet.tc::1,
      packet.rd::1,
      packet.ra::1,
      packet.z::1,
      packet.ad::1,
      packet.cd::1,
      packet.rcode::4,
      length(packet.question)::16,
      length(packet.answer)::16,
      length(packet.authority)::16,
      length(packet.additional)::16>>
  end

  defp create_questions_iolist(questions) do
    Enum.map(questions, &create_question_iolist/1)
  end

  defp create_question_iolist(%{qname: qname, qtype: qtype, qclass: qclass}) do
    [
      create_domain_name_optimized_v2(qname),
      <<DNS.type_code(qtype)::16, DNS.class_code(qclass)::16>>
    ]
  end

  defp create_records_iolist(records) do
    Enum.map(records, &create_record_iolist/1)
  end

  defp create_record_iolist(%{type: :opt} = rr) do
    rdata_iolist = create_opt_rdata_iolist(rr.rdata)
    rdata_binary = :erlang.iolist_to_binary(rdata_iolist)
    
    [
      <<0>>, # Root domain for OPT
      <<DNS.type_code(:opt)::16>>,
      <<rr.payload_size::16>>,
      <<rr.ex_rcode::8>>,
      <<rr.version::8>>,
      <<rr.dnssec::1, rr.z::15>>,
      <<byte_size(rdata_binary)::16>>,
      rdata_binary
    ]
  end

  defp create_record_iolist(rr) do
    rdata_iolist = create_rdata_iolist(rr.rdata, rr.type, rr.class)
    rdata_binary = :erlang.iolist_to_binary(rdata_iolist)
    
    [
      create_domain_name_optimized_v2(rr.name),
      <<DNS.type_code(rr.type)::16>>,
      <<DNS.class_code(rr.class)::16>>,
      <<rr.ttl::32>>,
      <<byte_size(rdata_binary)::16>>,
      rdata_binary
    ]
  end

  # Example 4: Specialized RDATA Creation
  defp create_rdata_iolist(%{addr: addr}, :a, :in) do
    [create_a_record_fast(addr)]
  end

  defp create_rdata_iolist(%{addr: addr}, :aaaa, :in) do
    [create_aaaa_record_fast(addr)]
  end

  defp create_rdata_iolist(%{preference: pref, name: name}, :mx, _) do
    create_mx_record_fast(pref, name)
  end

  defp create_rdata_iolist(%{name: name}, type, _) 
       when type in [:ns, :cname, :ptr] do
    [create_ns_record_fast(name)]
  end

  defp create_rdata_iolist(%{txt: txt}, :txt, _) do
    [<<byte_size(txt)::8>>, txt]
  end

  defp create_rdata_iolist(rdata, type, class) do
    # Fallback to original implementation
    DNSpacket.create_rdata(rdata, type, class)
  end

  defp create_opt_rdata_iolist(rdata_list) do
    Enum.map(rdata_list, &create_opt_option_iolist/1)
  end

  defp create_opt_option_iolist(%{code: code, data: data}) do
    [
      <<DNS.option_code(code)::16>>,
      <<byte_size(data)::16>>,
      data
    ]
  end

  # Example 5: Optimized Parsing with Pattern Matching
  def parse_rdata_optimized(rdata, type, class, orig_body) do
    case {type, class} do
      {:a, :in} -> parse_a_record_fast(rdata)
      {:aaaa, :in} -> parse_aaaa_record_fast(rdata)
      {:mx, _} -> parse_mx_record_fast(rdata, orig_body)
      {:ns, _} -> parse_ns_record_fast(rdata, orig_body)
      {:cname, _} -> parse_cname_record_fast(rdata, orig_body)
      {:ptr, _} -> parse_ptr_record_fast(rdata, orig_body)
      {:txt, _} -> parse_txt_record_fast(rdata)
      _ -> DNSpacket.parse_rdata(rdata, type, class, orig_body)
    end
  end

  @compile {:inline, [
    parse_a_record_fast: 1,
    parse_aaaa_record_fast: 1,
    parse_txt_record_fast: 1
  ]}

  defp parse_a_record_fast(<<a::8, b::8, c::8, d::8>>) do
    %{addr: {a, b, c, d}}
  end

  defp parse_aaaa_record_fast(<<a1::16, a2::16, a3::16, a4::16, 
                                a5::16, a6::16, a7::16, a8::16>>) do
    %{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}
  end

  defp parse_txt_record_fast(<<length::8, txt::binary-size(length), _::binary>>) do
    %{txt: txt}
  end

  defp parse_mx_record_fast(<<preference::16, name_data::binary>>, orig_body) do
    {_, _, name} = DNSpacket.parse_name(name_data, orig_body, "")
    %{preference: preference, name: name}
  end

  defp parse_ns_record_fast(rdata, orig_body) do
    {_, _, name} = DNSpacket.parse_name(rdata, orig_body, "")
    %{name: name}
  end

  defp parse_cname_record_fast(rdata, orig_body) do
    {_, _, name} = DNSpacket.parse_name(rdata, orig_body, "")
    %{name: name}
  end

  defp parse_ptr_record_fast(rdata, orig_body) do
    {_, _, name} = DNSpacket.parse_name(rdata, orig_body, "")
    %{name: name}
  end

  # Example 6: Lazy Parsing Implementation
  defmodule LazyPacket do
    defstruct [:binary, :header, :parsed_sections, :offsets]

    def parse_lazy(binary) do
      {header, offsets} = parse_header_and_offsets(binary)
      %__MODULE__{
        binary: binary,
        header: header,
        parsed_sections: %{},
        offsets: offsets
      }
    end

    def get_questions(%__MODULE__{parsed_sections: %{questions: questions}}) do
      questions
    end

    def get_questions(%__MODULE__{} = packet) do
      questions = parse_section_on_demand(packet, :questions)
      %{packet | parsed_sections: Map.put(packet.parsed_sections, :questions, questions)}
    end

    def get_answers(%__MODULE__{parsed_sections: %{answers: answers}}) do
      answers
    end

    def get_answers(%__MODULE__{} = packet) do
      answers = parse_section_on_demand(packet, :answers)
      %{packet | parsed_sections: Map.put(packet.parsed_sections, :answers, answers)}
    end

    defp parse_header_and_offsets(<<
      id::16, qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, z::1, ad::1, cd::1, rcode::4,
      qdcount::16, ancount::16, nscount::16, arcount::16,
      body::binary
    >>) do
      header = %{
        id: id, qr: qr, opcode: opcode, aa: aa, tc: tc, rd: rd, ra: ra,
        z: z, ad: ad, cd: cd, rcode: rcode,
        qdcount: qdcount, ancount: ancount, nscount: nscount, arcount: arcount
      }
      
      # Calculate section offsets without parsing
      offsets = calculate_section_offsets(body, qdcount, ancount, nscount, arcount)
      
      {header, offsets}
    end

    defp calculate_section_offsets(body, qdcount, ancount, nscount, arcount) do
      # Fast calculation of where each section starts
      # This is much faster than full parsing
      %{
        questions: 12, # After header
        answers: calculate_questions_end(body, qdcount),
        authority: calculate_answers_end(body, qdcount, ancount),
        additional: calculate_authority_end(body, qdcount, ancount, nscount)
      }
    end

    defp parse_section_on_demand(packet, section) do
      # Parse only the requested section
      # Implementation details...
    end
  end

  # Helper function for benchmarking
  def create_character_string(txt), do: <<byte_size(txt)::8, txt::binary>>

  # Benchmark the optimizations
  def run_optimization_benchmarks do
    test_domain = "subdomain.example.com"
    
    IO.puts("=== Domain Name Optimization Benchmark ===")
    
    # Benchmark domain name creation
    {time_current, _} = :timer.tc(fn ->
      for _ <- 1..10000, do: create_domain_name_current(test_domain)
    end)
    
    {time_v1, _} = :timer.tc(fn ->
      for _ <- 1..10000, do: create_domain_name_optimized_v1(test_domain)
    end)
    
    {time_v2, _} = :timer.tc(fn ->
      for _ <- 1..10000, do: create_domain_name_optimized_v2(test_domain)
    end)
    
    IO.puts("Current implementation: #{time_current}μs")
    IO.puts("Optimized v1 (binary.split): #{time_v1}μs")
    IO.puts("Optimized v2 (direct binary): #{time_v2}μs")
    
    improvement_v1 = Float.round((time_current - time_v1) / time_current * 100, 1)
    improvement_v2 = Float.round((time_current - time_v2) / time_current * 100, 1)
    
    IO.puts("Improvement v1: #{improvement_v1}%")
    IO.puts("Improvement v2: #{improvement_v2}%")
    
    # Benchmark record creation
    IO.puts("\n=== Record Creation Benchmark ===")
    
    a_addr = {192, 168, 1, 1}
    aaaa_addr = {0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}
    
    {time_a_current, _} = :timer.tc(fn ->
      for _ <- 1..50000, do: DNSpacket.create_rdata(%{addr: a_addr}, :a, :in)
    end)
    
    {time_a_fast, _} = :timer.tc(fn ->
      for _ <- 1..50000, do: create_a_record_fast(a_addr)
    end)
    
    {time_aaaa_current, _} = :timer.tc(fn ->
      for _ <- 1..50000, do: DNSpacket.create_rdata(%{addr: aaaa_addr}, :aaaa, :in)
    end)
    
    {time_aaaa_fast, _} = :timer.tc(fn ->
      for _ <- 1..50000, do: create_aaaa_record_fast(aaaa_addr)
    end)
    
    IO.puts("A record - Current: #{time_a_current}μs, Optimized: #{time_a_fast}μs")
    IO.puts("AAAA record - Current: #{time_aaaa_current}μs, Optimized: #{time_aaaa_fast}μs")
    
    a_improvement = Float.round((time_a_current - time_a_fast) / time_a_current * 100, 1)
    aaaa_improvement = Float.round((time_aaaa_current - time_aaaa_fast) / time_aaaa_current * 100, 1)
    
    IO.puts("A record improvement: #{a_improvement}%")
    IO.puts("AAAA record improvement: #{aaaa_improvement}%")
  end
end

# Run the benchmarks
OptimizationExamples.run_optimization_benchmarks()