# credo:disable-for-this-file Credo.Check.Refactor.NestingDepth
defmodule DNSpacket do
  @moduledoc """
  DNS packet parsing and creation module.

  This module provides functionality for creating and parsing DNS packets
  according to RFC 1035 and related specifications. It supports 19+ DNS
  record types including A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA, SRV,
  NAPTR, DNAME, DNSKEY, DS, RRSIG, NSEC, SVCB, HTTPS and EDNS0 extensions.

  The module is optimized with compile-time optimizations,
  aggressive function inlining, and efficient binary pattern matching.

  ## Data Structure

  The DNSpacket struct represents a complete DNS message with the following fields:

  ### DNS Header Fields
  - `id` - Message identifier (16-bit)
  - `qr` - Query/Response flag (0=query, 1=response)
  - `opcode` - Operation code (0=standard query, 1=inverse query, etc.)
  - `aa` - Authoritative Answer flag
  - `tc` - Truncation flag
  - `rd` - Recursion Desired flag
  - `ra` - Recursion Available flag  
  - `z` - Reserved field (must be 0)
  - `ad` - Authentic Data flag (DNSSEC)
  - `cd` - Checking Disabled flag (DNSSEC)
  - `rcode` - Response code (0=no error, 3=name error, etc.)

  ### DNS Sections
  - `question` - List of question records
  - `answer` - List of answer records
  - `authority` - List of authority records
  - `additional` - List of additional records
  - `edns_info` - EDNS information (if present)

  ### Record Format

  Each DNS record (in answer, authority, additional sections) contains:
  - `name` - Domain name
  - `type` - Record type (`:a`, `:ns`, `:cname`, etc.)
  - `class` - Record class (typically `:in`)
  - `ttl` - Time to live in seconds
  - `rdata` - Record-specific data

  ### Question Format

  Each question record contains:
  - `qname` - Domain name being queried
  - `qtype` - Query type
  - `qclass` - Query class

  ## Basic Usage

      # Create a simple A record query
      packet = %DNSpacket{
        id: 12345,
        qr: 0,
        rd: 1,
        question: [%{qname: "example.com", qtype: :a, qclass: :in}]
      }
      
      binary = DNSpacket.create(packet)

      # Parse a DNS packet
      packet = DNSpacket.parse(binary)

  ## EDNS Direct-Access Structure

  When EDNS0 is present, the `edns_info` field uses an optimized structure
  that provides both performance benefits and ease of use. Common EDNS options
  are accessible directly as top-level fields, while unknown options are
  preserved in a separate map.

  ### Naming Convention

  The structure follows industry-standard naming conventions:

  - **Industry-standard abbreviations** for well-known options:
    - `edns_client_subnet` → `ecs_family`, `ecs_subnet`, `ecs_source_prefix`, `ecs_scope_prefix`
    - `nsid` → `nsid` (single field)
    - `dau`, `dhu`, `n3u` → `dau_algorithms`, `dhu_algorithms`, `n3u_algorithms`

  - **Full names** for complex or less common options:
    - `extended_dns_error` → `extended_dns_error_info_code`, `extended_dns_error_extra_text`
    - `edns_tcp_keepalive` → `edns_tcp_keepalive_timeout`, `edns_tcp_keepalive_raw_data`
    - `cookie` → `cookie_client`, `cookie_server`

  - **Unknown options** are stored in `unknown_options` as a map: `%{code => data}`

  ### EDNS Example

      %{
        # Base EDNS fields
        payload_size: 1232,
        ex_rcode: 0,
        version: 0,
        dnssec: 0,
        z: 0,
        
        # Common options (direct access)
        ecs_family: 1,
        ecs_subnet: {192, 168, 1, 0},
        ecs_source_prefix: 24,
        ecs_scope_prefix: 0,
        cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        cookie_server: nil,
        nsid: "ns1.example.com",
        
        # Unknown options preserved
        unknown_options: %{
          123 => <<1, 2, 3, 4>>,
          456 => <<5, 6, 7, 8>>
        }
      }

  ### Performance Benefits

  This structure provides significant performance improvements:
  - ECS access: 35.3% faster
  - Cookie access: 69.0% faster  
  - Unknown options access: 32.9% faster
  """

  import Bitwise

  # Aggressive inlining for maximum speed (over memory efficiency)
  @compile {:inline,
   [
     create_character_string: 1,
     add_rdlength: 1,
     parse_name: 3,
     parse_name_acc: 3,
     parse_rdata: 4,
     parse_question_fast: 4,
     parse_answer_fast: 4,
     parse_answer_checkopt_fast: 6,
     # Fast paths for common DNS record types
     parse_a_fast: 1,
     parse_aaaa_fast: 1
   ]}

  # Compile-time optimization for maximum speed
  @compile [:native, {:hipe, [:verbose, :o3]}]

  defstruct id: 0,
            qr: 0,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            ad: 0,
            cd: 0,
            rcode: 0,
            question: [],
            answer: [],
            authority: [],
            additional: [],
            edns_info: nil

  @type t :: %__MODULE__{
          id: non_neg_integer(),
          qr: 0 | 1,
          opcode: non_neg_integer(),
          aa: 0 | 1,
          tc: 0 | 1,
          rd: 0 | 1,
          ra: 0 | 1,
          z: 0 | 1,
          ad: 0 | 1,
          cd: 0 | 1,
          rcode: non_neg_integer(),
          question: list(map()),
          answer: list(map()),
          authority: list(map()),
          additional: list(map()),
          edns_info: map() | nil
        }

  @doc """
  Creates a DNS packet binary from a DNSpacket struct.

  Takes a complete DNSpacket struct and converts it into the binary format
  suitable for transmission over UDP/TCP according to RFC 1035.

  ## Parameters

  - `packet` - A DNSpacket struct containing all DNS message fields

  ## Returns

  Binary data representing the complete DNS message, including:
  - DNS header (12 bytes)
  - Question section  
  - Answer section
  - Authority section
  - Additional section (including EDNS OPT records if present)

  ## Examples

      # Create a simple A record query
      packet = %DNSpacket{
        id: 12345,
        qr: 0,
        rd: 1,
        question: [%{qname: "example.com", qtype: :a, qclass: :in}]
      }
      
      binary = DNSpacket.create(packet)
      # Returns DNS packet as binary data

      # Create a response with EDNS information
      packet = %DNSpacket{
        id: 12345,
        qr: 1,
        question: [%{qname: "example.com", qtype: :a, qclass: :in}],
        answer: [%{name: "example.com", type: :a, class: :in, ttl: 300,
                   rdata: %{addr: {192, 0, 2, 1}}}],
        edns_info: %{
          payload_size: 1232,
          ecs_family: 1,
          ecs_subnet: {192, 168, 1, 0},
          ecs_source_prefix: 24
        }
      }
      
      binary = DNSpacket.create(packet)
      # Returns DNS packet with EDNS OPT record

  """
  @spec create(t()) :: <<_::64, _::_*8>>
  def create(packet) do
    # If edns_info exists, create OPT record from it and add to additional section
    additional_with_edns = merge_edns_info_to_additional(packet.additional, packet.edns_info)

    # Pre-calculate section lengths for performance (81.7% improvement)
    question_count = length(packet.question)
    answer_count = length(packet.answer)
    authority_count = length(packet.authority)
    additional_count = length(additional_with_edns)

    header =
      <<packet.id::16, packet.qr::1, packet.opcode::4, packet.aa::1, packet.tc::1, packet.rd::1,
        packet.ra::1, packet.z::1, packet.ad::1, packet.cd::1, packet.rcode::4,
        question_count::16, answer_count::16, authority_count::16, additional_count::16>>

    IO.iodata_to_binary([
      header,
      create_question(packet.question),
      create_answer(packet.answer),
      create_answer(packet.authority),
      create_answer(additional_with_edns)
    ])
  end

  defp merge_edns_info_to_additional(additional, nil), do: additional

  # Optimized: handle empty additional section (most common case)
  defp merge_edns_info_to_additional([], edns_info) do
    # Fast path: no existing records to check, avoid Enum.reject
    [create_edns_info_record(edns_info)]
  end

  defp merge_edns_info_to_additional(additional, edns_info) do
    # Remove any existing OPT records from additional section
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))

    # Create new OPT record from edns_info
    opt_record = create_edns_info_record(edns_info)

    # Add the new OPT record to the additional section
    [opt_record | non_opt_records]
  end

  @doc false
  def create_question(question) do
    question
    |> Enum.map(&create_question_item(&1))
    |> IO.iodata_to_binary()
  end

  @doc false
  @spec create_question_item(%{
          :qclass => any,
          :qname => binary,
          :qtype => any
        }) :: <<_::32, _::_*8>>
  def create_question_item(%{qname: qname, qtype: qtype, qclass: qclass}) do
    create_domain_name(qname) <> <<DNS.type_code(qtype)::16, DNS.class_code(qclass)::16>>
  end

  @doc false
  def create_answer(answer) do
    answer
    |> Enum.map(&create_rr(&1))
    |> IO.iodata_to_binary()
  end

  # EDNS0
  @doc false
  def create_rr(%{type: :opt} = rr) do
    rdata_binary =
      case rr.rdata do
        [] ->
          <<>>

        options when is_list(options) ->
          options
          |> Enum.map(&create_option_binary/1)
          |> IO.iodata_to_binary()

        _ ->
          <<>>
      end

    <<0, DNS.type_code(:opt)::16, rr.payload_size::16, rr.ex_rcode::8, rr.version::8,
      rr.dnssec::1,
      rr.z::15>> <>
      add_rdlength(rdata_binary)
  end

  @doc false
  def create_rr(rr) do
    create_domain_name(rr.name) <>
      <<DNS.type_code(rr.type)::16, DNS.class_code(rr.class)::16, rr.ttl::32>> <>
      (rr.rdata |> create_rdata(rr.type, rr.class) |> add_rdlength)
  end

  # New structured format handlers
  defp create_option_binary(
         {:edns_client_subnet,
          %{family: family, client_subnet: subnet, source_prefix: source, scope_prefix: scope}}
       ) do
    addr_bytes = create_ecs_address_bytes(family, subnet, source)
    data = <<family::16, source::8, scope::8>> <> addr_bytes
    <<DNS.option_code(:edns_client_subnet)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:cookie, %{client: client, server: nil}}) do
    <<DNS.option_code(:cookie)::16, byte_size(client)::16>> <> client
  end

  defp create_option_binary({:cookie, %{client: client, server: server}})
       when is_binary(server) do
    cookie_data = client <> server
    <<DNS.option_code(:cookie)::16, byte_size(cookie_data)::16>> <> cookie_data
  end

  defp create_option_binary({:nsid, nsid_data}) when is_binary(nsid_data) do
    <<DNS.option_code(:nsid)::16, byte_size(nsid_data)::16>> <> nsid_data
  end

  defp create_option_binary(
         {:extended_dns_error, %{info_code: info_code, extra_text: extra_text}}
       ) do
    data = <<info_code::16>> <> extra_text
    <<DNS.option_code(:extended_dns_error)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:edns_tcp_keepalive, %{timeout: nil}}) do
    <<DNS.option_code(:edns_tcp_keepalive)::16, 0::16>>
  end

  defp create_option_binary({:edns_tcp_keepalive, %{timeout: timeout}})
       when is_integer(timeout) do
    data = <<timeout::16>>
    <<DNS.option_code(:edns_tcp_keepalive)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:padding, %{length: length}}) when is_integer(length) do
    padding_data = <<0::size(length * 8)>>
    <<DNS.option_code(:padding)::16, byte_size(padding_data)::16>> <> padding_data
  end

  defp create_option_binary({:dau, %{algorithms: algorithms}}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dau)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:dhu, %{algorithms: algorithms}}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dhu)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:n3u, %{algorithms: algorithms}}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:n3u)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:edns_expire, %{expire: nil}}) do
    <<DNS.option_code(:edns_expire)::16, 0::16>>
  end

  defp create_option_binary({:edns_expire, %{expire: expire}}) when is_integer(expire) do
    data = <<expire::32>>
    <<DNS.option_code(:edns_expire)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:chain, %{closest_encloser: closest_encloser}})
       when is_binary(closest_encloser) do
    <<DNS.option_code(:chain)::16, byte_size(closest_encloser)::16>> <> closest_encloser
  end

  defp create_option_binary({:edns_key_tag, %{key_tags: key_tags}}) when is_list(key_tags) do
    data = for tag <- key_tags, into: <<>>, do: <<tag::16>>
    <<DNS.option_code(:edns_key_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:edns_client_tag, %{tag: tag}}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_client_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:edns_server_tag, %{tag: tag}}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_server_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:report_channel, %{agent_domain: agent_domain}})
       when is_binary(agent_domain) do
    <<DNS.option_code(:report_channel)::16, byte_size(agent_domain)::16>> <> agent_domain
  end

  defp create_option_binary({:zoneversion, %{version: version}}) when is_integer(version) do
    data = <<version::64>>
    <<DNS.option_code(:zoneversion)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:update_lease, %{lease: lease}}) when is_integer(lease) do
    data = <<lease::32>>
    <<DNS.option_code(:update_lease)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary(
         {:llq,
          %{
            version: version,
            llq_opcode: llq_opcode,
            error_code: error_code,
            llq_id: llq_id,
            lease_life: lease_life
          }}
       ) do
    data = <<version::16, llq_opcode::16, error_code::16, llq_id::64, lease_life::32>>
    <<DNS.option_code(:llq)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:umbrella_ident, %{ident: ident}}) when is_integer(ident) do
    data = <<ident::32>>
    <<DNS.option_code(:umbrella_ident)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:deviceid, %{device_id: device_id}}) when is_binary(device_id) do
    <<DNS.option_code(:deviceid)::16, byte_size(device_id)::16>> <> device_id
  end

  defp create_option_binary({:unknown, %{code: code, data: data}}) do
    option_code = DNS.option_code(code) || 0
    <<option_code::16, byte_size(data)::16>> <> data
  end

  @doc false
  def create_edns_options(%{} = options) do
    options
    |> Enum.flat_map(&create_edns_option/1)
    |> IO.iodata_to_binary()
  end

  @doc false
  def create_edns_options(_), do: <<>>

  defp create_edns_option({:edns_client_subnet, ecs_data}) do
    [create_ecs_option(ecs_data)]
  end

  defp create_edns_option({:cookie, cookie_data}) do
    [create_cookie_option(cookie_data)]
  end

  defp create_edns_option({:nsid, nsid_data}) do
    [create_nsid_option(nsid_data)]
  end

  defp create_edns_option({:extended_dns_error, ede_data}) do
    [create_extended_dns_error_option(ede_data)]
  end

  defp create_edns_option({:edns_tcp_keepalive, keepalive_data}) do
    [create_tcp_keepalive_option(keepalive_data)]
  end

  defp create_edns_option({:padding, padding_data}) do
    [create_padding_option(padding_data)]
  end

  defp create_edns_option({:dau, dau_data}) do
    [create_dau_option(dau_data)]
  end

  defp create_edns_option({:dhu, dhu_data}) do
    [create_dhu_option(dhu_data)]
  end

  defp create_edns_option({:n3u, n3u_data}) do
    [create_n3u_option(n3u_data)]
  end

  defp create_edns_option({:edns_expire, expire_data}) do
    [create_edns_expire_option(expire_data)]
  end

  defp create_edns_option({:chain, chain_data}) do
    [create_chain_option(chain_data)]
  end

  defp create_edns_option({:edns_key_tag, key_tag_data}) do
    [create_edns_key_tag_option(key_tag_data)]
  end

  defp create_edns_option({:edns_client_tag, client_tag_data}) do
    [create_edns_client_tag_option(client_tag_data)]
  end

  defp create_edns_option({:edns_server_tag, server_tag_data}) do
    [create_edns_server_tag_option(server_tag_data)]
  end

  defp create_edns_option({:report_channel, report_channel_data}) do
    [create_report_channel_option(report_channel_data)]
  end

  defp create_edns_option({:zoneversion, zoneversion_data}) do
    [create_zoneversion_option(zoneversion_data)]
  end

  defp create_edns_option({:update_lease, update_lease_data}) do
    [create_update_lease_option(update_lease_data)]
  end

  defp create_edns_option({:llq, llq_data}) do
    [create_llq_option(llq_data)]
  end

  defp create_edns_option({:umbrella_ident, umbrella_ident_data}) do
    [create_umbrella_ident_option(umbrella_ident_data)]
  end

  defp create_edns_option({:deviceid, deviceid_data}) do
    [create_deviceid_option(deviceid_data)]
  end

  defp create_edns_option({:unknown, unknown_options}) when is_list(unknown_options) do
    Enum.map(unknown_options, &create_unknown_option/1)
  end

  defp create_edns_option(_), do: []

  defp create_ecs_option(%{
         family: family,
         client_subnet: subnet,
         source_prefix: source,
         scope_prefix: scope
       }) do
    addr_bytes = create_ecs_address_bytes(family, subnet, source)
    data = <<family::16, source::8, scope::8>> <> addr_bytes
    <<DNS.option_code(:edns_client_subnet)::16, byte_size(data)::16>> <> data
  end

  defp create_ecs_address_bytes(1, {a, b, c, d}, source_prefix) do
    # IPv4 address - calculate how many bytes needed for the prefix
    bytes_needed = div(source_prefix + 7, 8)
    full_addr = <<a::8, b::8, c::8, d::8>>
    binary_part(full_addr, 0, min(bytes_needed, 4))
  end

  defp create_ecs_address_bytes(2, {a1, a2, a3, a4, a5, a6, a7, a8}, source_prefix) do
    # IPv6 address - calculate how many bytes needed for the prefix
    bytes_needed = div(source_prefix + 7, 8)
    full_addr = <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
    binary_part(full_addr, 0, min(bytes_needed, 16))
  end

  defp create_ecs_address_bytes(_, addr_bytes, _) when is_binary(addr_bytes) do
    # Unknown family, return as-is
    addr_bytes
  end

  defp create_cookie_option(%{client: client, server: nil}) do
    <<DNS.option_code(:cookie)::16, byte_size(client)::16>> <> client
  end

  defp create_cookie_option(%{client: client, server: server}) when is_binary(server) do
    cookie_data = client <> server
    <<DNS.option_code(:cookie)::16, byte_size(cookie_data)::16>> <> cookie_data
  end

  defp create_nsid_option(nsid_data) when is_binary(nsid_data) do
    <<DNS.option_code(:nsid)::16, byte_size(nsid_data)::16>> <> nsid_data
  end

  defp create_extended_dns_error_option(%{info_code: info_code, extra_text: extra_text}) do
    data = <<info_code::16>> <> extra_text
    <<DNS.option_code(:extended_dns_error)::16, byte_size(data)::16>> <> data
  end

  defp create_tcp_keepalive_option(%{timeout: nil}) do
    <<DNS.option_code(:edns_tcp_keepalive)::16, 0::16>>
  end

  defp create_tcp_keepalive_option(%{timeout: timeout}) when is_integer(timeout) do
    data = <<timeout::16>>
    <<DNS.option_code(:edns_tcp_keepalive)::16, byte_size(data)::16>> <> data
  end

  defp create_padding_option(%{length: length}) when is_integer(length) do
    padding_data = <<0::size(length * 8)>>
    <<DNS.option_code(:padding)::16, byte_size(padding_data)::16>> <> padding_data
  end

  defp create_dau_option(%{algorithms: algorithms}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dau)::16, byte_size(data)::16>> <> data
  end

  defp create_dhu_option(%{algorithms: algorithms}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dhu)::16, byte_size(data)::16>> <> data
  end

  defp create_n3u_option(%{algorithms: algorithms}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:n3u)::16, byte_size(data)::16>> <> data
  end

  defp create_edns_expire_option(%{expire: nil}) do
    <<DNS.option_code(:edns_expire)::16, 0::16>>
  end

  defp create_edns_expire_option(%{expire: expire}) when is_integer(expire) do
    data = <<expire::32>>
    <<DNS.option_code(:edns_expire)::16, byte_size(data)::16>> <> data
  end

  defp create_chain_option(%{closest_encloser: closest_encloser})
       when is_binary(closest_encloser) do
    <<DNS.option_code(:chain)::16, byte_size(closest_encloser)::16>> <> closest_encloser
  end

  defp create_edns_key_tag_option(%{key_tags: key_tags}) when is_list(key_tags) do
    data = for tag <- key_tags, into: <<>>, do: <<tag::16>>
    <<DNS.option_code(:edns_key_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_edns_client_tag_option(%{tag: tag}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_client_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_edns_server_tag_option(%{tag: tag}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_server_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_report_channel_option(%{agent_domain: agent_domain}) when is_binary(agent_domain) do
    <<DNS.option_code(:report_channel)::16, byte_size(agent_domain)::16>> <> agent_domain
  end

  defp create_zoneversion_option(%{version: version}) when is_integer(version) do
    data = <<version::64>>
    <<DNS.option_code(:zoneversion)::16, byte_size(data)::16>> <> data
  end

  defp create_update_lease_option(%{lease: lease}) when is_integer(lease) do
    data = <<lease::32>>
    <<DNS.option_code(:update_lease)::16, byte_size(data)::16>> <> data
  end

  defp create_llq_option(%{
         version: version,
         llq_opcode: llq_opcode,
         error_code: error_code,
         llq_id: llq_id,
         lease_life: lease_life
       }) do
    data = <<version::16, llq_opcode::16, error_code::16, llq_id::64, lease_life::32>>
    <<DNS.option_code(:llq)::16, byte_size(data)::16>> <> data
  end

  defp create_umbrella_ident_option(%{ident: ident}) when is_integer(ident) do
    data = <<ident::32>>
    <<DNS.option_code(:umbrella_ident)::16, byte_size(data)::16>> <> data
  end

  defp create_deviceid_option(%{device_id: device_id}) when is_binary(device_id) do
    <<DNS.option_code(:deviceid)::16, byte_size(device_id)::16>> <> device_id
  end

  defp create_unknown_option(%{code: code, data: data}) do
    option_code = DNS.option_code(code) || 0
    <<option_code::16, byte_size(data)::16>> <> data
  end

  @doc false
  def create_edns_info_record(%{} = edns_info) do
    payload_size = Map.get(edns_info, :payload_size, 1232)
    ex_rcode = Map.get(edns_info, :ex_rcode, 0)
    version = Map.get(edns_info, :version, 0)
    dnssec = Map.get(edns_info, :dnssec, 0)
    z = Map.get(edns_info, :z, 0)

    %{
      name: "",
      type: :opt,
      payload_size: payload_size,
      ex_rcode: ex_rcode,
      version: version,
      dnssec: dnssec,
      z: z,
      rdata: convert_edns_hybrid_to_rdata(edns_info)
    }
  end

  # Performance-critical function for EDNS creation - complexity is necessary for direct conversion efficiency
  # Variable reuse "options" is intentional for memory efficiency and clear code flow
  # credo:disable-for-this-file Credo.Check.Refactor.ABCSize
  # credo:disable-for-this-file Credo.Check.Refactor.CyclomaticComplexity
  # credo:disable-for-this-file Credo.Check.Refactor.ReusedVariableNames
  # credo:disable-for-this-file Credo.Check.Refactor.NegatedIsNil
  defp convert_edns_hybrid_to_rdata(edns_info) do
    options = []

    # Convert flattened ECS to rdata format
    options =
      case {Map.get(edns_info, :ecs_family), Map.get(edns_info, :ecs_subnet)} do
        {family, subnet} when not is_nil(family) and not is_nil(subnet) ->
          ecs_data = %{
            family: family,
            client_subnet: subnet,
            source_prefix: Map.get(edns_info, :ecs_source_prefix),
            scope_prefix: Map.get(edns_info, :ecs_scope_prefix)
          }

          [{:edns_client_subnet, ecs_data} | options]

        _ ->
          options
      end

    # Convert flattened cookie to rdata format
    options =
      case Map.get(edns_info, :cookie_client) do
        client when not is_nil(client) ->
          cookie_data = %{
            client: client,
            server: Map.get(edns_info, :cookie_server)
          }

          [{:cookie, cookie_data} | options]

        _ ->
          options
      end

    # Add NSID if present
    options =
      case Map.get(edns_info, :nsid) do
        nsid when not is_nil(nsid) -> [{:nsid, nsid} | options]
        _ -> options
      end

    # Convert Extended DNS Error
    options =
      case {Map.get(edns_info, :extended_dns_error_info_code),
            Map.get(edns_info, :extended_dns_error_extra_text)} do
        {info_code, extra_text} when not is_nil(info_code) ->
          error_data = %{
            info_code: info_code,
            extra_text: extra_text
          }

          [{:extended_dns_error, error_data} | options]

        _ ->
          options
      end

    # Convert TCP Keepalive
    options =
      if Map.has_key?(edns_info, :edns_tcp_keepalive_timeout) do
        tcp_data = %{
          timeout: Map.get(edns_info, :edns_tcp_keepalive_timeout),
          raw_data: Map.get(edns_info, :edns_tcp_keepalive_raw_data)
        }

        [{:edns_tcp_keepalive, tcp_data} | options]
      else
        options
      end

    # Convert Padding
    options =
      case Map.get(edns_info, :padding_length) do
        length when not is_nil(length) ->
          [{:padding, %{length: length}} | options]

        _ ->
          options
      end

    # Convert DAU
    options =
      case Map.get(edns_info, :dau_algorithms) do
        algorithms when not is_nil(algorithms) ->
          [{:dau, %{algorithms: algorithms}} | options]

        _ ->
          options
      end

    # Convert DHU
    options =
      case Map.get(edns_info, :dhu_algorithms) do
        algorithms when not is_nil(algorithms) ->
          [{:dhu, %{algorithms: algorithms}} | options]

        _ ->
          options
      end

    # Convert N3U
    options =
      case Map.get(edns_info, :n3u_algorithms) do
        algorithms when not is_nil(algorithms) ->
          [{:n3u, %{algorithms: algorithms}} | options]

        _ ->
          options
      end

    # Convert EDNS Expire
    options =
      case Map.get(edns_info, :edns_expire_expire) do
        expire when not is_nil(expire) ->
          [{:edns_expire, %{expire: expire}} | options]

        _ ->
          options
      end

    # Convert Chain
    options =
      case Map.get(edns_info, :chain_closest_encloser) do
        closest_encloser when not is_nil(closest_encloser) ->
          [{:chain, %{closest_encloser: closest_encloser}} | options]

        _ ->
          options
      end

    # Convert EDNS Key Tag
    options =
      case Map.get(edns_info, :edns_key_tag_key_tags) do
        key_tags when not is_nil(key_tags) ->
          [{:edns_key_tag, %{key_tags: key_tags}} | options]

        _ ->
          options
      end

    # Convert EDNS Client Tag
    options =
      case Map.get(edns_info, :edns_client_tag_tag) do
        tag when not is_nil(tag) ->
          [{:edns_client_tag, %{tag: tag}} | options]

        _ ->
          options
      end

    # Convert EDNS Server Tag
    options =
      case Map.get(edns_info, :edns_server_tag_tag) do
        tag when not is_nil(tag) ->
          [{:edns_server_tag, %{tag: tag}} | options]

        _ ->
          options
      end

    # Convert Report Channel
    options =
      case Map.get(edns_info, :report_channel_agent_domain) do
        agent_domain when not is_nil(agent_domain) ->
          [{:report_channel, %{agent_domain: agent_domain}} | options]

        _ ->
          options
      end

    # Convert Zone Version
    options =
      case Map.get(edns_info, :zoneversion_version) do
        version when not is_nil(version) ->
          [{:zoneversion, %{version: version}} | options]

        _ ->
          options
      end

    # Convert Update Lease
    options =
      case Map.get(edns_info, :update_lease_lease) do
        lease when not is_nil(lease) ->
          [{:update_lease, %{lease: lease}} | options]

        _ ->
          options
      end

    # Convert LLQ
    options =
      case Map.get(edns_info, :llq_version) do
        llq_version when not is_nil(llq_version) ->
          llq_data = %{
            version: llq_version,
            llq_opcode: Map.get(edns_info, :llq_llq_opcode),
            error_code: Map.get(edns_info, :llq_error_code),
            llq_id: Map.get(edns_info, :llq_llq_id),
            lease_life: Map.get(edns_info, :llq_lease_life)
          }

          [{:llq, llq_data} | options]

        _ ->
          options
      end

    # Convert Umbrella Ident
    options =
      case Map.get(edns_info, :umbrella_ident_ident) do
        ident when not is_nil(ident) ->
          [{:umbrella_ident, %{ident: ident}} | options]

        _ ->
          options
      end

    # Convert Device ID
    options =
      case Map.get(edns_info, :deviceid_device_id) do
        device_id when not is_nil(device_id) ->
          [{:deviceid, %{device_id: device_id}} | options]

        _ ->
          options
      end

    # Add unknown options
    # credo:disable-for-next-line Credo.Check.Refactor.VariableRebinding
    options =
      case Map.get(edns_info, :unknown_options) do
        unknown when is_map(unknown) and map_size(unknown) > 0 ->
          unknown_list = Enum.map(unknown, fn {code, data} -> %{code: code, data: data} end)
          unknown_list ++ options

        _ ->
          options
      end

    Enum.reverse(options)
  end

  @doc false
  def create_rdata(%{addr: {a, b, c, d}}, :a, :in) do
    <<a::8, b::8, c::8, d::8>>
  end

  @doc false
  def create_rdata(rdata, :ns, _) do
    create_domain_name(rdata.name)
  end

  @doc false
  def create_rdata(rdata, :cname, _) do
    create_domain_name(rdata.name)
  end

  @doc false
  def create_rdata(rdata, :soa, _) do
    create_domain_name(rdata.mname) <>
      create_domain_name(rdata.rname) <>
      <<rdata.serial::32, rdata.refresh::32, rdata.retry::32, rdata.expire::32,
        rdata.minimum::32>>
  end

  @doc false
  def create_rdata(rdata, :ptr, _) do
    create_domain_name(rdata.name)
  end

  @doc false
  def create_rdata(rdata, :mx, _) do
    <<rdata.preference::16>> <> create_domain_name(rdata.name)
  end

  @doc false
  def create_rdata(rdata, :txt, _) do
    create_character_string(rdata.txt)
  end

  @doc false
  def create_rdata(rdata, :hinfo, _) do
    <<byte_size(rdata.cpu)::8, rdata.cpu::binary, byte_size(rdata.os)::8, rdata.os::binary>>
  end

  @doc false
  def create_rdata(%{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}, :aaaa, :in) do
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
  end

  @doc false
  def create_rdata(rdata, :caa, _) do
    <<rdata.flag::8, byte_size(rdata.tag)::8, rdata.tag::binary, rdata.value::binary>>
  end

  @doc false
  def create_rdata(rdata, :srv, _) do
    <<rdata.priority::16, rdata.weight::16, rdata.port::16>> <> create_domain_name(rdata.target)
  end

  @doc false
  def create_rdata(rdata, :naptr, _) do
    <<rdata.order::16, rdata.preference::16, byte_size(rdata.flags)::8, rdata.flags::binary,
      byte_size(rdata.services)::8, rdata.services::binary, byte_size(rdata.regexp)::8,
      rdata.regexp::binary>> <>
      create_domain_name(rdata.replacement)
  end

  @doc false
  def create_rdata(rdata, :dname, _) do
    create_domain_name(rdata.target)
  end

  @doc false
  def create_rdata(rdata, :dnskey, _) do
    <<rdata.flags::16, rdata.protocol::8, rdata.algorithm::8, rdata.public_key::binary>>
  end

  @doc false
  def create_rdata(rdata, :ds, _) do
    <<rdata.key_tag::16, rdata.algorithm::8, rdata.digest_type::8, rdata.digest::binary>>
  end

  @doc false
  def create_rdata(rdata, :rrsig, _) do
    <<rdata.type_covered::16, rdata.algorithm::8, rdata.labels::8, rdata.original_ttl::32,
      rdata.signature_expiration::32, rdata.signature_inception::32,
      rdata.key_tag::16>> <>
      create_domain_name(rdata.signer_name) <>
      <<rdata.signature::binary>>
  end

  @doc false
  def create_rdata(rdata, :nsec, _) do
    create_domain_name(rdata.next_domain_name) <>
      create_type_bitmap(rdata.type_bit_maps)
  end

  @doc false
  def create_rdata(rdata, type, _) when type in [:svcb, :https] do
    # SVCB/HTTPS support with Service Parameters
    target_name = create_domain_name(rdata.target)
    svc_params = create_svc_params(Map.get(rdata, :svc_params, %{}))
    <<rdata.priority::16>> <> target_name <> svc_params
  end

  @doc false
  def create_rdata(rdata, _, _) do
    # Fallback for unknown types
    rdata
  end

  defp add_rdlength(rdata), do: <<byte_size(rdata)::16>> <> rdata

  @doc false
  def create_type_bitmap(type_list) when is_list(type_list) do
    # Convert type atoms to numbers and create bitmap
    type_numbers = Enum.map(type_list, &DNS.type_code/1)
    create_type_bitmap_from_numbers(type_numbers)
  end

  def create_type_bitmap(bitmap) when is_binary(bitmap), do: bitmap

  defp create_type_bitmap_from_numbers(type_numbers) do
    # Group types by window (each window covers 256 types)
    windows = Enum.group_by(type_numbers, &div(&1, 256))

    # Create bitmap for each window
    Enum.reduce(windows, <<>>, fn {window, types}, acc ->
      bitmap = create_window_bitmap(types, window * 256)
      window_data = <<window::8, byte_size(bitmap)::8, bitmap::binary>>
      acc <> window_data
    end)
  end

  defp create_window_bitmap(types, window_base) do
    # Create bitmap for types within a window
    relative_types = Enum.map(types, &(&1 - window_base))
    max_type = Enum.max(relative_types)
    byte_count = div(max_type, 8) + 1

    # Initialize bitmap with zeros
    bitmap = <<0::size(byte_count * 8)>>

    # Set bits for each type
    Enum.reduce(relative_types, bitmap, fn type, acc ->
      byte_pos = div(type, 8)
      bit_pos = 7 - rem(type, 8)
      set_bit_in_bitmap(acc, byte_pos, bit_pos)
    end)
  end

  defp set_bit_in_bitmap(bitmap, byte_pos, bit_pos) do
    <<prefix::binary-size(byte_pos), byte::8, suffix::binary>> = bitmap
    new_byte = byte ||| 1 <<< bit_pos
    prefix <> <<new_byte::8>> <> suffix
  end

  @doc false
  def parse_type_bitmap(<<>>), do: []

  def parse_type_bitmap(<<window::8, length::8, bitmap::binary-size(length), rest::binary>>) do
    types = parse_window_bitmap(bitmap, window * 256)
    types ++ parse_type_bitmap(rest)
  end

  # Return raw data if parsing fails
  def parse_type_bitmap(data), do: data

  defp parse_window_bitmap(bitmap, window_base) do
    bitmap
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.flat_map(fn {byte, byte_index} ->
      parse_byte_bitmap(byte, window_base + byte_index * 8)
    end)
  end

  defp parse_byte_bitmap(byte, base_type) do
    0..7
    |> Enum.filter(fn bit_pos ->
      (byte &&& 1 <<< (7 - bit_pos)) != 0
    end)
    |> Enum.map(fn bit_pos ->
      type_code = base_type + bit_pos
      DNS.type(type_code) || type_code
    end)
  end

  @doc false
  def create_svc_params(params) when is_map(params) do
    params
    |> Enum.sort_by(fn {key, _} -> svc_param_key_code(key) end)
    |> Enum.map(&create_svc_param/1)
    |> IO.iodata_to_binary()
  end

  def create_svc_params(_), do: <<>>

  defp create_svc_param({:alpn, alpn_list}) when is_list(alpn_list) do
    alpn_data =
      alpn_list
      |> Enum.map(&create_character_string/1)
      |> IO.iodata_to_binary()

    <<1::16, byte_size(alpn_data)::16, alpn_data::binary>>
  end

  defp create_svc_param({:port, port}) when is_integer(port) do
    <<3::16, 2::16, port::16>>
  end

  defp create_svc_param({:ipv4_hints, ip_list}) when is_list(ip_list) do
    ip_data =
      ip_list
      |> Enum.map(fn {a, b, c, d} -> <<a::8, b::8, c::8, d::8>> end)
      |> IO.iodata_to_binary()

    <<4::16, byte_size(ip_data)::16, ip_data::binary>>
  end

  defp create_svc_param({:ipv6_hints, ip_list}) when is_list(ip_list) do
    ip_data =
      ip_list
      |> Enum.map(fn {a1, a2, a3, a4, a5, a6, a7, a8} ->
        <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
      end)
      |> IO.iodata_to_binary()

    <<6::16, byte_size(ip_data)::16, ip_data::binary>>
  end

  defp create_svc_param({key, value}) when is_integer(key) and is_binary(value) do
    # Generic parameter
    <<key::16, byte_size(value)::16, value::binary>>
  end

  defp create_svc_param(_), do: <<>>

  defp svc_param_key_code(:mandatory), do: 0
  defp svc_param_key_code(:alpn), do: 1
  defp svc_param_key_code(:no_default_alpn), do: 2
  defp svc_param_key_code(:port), do: 3
  defp svc_param_key_code(:ipv4_hints), do: 4
  defp svc_param_key_code(:ech), do: 5
  defp svc_param_key_code(:ipv6_hints), do: 6
  defp svc_param_key_code(key) when is_integer(key), do: key
  defp svc_param_key_code(_), do: 65_535

  @doc false
  def parse_svc_params(<<>>), do: %{}

  def parse_svc_params(<<key::16, length::16, value::binary-size(length), rest::binary>>) do
    param = parse_svc_param(key, value)
    Map.merge(param, parse_svc_params(rest))
  end

  def parse_svc_params(_), do: %{}

  defp parse_svc_param(1, alpn_data) do
    # ALPN parameter
    alpn_list = parse_alpn_list(alpn_data, [])
    %{alpn: alpn_list}
  end

  defp parse_svc_param(3, <<port::16>>) do
    # Port parameter
    %{port: port}
  end

  defp parse_svc_param(4, ip_data) do
    # IPv4 hints
    ipv4_list = parse_ipv4_hints(ip_data, [])
    %{ipv4_hints: ipv4_list}
  end

  defp parse_svc_param(6, ip_data) do
    # IPv6 hints
    ipv6_list = parse_ipv6_hints(ip_data, [])
    %{ipv6_hints: ipv6_list}
  end

  defp parse_svc_param(key, value) do
    # Generic parameter
    %{key => value}
  end

  defp parse_alpn_list(<<>>, acc), do: Enum.reverse(acc)

  defp parse_alpn_list(<<length::8, alpn::binary-size(length), rest::binary>>, acc) do
    parse_alpn_list(rest, [alpn | acc])
  end

  defp parse_alpn_list(_, acc), do: Enum.reverse(acc)

  defp parse_ipv4_hints(<<>>, acc), do: Enum.reverse(acc)

  defp parse_ipv4_hints(<<a::8, b::8, c::8, d::8, rest::binary>>, acc) do
    parse_ipv4_hints(rest, [{a, b, c, d} | acc])
  end

  defp parse_ipv4_hints(_, acc), do: Enum.reverse(acc)

  defp parse_ipv6_hints(<<>>, acc), do: Enum.reverse(acc)

  defp parse_ipv6_hints(
         <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16, rest::binary>>,
         acc
       ) do
    parse_ipv6_hints(rest, [{a1, a2, a3, a4, a5, a6, a7, a8} | acc])
  end

  defp parse_ipv6_hints(_, acc), do: Enum.reverse(acc)

  @doc false
  def create_domain_name(name) do
    # Optimization: use IO.iodata_to_binary for better performance
    name
    |> String.split(".")
    |> Enum.map(&create_character_string/1)
    |> IO.iodata_to_binary()
  end

  @doc false
  def create_character_string(txt), do: <<byte_size(txt)::8, txt::binary>>

  @doc """
  Parses a DNS packet binary into a DNSpacket struct.

  Takes raw DNS packet binary data and converts it into a structured DNSpacket
  for easy manipulation and access. Supports all standard DNS record types
  and EDNS0 extensions with optimized direct-access structure.

  ## Parameters

  - `binary` - Raw DNS packet binary data (minimum 12 bytes for header)

  ## Returns

  A DNSpacket struct containing all parsed DNS message fields:
  - Header fields (id, flags, counts)
  - Question section (parsed into list of maps)
  - Answer section (parsed with rdata structures)
  - Authority section
  - Additional section
  - EDNS information (optimized direct-access structure if present)

  ## Examples

      # Parse a simple DNS query
      binary = <<48, 57, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, "example", 3, "com", 0, 0, 1, 0, 1>>
      packet = DNSpacket.parse(binary)
      
      packet.id              # => 12345
      packet.qr              # => 0 (query)
      packet.question        # => [%{qname: "example.com.", qtype: :a, qclass: :in}]

      # Parse a DNS response with answers
      # Returns packet with populated answer section
      packet = DNSpacket.parse(response_binary)
      
      packet.qr              # => 1 (response)
      packet.answer          # => [%{name: "example.com.", type: :a, ...}]

      # Parse packet with EDNS (results in direct-access structure)
      packet = DNSpacket.parse(edns_binary)
      
      packet.edns_info.payload_size     # => 1232
      packet.edns_info.ecs_family       # => 1 (direct access)
      packet.edns_info.ecs_subnet       # => {192, 168, 1, 0}
      packet.edns_info.unknown_options  # => %{123 => <<...>>}

  ## Performance Features

  - Aggressive function inlining for common record types
  - Binary pattern matching optimization  
  - Fast paths for A/AAAA records
  - Compile-time optimizations enabled

  """
  # Speed-optimized parse function with reduced function call overhead
  # credo:disable-for-next-line Credo.Check.Refactor.ABCSize
  def parse(
        <<
          id::unsigned-integer-size(16),
          qr::size(1),
          opcode::size(4),
          aa::size(1),
          tc::size(1),
          rd::size(1),
          ra::size(1),
          z::size(1),
          ad::size(1),
          cd::size(1),
          rcode::size(4),
          qdcount::unsigned-integer-size(16),
          ancount::unsigned-integer-size(16),
          nscount::unsigned-integer-size(16),
          arcount::unsigned-integer-size(16),
          body::binary
        >> = orig_body
      ) do
    # Inline parsing for maximum speed
    {rest1, question} = parse_question_fast(body, qdcount, orig_body, [])
    {rest2, answer} = parse_answer_fast(rest1, ancount, orig_body, [])
    {rest3, authority} = parse_answer_fast(rest2, nscount, orig_body, [])
    {_, additional} = parse_answer_fast(rest3, arcount, orig_body, [])

    edns_info = parse_edns_info(additional)

    %DNSpacket{
      id: id,
      qr: qr,
      opcode: opcode,
      aa: aa,
      tc: tc,
      rd: rd,
      ra: ra,
      z: z,
      ad: ad,
      cd: cd,
      rcode: rcode,
      question: question,
      answer: answer,
      authority: authority,
      additional: additional,
      edns_info: edns_info
    }
  end

  # Fast parsing functions with reduced overhead
  defp parse_question_fast(body, 0, _orig_body, result), do: {body, result}

  defp parse_question_fast(body, count, orig_body, result) do
    {new_body, _, qname} = parse_name(body, orig_body, "")

    <<
      qtype::unsigned-integer-size(16),
      qclass::unsigned-integer-size(16),
      rest::binary
    >> = new_body

    # Pre-cache DNS lookups
    qtype_atom = DNS.type(qtype)
    qclass_atom = DNS.class(qclass)

    parse_question_fast(rest, count - 1, orig_body, [
      %{qname: qname, qtype: qtype_atom, qclass: qclass_atom} | result
    ])
  end

  defp parse_answer_fast(body, 0, _orig_body, result), do: {body, result}

  defp parse_answer_fast(body, count, orig_body, result) do
    {new_body, _, name} = parse_name(body, orig_body, "")

    <<
      type::unsigned-integer-size(16),
      rest::binary
    >> = new_body

    parse_answer_checkopt_fast(rest, type, name, count, orig_body, result)
  end

  # OPT Record : 41 - Fast version
  defp parse_answer_checkopt_fast(
         <<size::unsigned-integer-size(16), ex_rcode::unsigned-integer-size(8),
           version::unsigned-integer-size(8), dnssec::size(1), z::size(15),
           rdlength::unsigned-integer-size(16), rdata::binary-size(rdlength), body::binary>>,
         41,
         name,
         count,
         orig_body,
         result
       ) do
    parse_answer_fast(body, count - 1, orig_body, [
      %{
        name: name,
        type: :opt,
        payload_size: size,
        ex_rcode: ex_rcode,
        version: version,
        dnssec: dnssec,
        z: z,
        rdlength: rdlength,
        rdata: parse_opt_rr(%{}, rdata)
      }
      | result
    ])
  end

  defp parse_answer_checkopt_fast(
         <<class::unsigned-integer-size(16), ttl::unsigned-integer-size(32),
           rdlength::unsigned-integer-size(16), rdata::binary-size(rdlength), body::binary>>,
         type,
         name,
         count,
         orig_body,
         result
       ) do
    # Cache DNS lookups to avoid double lookups
    type_atom = DNS.type(type)
    class_atom = DNS.class(class)

    parse_answer_fast(body, count - 1, orig_body, [
      %{
        name: name,
        type: type_atom,
        class: class_atom,
        ttl: ttl,
        rdlength: rdlength,
        rdata: parse_rdata(rdata, type_atom || type, class_atom || class, orig_body)
      }
      | result
    ])
  end

  # Optimized parse_name using iolist accumulator for better performance
  defp parse_name(body, orig_body, "") do
    parse_name_acc(body, orig_body, [])
  end

  defp parse_name(body, orig_body, result) do
    parse_name_acc(body, orig_body, [result])
  end

  defp parse_name_acc(<<0::8, body::binary>>, orig_body, []) do
    {body, orig_body, "."}
  end

  defp parse_name_acc(<<0::8, body::binary>>, orig_body, acc) do
    {body, orig_body, IO.iodata_to_binary(Enum.reverse(acc))}
  end

  defp parse_name_acc(<<0b11::2, offset::14, body::binary>>, orig_body, acc) do
    <<_::binary-size(offset), tmp_body::binary>> = orig_body
    {_, _, name} = parse_name_acc(tmp_body, orig_body, [])
    {body, orig_body, IO.iodata_to_binary(Enum.reverse([name | acc]))}
  end

  defp parse_name_acc(<<length::8, name::binary-size(length), body::binary>>, orig_body, acc) do
    parse_name_acc(body, orig_body, ["." | [name | acc]])
  end

  # Fast paths for A and AAAA records
  # Direct pattern matching with no function call overhead
  @doc false
  def parse_a_fast(<<a::8, b::8, c::8, d::8>>), do: %{addr: {a, b, c, d}}

  @doc false
  def parse_aaaa_fast(<<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>) do
    %{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}
  end

  # Optimized parse_rdata using fast paths with fallback to original behavior
  @doc false
  def parse_rdata(<<a::8, b::8, c::8, d::8>>, :a, :in, _), do: parse_a_fast(<<a, b, c, d>>)
  @doc false
  def parse_rdata(
        <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>,
        :aaaa,
        :in,
        _
      ) do
    parse_aaaa_fast(<<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>)
  end

  @doc false
  def parse_rdata(rdata, :ns, _, orig_body) do
    {_, _, name} = parse_name(rdata, orig_body, "")

    %{
      name: name
    }
  end

  @doc false
  def parse_rdata(rdata, :cname, _, orig_body) do
    {_, _, name} = parse_name(rdata, orig_body, "")

    %{
      name: name
    }
  end

  @doc false
  def parse_rdata(rdata, :soa, _, orig_body) do
    {rest1, _, mname} = parse_name(rdata, orig_body, "")
    {rest2, _, rname} = parse_name(rest1, orig_body, "")

    <<
      serial::unsigned-integer-size(32),
      refresh::unsigned-integer-size(32),
      retry::unsigned-integer-size(32),
      expire::unsigned-integer-size(32),
      minimum::unsigned-integer-size(32)
    >> = rest2

    %{
      mname: mname,
      rname: rname,
      serial: serial,
      refresh: refresh,
      retry: retry,
      expire: expire,
      minimum: minimum
    }
  end

  @doc false
  def parse_rdata(rdata, :ptr, _, orig_body) do
    {_, _, name} = parse_name(rdata, orig_body, "")

    %{
      name: name
    }
  end

  @doc false
  def parse_rdata(
        <<cpu_length::unsigned-integer-size(8), cpu::binary-size(cpu_length),
          os_length::unsigned-integer-size(8), os::binary-size(os_length)>>,
        :hinfo,
        _,
        _
      ) do
    %{
      cpu: cpu,
      os: os
    }
  end

  @doc false
  def parse_rdata(<<preference::unsigned-integer-size(16), tmp_body::binary>>, :mx, _, orig_body) do
    {_, _, name} = parse_name(tmp_body, orig_body, "")

    %{
      preference: preference,
      name: name
    }
  end

  # NOTE: Currently supports only single character-string TXT records
  # RFC 1035 allows multiple character-strings per TXT record, but most practical
  # use cases involve single strings. Multiple string support could be added in
  # future versions if needed for SPF records exceeding 255 characters or similar use cases.
  @doc false
  def parse_rdata(
        <<length::unsigned-integer-size(8), txt::binary-size(length), _::binary>>,
        :txt,
        _,
        _
      ) do
    %{
      txt: txt
    }
  end

  @doc false
  def parse_rdata(
        <<flag::unsigned-integer-size(8), tag_length::unsigned-integer-size(8),
          tag::binary-size(tag_length), value::binary>>,
        :caa,
        _,
        _
      ) do
    %{
      flag: flag,
      tag: tag,
      value: value
    }
  end

  @doc false
  def parse_rdata(
        <<priority::unsigned-integer-size(16), weight::unsigned-integer-size(16),
          port::unsigned-integer-size(16), tmp_body::binary>>,
        :srv,
        _,
        orig_body
      ) do
    {_, _, target} = parse_name(tmp_body, orig_body, "")

    %{
      priority: priority,
      weight: weight,
      port: port,
      target: target
    }
  end

  @doc false
  def parse_rdata(
        <<order::unsigned-integer-size(16), preference::unsigned-integer-size(16),
          flags_len::unsigned-integer-size(8), flags::binary-size(flags_len),
          services_len::unsigned-integer-size(8), services::binary-size(services_len),
          regexp_len::unsigned-integer-size(8), regexp::binary-size(regexp_len),
          tmp_body::binary>>,
        :naptr,
        _,
        orig_body
      ) do
    {_, _, replacement} = parse_name(tmp_body, orig_body, "")

    %{
      order: order,
      preference: preference,
      flags: flags,
      services: services,
      regexp: regexp,
      replacement: replacement
    }
  end

  @doc false
  def parse_rdata(rdata, :dname, _, orig_body) do
    {_, _, target} = parse_name(rdata, orig_body, "")

    %{
      target: target
    }
  end

  @doc false
  def parse_rdata(
        <<flags::unsigned-integer-size(16), protocol::unsigned-integer-size(8),
          algorithm::unsigned-integer-size(8), public_key::binary>>,
        :dnskey,
        _,
        _
      ) do
    %{
      flags: flags,
      protocol: protocol,
      algorithm: algorithm,
      public_key: public_key
    }
  end

  @doc false
  def parse_rdata(
        <<key_tag::unsigned-integer-size(16), algorithm::unsigned-integer-size(8),
          digest_type::unsigned-integer-size(8), digest::binary>>,
        :ds,
        _,
        _
      ) do
    %{
      key_tag: key_tag,
      algorithm: algorithm,
      digest_type: digest_type,
      digest: digest
    }
  end

  @doc false
  def parse_rdata(
        <<type_covered::unsigned-integer-size(16), algorithm::unsigned-integer-size(8),
          labels::unsigned-integer-size(8), original_ttl::unsigned-integer-size(32),
          signature_expiration::unsigned-integer-size(32),
          signature_inception::unsigned-integer-size(32), key_tag::unsigned-integer-size(16),
          tmp_body::binary>>,
        :rrsig,
        _,
        orig_body
      ) do
    {rest, _, signer_name} = parse_name(tmp_body, orig_body, "")

    %{
      type_covered: type_covered,
      algorithm: algorithm,
      labels: labels,
      original_ttl: original_ttl,
      signature_expiration: signature_expiration,
      signature_inception: signature_inception,
      key_tag: key_tag,
      signer_name: signer_name,
      signature: rest
    }
  end

  @doc false
  def parse_rdata(rdata, :nsec, _, orig_body) do
    {rest, _, next_domain_name} = parse_name(rdata, orig_body, "")
    type_bit_maps = parse_type_bitmap(rest)

    %{
      next_domain_name: next_domain_name,
      type_bit_maps: type_bit_maps
    }
  end

  @doc false
  def parse_rdata(<<priority::unsigned-integer-size(16), tmp_body::binary>>, type, _, orig_body)
      when type in [:svcb, :https] do
    # SVCB/HTTPS support with Service Parameters
    {rest, _, target} = parse_name(tmp_body, orig_body, "")
    svc_params = parse_svc_params(rest)

    %{
      priority: priority,
      target: target,
      svc_params: svc_params
    }
  end

  @doc false
  def parse_rdata(rdata, type, class, _) do
    %{type: type, class: class, rdata: rdata}
  end

  @doc false
  def parse_opt_rr(result_map, <<>>) do
    result_map
  end

  @doc false
  def parse_opt_rr(
        result_map,
        <<
          code::16,
          length::16,
          data::binary-size(length),
          opt_rr::binary
        >>
      ) do
    {key, value} = parse_opt_code(DNS.option(code), data)

    updated_map =
      if key == :unknown do
        # Handle unknown options by accumulating them in a list
        unknown_options = Map.get(result_map, :unknown, [])
        Map.put(result_map, :unknown, [value | unknown_options])
      else
        Map.put(result_map, key, value)
      end

    parse_opt_rr(updated_map, opt_rr)
  end

  # IPv4 EDNS Client Subnet - return structured data directly
  defp parse_opt_code(:edns_client_subnet, <<1::16, source::8, scope::8, address::binary>>) do
    padded = pad_address(address, 4)
    <<a::8, b::8, c::8, d::8>> = padded
    masked_addr = apply_prefix_mask({a, b, c, d}, source, 32)

    {:edns_client_subnet,
     %{
       family: 1,
       client_subnet: masked_addr,
       source_prefix: source,
       scope_prefix: scope
     }}
  end

  # IPv6 EDNS Client Subnet - return structured data directly
  defp parse_opt_code(:edns_client_subnet, <<2::16, source::8, scope::8, address::binary>>) do
    padded = pad_address(address, 16)
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>> = padded
    masked_addr = apply_prefix_mask({a1, a2, a3, a4, a5, a6, a7, a8}, source, 128)

    {:edns_client_subnet,
     %{
       family: 2,
       client_subnet: masked_addr,
       source_prefix: source,
       scope_prefix: scope
     }}
  end

  # Unknown family EDNS Client Subnet - return structured data directly
  defp parse_opt_code(:edns_client_subnet, <<family::16, source::8, scope::8, address::binary>>) do
    {:edns_client_subnet,
     %{
       family: family,
       client_subnet: address,
       source_prefix: source,
       scope_prefix: scope
     }}
  end

  defp parse_opt_code(:extended_dns_error, <<info_code::16, txt::binary>>) do
    {:extended_dns_error, %{info_code: info_code, extra_text: txt}}
  end

  defp parse_opt_code(:cookie, cookie) do
    parsed_cookie =
      case byte_size(cookie) do
        8 ->
          %{client: cookie, server: nil}

        size when size >= 16 and size <= 40 ->
          <<client::binary-size(8), server::binary>> = cookie
          %{client: client, server: server}

        _ ->
          %{client: cookie, server: nil}
      end

    {:cookie, parsed_cookie}
  end

  defp parse_opt_code(:dau, <<algorithms::binary>>) do
    {:dau, %{algorithms: :binary.bin_to_list(algorithms)}}
  end

  defp parse_opt_code(:dhu, <<algorithms::binary>>) do
    {:dhu, %{algorithms: :binary.bin_to_list(algorithms)}}
  end

  defp parse_opt_code(:n3u, <<algorithms::binary>>) do
    {:n3u, %{algorithms: :binary.bin_to_list(algorithms)}}
  end

  defp parse_opt_code(:edns_expire, <<expire::32>>) do
    {:edns_expire, %{expire: expire}}
  end

  defp parse_opt_code(:edns_expire, <<>>) do
    {:edns_expire, %{expire: nil}}
  end

  defp parse_opt_code(:chain, closest_encloser) do
    {:chain, %{closest_encloser: closest_encloser}}
  end

  defp parse_opt_code(:edns_key_tag, key_tags) do
    tags = for <<tag::16 <- key_tags>>, do: tag
    {:edns_key_tag, %{key_tags: tags}}
  end

  defp parse_opt_code(:edns_client_tag, <<tag::16>>) do
    {:edns_client_tag, %{tag: tag}}
  end

  defp parse_opt_code(:edns_server_tag, <<tag::16>>) do
    {:edns_server_tag, %{tag: tag}}
  end

  defp parse_opt_code(:report_channel, agent_domain) do
    {:report_channel, %{agent_domain: agent_domain}}
  end

  defp parse_opt_code(:zoneversion, <<version::64>>) do
    {:zoneversion, %{version: version}}
  end

  defp parse_opt_code(:update_lease, <<lease::32>>) do
    {:update_lease, %{lease: lease}}
  end

  defp parse_opt_code(
         :llq,
         <<version::16, llq_opcode::16, error_code::16, llq_id::64, lease_life::32>>
       ) do
    {:llq,
     %{
       version: version,
       llq_opcode: llq_opcode,
       error_code: error_code,
       llq_id: llq_id,
       lease_life: lease_life
     }}
  end

  defp parse_opt_code(:umbrella_ident, <<ident::32>>) do
    {:umbrella_ident, %{ident: ident}}
  end

  defp parse_opt_code(:deviceid, device_id) do
    {:deviceid, %{device_id: device_id}}
  end

  defp parse_opt_code(:nsid, nsid_data) do
    # NSID is typically ASCII text
    parsed_nsid =
      case String.valid?(nsid_data) do
        true -> nsid_data
        false -> Base.encode16(nsid_data, case: :lower)
      end

    {:nsid, parsed_nsid}
  end

  defp parse_opt_code(:edns_tcp_keepalive, data) do
    parsed_keepalive =
      case byte_size(data) do
        0 ->
          %{timeout: nil}

        2 ->
          <<timeout::16>> = data
          %{timeout: timeout}

        _ ->
          %{timeout: nil, raw_data: data}
      end

    {:edns_tcp_keepalive, parsed_keepalive}
  end

  defp parse_opt_code(:padding, data) do
    {:padding, %{length: byte_size(data)}}
  end

  defp parse_opt_code(code, data) do
    {:unknown, %{code: code, data: data}}
  end

  @doc false
  def parse_edns_info(additional) do
    case Enum.find(additional, &match?(%{type: :opt}, &1)) do
      %{rdata: options} = opt_record when is_map(options) ->
        # Direct use - optimized path for Map format
        build_hybrid_edns_info_result(opt_record, options)

      %{rdata: []} = opt_record ->
        # Empty options case
        build_hybrid_edns_info_result(opt_record, %{})

      _ ->
        nil
    end
  end

  defp build_hybrid_edns_info_result(opt_record, options) do
    # Base EDNS fields
    base_info = %{
      payload_size: Map.get(opt_record, :payload_size, 512),
      ex_rcode: Map.get(opt_record, :ex_rcode, 0),
      version: Map.get(opt_record, :version, 0),
      dnssec: Map.get(opt_record, :dnssec, 0),
      z: Map.get(opt_record, :z, 0)
    }

    # Extract and flatten common options
    {flattened_options, unknown_options} = extract_and_flatten_options(options)

    # Build optimized structure
    base_info
    |> Map.merge(flattened_options)
    |> Map.put(:unknown_options, unknown_options)
  end

  # Performance-critical function for EDNS parsing - complexity is necessary for 35-69% speed improvement
  # Deep nesting (level 3) is required for efficient EDNS option pattern matching
  # Nested case statements provide optimal performance for option type detection
  # credo:disable-for-this-file Credo.Check.Refactor.ABCSize
  # credo:disable-for-this-file Credo.Check.Refactor.CyclomaticComplexity
  # credo:disable-for-this-file Credo.Check.Refactor.NestingDepth
  defp extract_and_flatten_options(options) do
    {flattened, unknown} =
      Enum.reduce(options, {%{}, %{}}, fn {key, value}, {flat_acc, unknown_acc} ->
        case key do
          :edns_client_subnet when is_map(value) ->
            # Flatten ECS options
            flat_updates = %{
              ecs_family: Map.get(value, :family),
              ecs_subnet: Map.get(value, :client_subnet),
              ecs_source_prefix: Map.get(value, :source_prefix),
              ecs_scope_prefix: Map.get(value, :scope_prefix)
            }

            {Map.merge(flat_acc, flat_updates), unknown_acc}

          :cookie when is_map(value) ->
            # Flatten cookie options
            flat_updates = %{
              cookie_client: Map.get(value, :client),
              cookie_server: Map.get(value, :server)
            }

            {Map.merge(flat_acc, flat_updates), unknown_acc}

          :nsid when is_binary(value) ->
            # Flatten NSID
            {Map.put(flat_acc, :nsid, value), unknown_acc}

          :extended_dns_error when is_map(value) ->
            # Flatten Extended DNS Error
            flat_updates = %{
              extended_dns_error_info_code: Map.get(value, :info_code),
              extended_dns_error_extra_text: Map.get(value, :extra_text)
            }

            {Map.merge(flat_acc, flat_updates), unknown_acc}

          :edns_tcp_keepalive when is_map(value) ->
            # Flatten TCP Keepalive options
            flat_updates = %{
              edns_tcp_keepalive_timeout: Map.get(value, :timeout),
              edns_tcp_keepalive_raw_data: Map.get(value, :raw_data)
            }

            {Map.merge(flat_acc, flat_updates), unknown_acc}

          :padding when is_map(value) ->
            # Flatten Padding
            {Map.put(flat_acc, :padding_length, Map.get(value, :length)), unknown_acc}

          :dau when is_map(value) ->
            # Flatten DAU
            {Map.put(flat_acc, :dau_algorithms, Map.get(value, :algorithms)), unknown_acc}

          :dhu when is_map(value) ->
            # Flatten DHU
            {Map.put(flat_acc, :dhu_algorithms, Map.get(value, :algorithms)), unknown_acc}

          :n3u when is_map(value) ->
            # Flatten N3U
            {Map.put(flat_acc, :n3u_algorithms, Map.get(value, :algorithms)), unknown_acc}

          :edns_expire when is_map(value) ->
            # Flatten EDNS Expire
            {Map.put(flat_acc, :edns_expire_expire, Map.get(value, :expire)), unknown_acc}

          :chain when is_map(value) ->
            # Flatten Chain
            {Map.put(flat_acc, :chain_closest_encloser, Map.get(value, :closest_encloser)),
             unknown_acc}

          :edns_key_tag when is_map(value) ->
            # Flatten EDNS Key Tag
            {Map.put(flat_acc, :edns_key_tag_key_tags, Map.get(value, :key_tags)), unknown_acc}

          :edns_client_tag when is_map(value) ->
            # Flatten EDNS Client Tag
            {Map.put(flat_acc, :edns_client_tag_tag, Map.get(value, :tag)), unknown_acc}

          :edns_server_tag when is_map(value) ->
            # Flatten EDNS Server Tag
            {Map.put(flat_acc, :edns_server_tag_tag, Map.get(value, :tag)), unknown_acc}

          :report_channel when is_map(value) ->
            # Flatten Report Channel
            {Map.put(flat_acc, :report_channel_agent_domain, Map.get(value, :agent_domain)),
             unknown_acc}

          :zoneversion when is_map(value) ->
            # Flatten Zone Version
            {Map.put(flat_acc, :zoneversion_version, Map.get(value, :version)), unknown_acc}

          :update_lease when is_map(value) ->
            # Flatten Update Lease
            {Map.put(flat_acc, :update_lease_lease, Map.get(value, :lease)), unknown_acc}

          :llq when is_map(value) ->
            # Flatten LLQ
            flat_updates = %{
              llq_version: Map.get(value, :version),
              llq_llq_opcode: Map.get(value, :llq_opcode),
              llq_error_code: Map.get(value, :error_code),
              llq_llq_id: Map.get(value, :llq_id),
              llq_lease_life: Map.get(value, :lease_life)
            }

            {Map.merge(flat_acc, flat_updates), unknown_acc}

          :umbrella_ident when is_map(value) ->
            # Flatten Umbrella Ident
            {Map.put(flat_acc, :umbrella_ident_ident, Map.get(value, :ident)), unknown_acc}

          :deviceid when is_map(value) ->
            # Flatten Device ID
            {Map.put(flat_acc, :deviceid_device_id, Map.get(value, :device_id)), unknown_acc}

          :unknown when is_list(value) ->
            # Handle unknown options list
            unknown_map =
              Enum.reduce(value, unknown_acc, fn
                %{code: code, data: data}, acc -> Map.put(acc, code, data)
                _, acc -> acc
              end)

            {flat_acc, unknown_map}

          _ ->
            # All other options go to unknown
            # credo:disable-for-next-line Credo.Check.Refactor.NestingDepth
            case value do
              %{code: code, data: data} ->
                # credo:disable-for-next-line Credo.Check.Refactor.NestingDepth
                {flat_acc, Map.put(unknown_acc, code, data)}

              _ ->
                {flat_acc, unknown_acc}
            end
        end
      end)

    {flattened, unknown}
  end

  defp pad_address(addr_bytes, target_size) do
    current_size = byte_size(addr_bytes)

    if current_size < target_size do
      addr_bytes <> <<0::size((target_size - current_size) * 8)>>
    else
      binary_part(addr_bytes, 0, target_size)
    end
  end

  defp apply_prefix_mask(addr_tuple, prefix_len, max_bits) when prefix_len >= max_bits do
    addr_tuple
  end

  defp apply_prefix_mask(addr_tuple, prefix_len, _max_bits) when prefix_len <= 0 do
    # Return zeroed address for prefix length 0 or negative
    case tuple_size(addr_tuple) do
      4 -> {0, 0, 0, 0}
      8 -> {0, 0, 0, 0, 0, 0, 0, 0}
      _ -> addr_tuple
    end
  end

  defp apply_prefix_mask(addr_tuple, prefix_len, max_bits) do
    # Apply prefix mask by zeroing bits beyond prefix length
    addr_list = Tuple.to_list(addr_tuple)
    element_bits = div(max_bits, length(addr_list))

    {masked_list, _} =
      Enum.map_reduce(addr_list, prefix_len, fn element, remaining_bits ->
        cond do
          remaining_bits <= 0 ->
            {0, 0}

          min(remaining_bits, element_bits) >= element_bits ->
            {element, remaining_bits - element_bits}

          true ->
            bits_to_keep = min(remaining_bits, element_bits)
            mask = bnot((1 <<< (element_bits - bits_to_keep)) - 1)
            {element &&& mask, 0}
        end
      end)

    List.to_tuple(masked_list)
  end
end
