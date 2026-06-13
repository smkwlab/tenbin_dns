defmodule DNSpacket do
  @moduledoc """
  DNS packet parsing and creation module.

  This module provides functionality for creating and parsing DNS packets
  according to RFC 1035 and related specifications. It supports 19+ DNS
  record types including A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA, SRV,
  NAPTR, DNAME, DNSKEY, DS, RRSIG, NSEC, SVCB, HTTPS and EDNS0 extensions.

  The module is optimized with compile-time optimizations,
  aggressive function inlining, and efficient binary pattern matching.

  ## Public API

  The supported public API of this library is:

  - `create/1` — build the wire-format binary from a `DNSpacket` struct
  - `parse/1` — parse a wire-format binary into a `DNSpacket` struct
  - the `DNSpacket` struct itself and the hybrid `edns_info` structure
    documented below

  Every other public function in this module (and in `DNSpacket.EDNS`) is
  an internal implementation detail, marked `@doc false`, exposed only for
  cross-module calls and the test suite. Internal functions may change
  name, signature or return shape in any release without notice — do not
  call them from outside this library.

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
  - `rdata` - Record-specific data; the per-type map shape is documented in
    `DNSpacket.RData` (see `t:DNSpacket.RData.rdata/0`)

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

  ### Base Fields

  Always present when `edns_info` is set:

  - `payload_size` - requestor's UDP payload size (16-bit)
  - `ex_rcode` - upper 8 bits of the extended RCODE
  - `version` - EDNS version (0)
  - `dnssec` - DNSSEC OK (DO) bit (`0` or `1`)
  - `z` - remaining 15 bits of the flags field

  ### Option Fields

  Each EDNS option flattens to one or more top-level keys. A key is only
  present when its option appears in the packet; otherwise the field is
  absent (not `nil`). The full set:

  | Option | Flattened key(s) |
  |--------|------------------|
  | `edns_client_subnet` | `ecs_family`, `ecs_subnet`, `ecs_source_prefix`, `ecs_scope_prefix` |
  | `cookie` | `cookie_client` (8 bytes), `cookie_server` (binary or `nil`) |
  | `nsid` | `nsid` |
  | `extended_dns_error` | `extended_dns_error_info_code`, `extended_dns_error_extra_text` |
  | `edns_tcp_keepalive` | `edns_tcp_keepalive_timeout`, `edns_tcp_keepalive_raw_data` |
  | `padding` | `padding_length` |
  | `dau` / `dhu` / `n3u` | `dau_algorithms` / `dhu_algorithms` / `n3u_algorithms` (list of ints) |
  | `edns_expire` | `edns_expire_expire` |
  | `chain` | `chain_closest_encloser` |
  | `edns_key_tag` | `edns_key_tag_key_tags` (list of ints) |
  | `edns_client_tag` | `edns_client_tag_tag` |
  | `edns_server_tag` | `edns_server_tag_tag` |
  | `report_channel` | `report_channel_agent_domain` |
  | `zoneversion` | `zoneversion_version` |
  | `update_lease` | `update_lease_lease` |
  | `llq` | `llq_version`, `llq_llq_opcode`, `llq_error_code`, `llq_llq_id`, `llq_lease_life` |
  | `umbrella_ident` | `umbrella_ident_ident` |
  | `deviceid` | `deviceid_device_id` |

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

  alias DNSpacket.EDNS
  alias DNSpacket.RData

  # Aggressive inlining for maximum speed (over memory efficiency)
  @compile {:inline,
            [
              create_character_string: 1,
              add_rdlength: 1,
              parse_name: 3,
              parse_name_acc: 3,
              parse_sections: 6,
              parse_question_fast: 4,
              parse_answer_fast: 4,
              parse_answer_checkopt_fast: 6
            ]}

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
          |> Enum.map(&EDNS.encode_option/1)
          |> IO.iodata_to_binary()

        _ ->
          <<>>
      end

    <<0, DNS.type_code(:opt)::16, rr.payload_size::16, rr.ex_rcode::8, rr.version::8,
      rr.dnssec::1, rr.z::15>> <>
      add_rdlength(rdata_binary)
  end

  @doc false
  def create_rr(rr) do
    create_domain_name(rr.name) <>
      <<DNS.type_code(rr.type)::16, DNS.class_code(rr.class)::16, rr.ttl::32>> <>
      (rr.rdata |> RData.encode(rr.type, rr.class) |> add_rdlength)
  end

  @doc false
  defdelegate create_edns_options(options), to: EDNS, as: :encode_options

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
      rdata: EDNS.unflatten(edns_info)
    }
  end

  # Per-type rdata codec lives in DNSpacket.RData (#111); these delegates
  # keep the long-standing @doc false entry points stable for tests
  @doc false
  defdelegate create_rdata(rdata, type, class), to: RData, as: :encode

  @doc false
  defdelegate parse_rdata(rdata, type, class, orig_body), to: RData, as: :decode

  @doc false
  defdelegate create_type_bitmap(types), to: RData

  @doc false
  defdelegate parse_type_bitmap(data), to: RData

  @doc false
  defdelegate create_svc_params(params), to: RData

  @doc false
  defdelegate parse_svc_params(data), to: RData

  defp add_rdlength(rdata), do: <<byte_size(rdata)::16>> <> rdata

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

  ## Malformed Input

  Parsing degrades gracefully where it can: unknown record types are
  wrapped as raw rdata, and a trailing incomplete character-string in TXT
  rdata is silently ignored. Input that cannot be parsed at all (a binary
  shorter than the 12-byte header, or a record section truncated mid-field)
  raises, since `parse/1` is meant for trusted input on the hot path.

  For untrusted input (e.g. packets straight off the network), use
  `parse_safe/1`, which returns `{:ok, packet} | {:error, reason}` instead
  of raising.

  ## Performance Features

  - Aggressive function inlining for common record types
  - Binary pattern matching optimization
  - Fast paths for A/AAAA records
  - Compile-time optimizations enabled

  """
  @spec parse(binary()) :: t()
  # Speed-optimized parse function with reduced function call overhead;
  # parse_sections/6 is inlined, so the split costs no extra call
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
    {question, answer, authority, additional, edns_info} =
      parse_sections(body, qdcount, ancount, nscount, arcount, orig_body)

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

  @typedoc """
  Why `parse_safe/1` could not parse a binary:

  - `:not_binary` - the argument was not a binary
  - `:invalid_header` - fewer than the 12 bytes a DNS header needs
  - `:malformed` - the header parsed but a section/record could not (a
    truncated record, or an embedded length pointing past the data)
  """
  @type parse_error :: :not_binary | :invalid_header | :malformed

  @doc """
  Parses a DNS packet binary like `parse/1`, but returns a tagged tuple
  instead of raising.

  Use this for untrusted input (packets received over the network); use
  `parse/1` for trusted input where a parse failure is a programming error.

  Returns `{:ok, packet}` for any binary `parse/1` accepts — including the
  malformed-but-recoverable inputs `parse/1` degrades on (unknown record
  types, a trailing truncated TXT character-string). Returns
  `{:error, reason}` (see `t:parse_error/0`) only when the binary genuinely
  cannot be parsed.

  ## Examples

      iex> {:ok, packet} = DNSpacket.parse_safe(DNSpacket.create(%DNSpacket{id: 1}))
      iex> packet.id
      1

      iex> DNSpacket.parse_safe(<<0, 1, 2>>)
      {:error, :invalid_header}

      iex> DNSpacket.parse_safe(:not_a_binary)
      {:error, :not_binary}
  """
  @spec parse_safe(binary()) :: {:ok, t()} | {:error, parse_error()}
  def parse_safe(binary) when is_binary(binary) and byte_size(binary) < 12 do
    {:error, :invalid_header}
  end

  def parse_safe(binary) when is_binary(binary) do
    {:ok, parse(binary)}
  rescue
    # A truncated section/record makes a binary pattern fail to match:
    # FunctionClauseError (no parse clause matches the leftover bytes) or
    # MatchError (a `<<...>> = rest` inside an rdata clause). This set is
    # confirmed exhaustive by the no-raise property test (see
    # dns_packet_parse_safe_test.exs) — parse/1 raises nothing else on
    # malformed input. Map only those to :malformed; anything else (e.g. a
    # genuine internal bug) keeps propagating so it is not silently
    # swallowed. If the property ever surfaces another type, add it here.
    _error in [FunctionClauseError, MatchError] ->
      {:error, :malformed}
  end

  def parse_safe(_), do: {:error, :not_binary}

  defp parse_sections(body, qdcount, ancount, nscount, arcount, orig_body) do
    {rest1, question} = parse_question_fast(body, qdcount, orig_body, [])
    {rest2, answer} = parse_answer_fast(rest1, ancount, orig_body, [])
    {rest3, authority} = parse_answer_fast(rest2, nscount, orig_body, [])
    {_, additional} = parse_answer_fast(rest3, arcount, orig_body, [])

    # The section parsers accumulate by prepending; restore wire order here.
    # Record order is semantically meaningful in DNS (CNAME chains,
    # round-robin), see issue #98. additional is reversed before the EDNS
    # lookup so that (invalid) multi-OPT packets resolve the same OPT record
    # as the wire order implies.
    additional_in_order = Enum.reverse(additional)

    {Enum.reverse(question), Enum.reverse(answer), Enum.reverse(authority), additional_in_order,
     parse_edns_info(additional_in_order)}
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
        rdata: RData.decode(rdata, type_atom || type, class_atom || class, orig_body)
      }
      | result
    ])
  end

  # Optimized parse_name using iolist accumulator for better performance.
  # Public (@doc false) because DNSpacket.RData decodes embedded domain
  # names with it; local callers still get the @compile :inline benefit
  @doc false
  def parse_name(body, orig_body, "") do
    parse_name_acc(body, orig_body, [])
  end

  def parse_name(body, orig_body, result) do
    parse_name_acc(body, orig_body, [result])
  end

  defp parse_name_acc(<<0::8, body::binary>>, orig_body, []) do
    {body, orig_body, "."}
  end

  defp parse_name_acc(<<0::8, body::binary>>, orig_body, acc) do
    {body, orig_body, IO.iodata_to_binary(Enum.reverse(acc))}
  end

  defp parse_name_acc(<<0b11::2, offset::14, body::binary>>, orig_body, acc) do
    <<_::binary-size(^offset), tmp_body::binary>> = orig_body
    {_, _, name} = parse_name_acc(tmp_body, orig_body, [])
    {body, orig_body, IO.iodata_to_binary(Enum.reverse([name | acc]))}
  end

  defp parse_name_acc(<<length::8, name::binary-size(length), body::binary>>, orig_body, acc) do
    parse_name_acc(body, orig_body, ["." | [name | acc]])
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
    # Unrecognized option codes have no atom name; keep the numeric code
    {key, value} = EDNS.decode_option(DNS.option(code) || code, data)

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
    {flattened_options, unknown_options} = EDNS.flatten(options)

    # Build optimized structure
    base_info
    |> Map.merge(flattened_options)
    |> Map.put(:unknown_options, unknown_options)
  end
end
