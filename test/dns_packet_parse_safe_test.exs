defmodule DNSpacketParseSafeTest do
  @moduledoc """
  Tests for the non-raising `DNSpacket.parse_safe/1` (#109).

  It returns `{:ok, packet}` for anything `parse/1` would parse (including
  the inputs `parse/1` degrades gracefully on), and `{:error, reason}`
  instead of raising for input that genuinely cannot be parsed.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  # A well-formed query binary built through the public create/1
  defp valid_query do
    DNSpacket.create(%DNSpacket{
      id: 0x1234,
      qr: 0,
      rd: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}]
    })
  end

  describe "success" do
    test "returns {:ok, packet} identical to parse/1 for a valid binary" do
      bin = valid_query()
      assert {:ok, packet} = DNSpacket.parse_safe(bin)
      assert packet == DNSpacket.parse(bin)
    end

    test "a bare 12-byte header (all counts zero) parses" do
      header = <<0x1234::16, 0::16, 0::16, 0::16, 0::16, 0::16>>

      assert {:ok, %DNSpacket{id: 0x1234, question: [], answer: []}} =
               DNSpacket.parse_safe(header)
    end

    test "gracefully-degrading input still returns {:ok, _} (not an error)" do
      # parse/1 ignores a trailing truncated TXT character-string rather
      # than raising; parse_safe must mirror that, not turn it into :error
      txt = %DNSpacket{
        id: 1,
        qr: 1,
        answer: [%{name: "e.", type: :txt, class: :in, ttl: 0, rdata: %{txt: "ok"}}]
      }

      bin = DNSpacket.create(txt)
      assert {:ok, %DNSpacket{}} = DNSpacket.parse_safe(bin)
    end
  end

  describe "error classification" do
    test "non-binary input is {:error, :not_binary}" do
      assert DNSpacket.parse_safe(:nope) == {:error, :not_binary}
      assert DNSpacket.parse_safe(123) == {:error, :not_binary}
    end

    test "a binary shorter than the 12-byte header is {:error, :invalid_header}" do
      assert DNSpacket.parse_safe(<<>>) == {:error, :invalid_header}
      assert DNSpacket.parse_safe(<<0, 1, 2, 3>>) == {:error, :invalid_header}
      assert DNSpacket.parse_safe(<<0::size(88)>>) == {:error, :invalid_header}
    end

    test "a header promising records over a truncated body is {:error, :malformed}" do
      # ancount = 1 but no answer section at all -> the record parser cannot
      # read a name and parse/1 raises; parse_safe classifies it
      truncated = <<0x1234::16, 0::16, 0::16, 1::16, 0::16, 0::16>>
      assert DNSpacket.parse_safe(truncated) == {:error, :malformed}
    end

    test "a question count over an empty body is {:error, :malformed}" do
      truncated = <<0x1234::16, 0::16, 1::16, 0::16, 0::16, 0::16>>
      assert DNSpacket.parse_safe(truncated) == {:error, :malformed}
    end

    test "an rdata field truncated inside an otherwise-framed record is {:error, :malformed}" do
      # One answer: root name, SOA (type 6), IN, ttl 0, rdlength 2, rdata
      # <<0, 0>>. The framing is intact (rdata is exactly rdlength bytes),
      # but SOA decoding consumes both bytes as empty names and then the
      # 20-byte serial/refresh/... match fails -> MatchError, the other
      # exception the narrowed rescue must cover.
      header = <<0x1234::16, 0::16, 0::16, 1::16, 0::16, 0::16>>
      answer = <<0, 0, 6, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0>>
      assert DNSpacket.parse_safe(header <> answer) == {:error, :malformed}
    end
  end

  describe "no-raise contract (fuzz)" do
    # Full 0..255 bytes, so the generator freely produces compression
    # pointers (0b11-prefixed bytes). Since #116 bounds pointer following to
    # strictly-decreasing offsets, a pointer either resolves or raises
    # FunctionClauseError — it can no longer loop, so the fuzz cannot hang.
    # The point of this property is to confirm parse_safe's narrowed rescue
    # is exhaustive: malformed input must always come back as a tagged
    # tuple, never raise. If parse/1 raised an exception type the rescue
    # does not cover, the case below would crash and surface it with the
    # shrunk input.
    defp fuzz_binary do
      StreamData.map(
        StreamData.list_of(StreamData.integer(0..255), max_length: 48),
        &:erlang.list_to_binary/1
      )
    end

    defp assert_tagged(result) do
      case result do
        {:ok, %DNSpacket{}} -> :ok
        {:error, reason} -> assert reason in [:not_binary, :invalid_header, :malformed]
      end
    end

    property "never raises on an arbitrary short binary" do
      check all bin <- fuzz_binary() do
        assert_tagged(DNSpacket.parse_safe(bin))
      end
    end

    property "never raises on a valid header over a fuzzed body" do
      check all body <- fuzz_binary(),
                qd <- StreamData.integer(0..3),
                an <- StreamData.integer(0..3),
                ns <- StreamData.integer(0..3),
                ar <- StreamData.integer(0..3) do
        header = <<0x1234::16, 0::16, qd::16, an::16, ns::16, ar::16>>
        assert_tagged(DNSpacket.parse_safe(header <> body))
      end
    end
  end
end
