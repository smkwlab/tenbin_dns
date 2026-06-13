defmodule DNSpacketParseSafeTest do
  @moduledoc """
  Tests for the non-raising `DNSpacket.parse_safe/1` (#109).

  It returns `{:ok, packet}` for anything `parse/1` would parse (including
  the inputs `parse/1` degrades gracefully on), and `{:error, reason}`
  instead of raising for input that genuinely cannot be parsed.
  """
  use ExUnit.Case, async: true

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
  end
end
