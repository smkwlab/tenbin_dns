# DNS定数検証ガイド

## 概要
TenbinDnsライブラリのDNS定数の正当性を、RFC文書とIANAレジストリに基づいて検証する方法を記載します。

## 1. DNS Type定数の検証

### 公式リファレンス
- **IANA DNS Parameters**: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
- **RFC 1035**: Domain Names - Implementation and Specification
- **RFC 3596**: DNS Extensions to Support IPv6 (AAAA)
- **RFC 6844**: DNS Certification Authority Authorization (CAA)

### 検証すべき主要なType定数

```elixir
# lib/dns.ex より
@type_map %{
  1 => :a,          # RFC 1035 - IPv4 address
  2 => :ns,         # RFC 1035 - Authoritative name server
  5 => :cname,      # RFC 1035 - Canonical name
  6 => :soa,        # RFC 1035 - Start of authority
  12 => :ptr,       # RFC 1035 - Domain name pointer
  15 => :mx,        # RFC 1035 - Mail exchange
  16 => :txt,       # RFC 1035 - Text strings
  28 => :aaaa,      # RFC 3596 - IPv6 address
  41 => :opt,       # RFC 6891 - EDNS0
  257 => :caa       # RFC 6844 - Certification Authority Authorization
}
```

### IANAレジストリとの照合方法

1. IANA DNS Parametersページにアクセス
2. "Resource Record (RR) TYPEs"セクションを確認
3. 各タイプの番号と名前を照合

## 2. DNS Class定数の検証

### 公式リファレンス
- **RFC 1035**: Section 3.2.4 - CLASS values
- **IANA DNS Parameters**: DNS CLASSes section

```elixir
@class_map %{
  1 => :in,    # Internet (RFC 1035)
  2 => :cs,    # CSNET (obsolete)
  3 => :ch,    # CHAOS
  4 => :hs,    # Hesiod
  254 => :none,  # RFC 2136
  255 => :any    # RFC 1035
}
```

## 3. EDNS Option Code定数の検証

### 公式リファレンス
- **IANA EDNS0 Option Codes**: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
- 各オプションの個別RFC

```elixir
@option_map %{
  0 => :reserved,
  1 => :llq,                 # Long-Lived Queries (Apple)
  2 => :update_lease,        # RFC 4761
  3 => :nsid,                # RFC 5001 - Name Server Identifier
  5 => :dau,                 # RFC 6975 - DNSSEC Algorithm Understood
  6 => :dhu,                 # RFC 6975 - DS Hash Understood
  7 => :n3u,                 # RFC 6975 - NSEC3 Hash Understood
  8 => :edns_client_subnet,  # RFC 7871 - Client Subnet
  9 => :edns_expire,         # RFC 7314 - EDNS EXPIRE
  10 => :cookie,             # RFC 7873 - DNS Cookies
  11 => :edns_tcp_keepalive, # RFC 7828 - TCP Keepalive
  12 => :padding,            # RFC 7830 - Padding
  13 => :chain,              # RFC 7901 - CHAIN Query
  14 => :edns_key_tag,       # RFC 8145 - Key Tag
  15 => :extended_dns_error, # RFC 8914 - Extended DNS Errors
  16 => :edns_client_tag,    # draft-bellis-dnsop-edns-tags
  17 => :edns_server_tag,    # draft-bellis-dnsop-edns-tags
  18 => :report_channel,     # Apple - DNS Reporting
  19 => :zoneversion,        # Apple - Zone Version
  20_292 => :umbrella_ident, # Cisco Umbrella
  26_946 => :deviceid        # DSL Forum
}
```

### 検証ポイント

1. **名前の一貫性**
   - IANAレジストリの"Name"と一致しているか
   - アンダースコア区切りの命名規則に従っているか

2. **番号の正確性**
   - IANAレジストリのCode番号と一致しているか

3. **RFC準拠**
   - 各オプションのRFC仕様に準拠しているか

## 4. Response Code (RCODE)定数の検証

### 公式リファレンス
- **RFC 1035**: Section 4.1.1 - Header section format
- **IANA DNS RCODEs**: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6

```elixir
@rcode_map %{
  0 => :noerror,   # No Error (RFC 1035)
  1 => :formerr,   # Format Error (RFC 1035)
  2 => :servfail,  # Server Failure (RFC 1035)
  3 => :nxdomain,  # Non-Existent Domain (RFC 1035)
  4 => :notimp,    # Not Implemented (RFC 1035)
  5 => :refused,   # Query Refused (RFC 1035)
  16 => :badvers,  # Bad OPT Version (RFC 6891)
  23 => :badcookie # Bad/missing Server Cookie (RFC 7873)
}
```

## 5. 検証スクリプトの作成

### 自動検証スクリプト例

```elixir
defmodule DNS.ConstantsValidator do
  @moduledoc """
  DNS定数の検証ユーティリティ
  """

  # IANA公式の値（手動で更新が必要）
  @iana_types %{
    1 => "A",
    2 => "NS",
    5 => "CNAME",
    6 => "SOA",
    12 => "PTR",
    15 => "MX",
    16 => "TXT",
    28 => "AAAA",
    41 => "OPT",
    257 => "CAA"
  }

  @iana_options %{
    3 => "NSID",
    5 => "DAU",
    6 => "DHU",
    7 => "N3U",
    8 => "edns-client-subnet",
    9 => "EDNS EXPIRE",
    10 => "COOKIE",
    11 => "edns-tcp-keepalive",
    12 => "Padding",
    13 => "CHAIN",
    14 => "edns-key-tag",
    15 => "Extended DNS Error"
  }

  def validate_types do
    DNS.type_map()
    |> Enum.map(fn {code, atom} ->
      iana_name = @iana_types[code]
      expected = normalize_name(iana_name)
      actual = to_string(atom)
      
      if expected == actual do
        {:ok, code, atom}
      else
        {:error, code, atom, "Expected: #{expected}, Got: #{actual}"}
      end
    end)
  end

  defp normalize_name(nil), do: nil
  defp normalize_name(name) do
    name
    |> String.downcase()
    |> String.replace("-", "_")
  end
end
```

## 6. 検証チェックリスト

### DNS Type検証
- [ ] A (1) = IPv4 address
- [ ] NS (2) = Name Server
- [ ] CNAME (5) = Canonical Name
- [ ] SOA (6) = Start of Authority
- [ ] PTR (12) = Pointer
- [ ] MX (15) = Mail Exchange
- [ ] TXT (16) = Text
- [ ] AAAA (28) = IPv6 address
- [ ] OPT (41) = EDNS0
- [ ] CAA (257) = Certification Authority Authorization

### EDNS Option検証
- [ ] NSID (3) = Name Server Identifier
- [ ] DAU (5) = DNSSEC Algorithm Understood
- [ ] DHU (6) = DS Hash Understood
- [ ] N3U (7) = NSEC3 Hash Understood
- [ ] EDNS-CLIENT-SUBNET (8) = Client Subnet
- [ ] EDNS EXPIRE (9) = Zone Expire
- [ ] COOKIE (10) = DNS Cookies
- [ ] EDNS-TCP-KEEPALIVE (11) = TCP Keepalive
- [ ] Padding (12) = Message Padding
- [ ] CHAIN (13) = Chain Query
- [ ] EDNS-KEY-TAG (14) = Key Tag
- [ ] Extended DNS Error (15) = Extended Errors

### 命名規則の確認
- [ ] 小文字とアンダースコア区切り
- [ ] ハイフンはアンダースコアに変換
- [ ] 略語は一貫性を保つ（edns_client_subnet など）

## 7. 定期的な更新

IANAレジストリは定期的に更新されるため：

1. **四半期ごとの確認**
   - IANA DNS Parametersページの更新を確認
   - 新しいRFCの公開を確認

2. **更新手順**
   - 新しい定数を`@type_map`、`@option_map`等に追加
   - 対応するパース/作成関数を実装
   - テストケースを追加

3. **互換性の維持**
   - 既存の定数名は変更しない
   - 非推奨の定数も残す（コメントで明記）

## 8. 参考リンク

- [IANA DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
- [RFC 1035 - Domain Names](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 6891 - EDNS0](https://datatracker.ietf.org/doc/html/rfc6891)
- [DNS RFC List](https://www.isc.org/community/rfcs/dns/)
- [IANA EDNS0 Option Codes Registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)

## 結論

DNS定数の正当性確認は：
1. IANAレジストリとの照合
2. 関連RFCの確認
3. 命名規則の一貫性チェック
4. 定期的な更新確認

これらを組み合わせることで、標準準拠の信頼性の高いDNSライブラリを維持できます。