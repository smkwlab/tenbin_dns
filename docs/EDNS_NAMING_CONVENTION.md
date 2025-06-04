# EDNS Naming Convention

このドキュメントでは、TenbinDnsライブラリのEDNSハイブリッド構造で使用される命名規則について説明します。

## 概要

TenbinDnsライブラリは、EDNSオプションに対してハイブリッド構造を使用しています。この構造は、一般的なEDNSオプションをトップレベルにフラット化して直接アクセスを可能にし、未知のオプションは別のマップで保持します。

## 命名規則の原則

### 1. 業界標準の略語を使用

よく知られたオプションで業界標準の略語がある場合は、その略語を使用します：

| RFC名 | 略語 | フラット化フィールド |
|-------|------|---------------------|
| `edns_client_subnet` | ECS | `ecs_family`, `ecs_subnet`, `ecs_source_prefix`, `ecs_scope_prefix` |
| `nsid` | NSID | `nsid` |
| `dau`, `dhu`, `n3u` | - | `dau_algorithms`, `dhu_algorithms`, `n3u_algorithms` |

**理由**: 
- DNSエンジニアに馴染みがある（`dig`コマンド、Go miekg/dns、Python dnspythonでも使用）
- タイピング効率が良い
- 頻繁に使用されるオプションのため

### 2. 複雑なオプションは完全名を使用

標準略語がない、または複雑なオプションの場合は完全名を使用します：

| RFC名 | フラット化フィールド |
|-------|---------------------|
| `extended_dns_error` | `extended_dns_error_info_code`, `extended_dns_error_extra_text` |
| `edns_tcp_keepalive` | `edns_tcp_keepalive_timeout`, `edns_tcp_keepalive_raw_data` |
| `cookie` | `cookie_client`, `cookie_server` |
| `padding` | `padding_length` |
| `chain` | `chain_closest_encloser` |
| `edns_key_tag` | `edns_key_tag_key_tags` |
| `edns_client_tag` | `edns_client_tag_tag` |
| `edns_server_tag` | `edns_server_tag_tag` |
| `report_channel` | `report_channel_agent_domain` |
| `zoneversion` | `zoneversion_version` |
| `update_lease` | `update_lease_lease` |
| `llq` | `llq_version`, `llq_llq_opcode`, `llq_error_code`, `llq_llq_id`, `llq_lease_life` |
| `umbrella_ident` | `umbrella_ident_ident` |
| `deviceid` | `deviceid_device_id` |

**理由**:
- 明確性と可読性
- RFC仕様との一貫性
- 誤解を避ける

### 3. 未知オプション

未知のEDNSオプションは`unknown_options`マップに格納されます：

```elixir
unknown_options: %{
  123 => <<1, 2, 3, 4>>,  # コード123の未知オプション
  456 => <<5, 6, 7, 8>>   # コード456の未知オプション
}
```

## 使用例

### アクセスパターン

```elixir
# 頻繁に使用される（短縮形で効率的）
case edns_info do
  %{ecs_family: family, ecs_subnet: subnet} when not is_nil(family) ->
    process_ecs(family, subnet)
  _ ->
    :no_ecs
end

# シンプルなオプション
if edns_info.nsid do
  IO.puts("Name Server ID: #{edns_info.nsid}")
end

# 複雑なオプション（完全名で明確）
case edns_info do
  %{extended_dns_error_info_code: code, extended_dns_error_extra_text: text} ->
    handle_extended_error(code, text)
  _ ->
    :no_extended_error
end

# 未知オプション
Enum.each(edns_info.unknown_options, fn {code, data} ->
  IO.puts("Unknown option #{code}: #{inspect(data)}")
end)
```

### EDNS情報の作成

```elixir
edns_info = %{
  payload_size: 1232,
  ex_rcode: 0,
  version: 0,
  dnssec: 0,
  z: 0,
  
  # ECS情報
  ecs_family: 1,
  ecs_subnet: {192, 168, 1, 0},
  ecs_source_prefix: 24,
  ecs_scope_prefix: 0,
  
  # Cookie情報
  cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
  cookie_server: nil,
  
  # NSID
  nsid: "ns1.example.com",
  
  # 未知オプション
  unknown_options: %{
    123 => <<1, 2, 3, 4>>
  }
}
```

## パフォーマンス影響

この命名規則とハイブリッド構造により、以下のパフォーマンス向上が実現されています：

- **ECS アクセス**: 35.3% 高速化
- **Cookie アクセス**: 69.0% 高速化
- **未知オプション アクセス**: 32.9% 高速化

## 将来の拡張

新しいEDNSオプションを追加する際は、以下の基準に従ってください：

1. **業界で標準略語がある場合**: 略語を使用（例：ECS）
2. **新しいRFCオプションで複雑な場合**: 完全名を使用
3. **単一フィールドで分かりやすい場合**: そのまま使用（例：nsid）

### 新しいオプション追加手順

1. `lib/dns.ex`に新しいオプションコードを追加
2. `lib/dns_packet.ex`の`parse_opt_code/2`関数にパーサーを追加
3. `extract_and_flatten_options/1`関数にフラット化ロジックを追加
4. `convert_hybrid_to_nested_options/1`関数に逆変換ロジックを追加
5. この命名規則に従ってフィールド名を決定
6. テストを追加

## 参考資料

- [RFC 6891 - Extension Mechanisms for DNS (EDNS(0))](https://tools.ietf.org/html/rfc6891)
- [RFC 7871 - Client Subnet in DNS Queries](https://tools.ietf.org/html/rfc7871)
- [RFC 7873 - Domain Name System (DNS) Cookies](https://tools.ietf.org/html/rfc7873)
- [DNS Option Codes - IANA Registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)