# 実機確認用 REST API 例

起動（listenは 0.0.0.0:7878） 

```shell
bash run.sh --daemon -c sample_daemon.toml
```

実機構成（0000:02:00.0 → Tx、0000:02:00.1 → Rx、ループバック）を想定した一連の流れです。

# 1. ポート追加（mode省略時はtx/rx/pcapすべて許可、rxq/txq省略時は1、rxd省略時は1024）

```shell
curl -X POST localhost:7878/ports -d '{"pci": "0000:02:00.0"}'
curl -X POST localhost:7878/ports \
  -d '{"pci": "0000:02:00.1", "rxq": 1, "txq": 1, "rxd": 2048, "mode": {"rx": true, "pcap": true}}'
```

- rxd: Rxキュー1本あたりのdescriptor数（リングサイズ）。バースト受信での取りこぼし（hw統計のrx_missed）が出る場合に増やす
- NICが受け付けない値（範囲外・アライメント違反など）はポート追加自体がエラーになる
- ポート追加時にのみ指定可能。変更する場合はDELETE後に再POSTする
- `[[dpdk.ports]]`（TOML設定）でも同じフィールド名で指定可能

# 2. 状態確認

```shell
curl localhost:7878/ports
# → {"ports":[{"pci":"0000:02:00.0","link_up":true,"mode":{...},"running":{...},"pcap_ready":false}, ...]}
```

- link_up: NICのリンク状態（Link upならtrue）。リンク状態を読み取れなかった場合はnull

# 3. キャプチャ開始 → Rx開始（この順だと取りこぼしなし）

```shell
curl -X POST localhost:7878/ports/0000:02:00.1/pcap/start
curl -X POST localhost:7878/ports/0000:02:00.1/rx/start
```

# 4. Tx開始（ボディのstreamsは sample_oneshot.toml の [[tx.streams]] と同じフィールド）

```shell
curl -X POST localhost:7878/ports/0000:02:00.0/tx/start -d '{
  "streams": [
    {
      "protocol": "ipv4",
      "src_mac": "00:11:22:33:44:55",
      "dst_mac": "66:77:88:99:aa:bb",
      "src_ip": "10.0.0.1",
      "dst_ip": "10.0.0.2",
      "count": 1000
    },
    {
      "protocol": "arp",
      "arp_op": "request",
      "src_mac": "00:11:22:33:44:55",
      "dst_mac": "ff:ff:ff:ff:ff:ff",
      "src_ip": "10.0.0.1",
      "dst_ip": "10.0.0.2"
    },
    {
      "protocol": "ipv6",
      "vlan": 100,
      "src_mac": "00:11:22:33:44:55",
      "dst_mac": "66:77:88:99:aa:bb",
      "src_ip": "2001:db8::1",
      "dst_ip": "2001:db8::2",
      "payload_len": 128,
      "hop_limit": 32
    }
  ]
}'
```

# 5. 統計取得（タスク実行中でも可）

```shell
curl localhost:7878/ports/0000:02:00.1/stats
# → {"pci":"0000:02:00.1",
#    "hw":{"rx_packets":1002,"tx_packets":0,"rx_bytes":76280,"tx_bytes":0,
#          "rx_missed":0,"rx_errors":0,"tx_errors":0,"rx_nombuf":0},
#    "sw":{"tx_frames":0,"tx_bytes":0,"rx_frames":1002,"rx_bytes":76280}}
```

- hw: NICのカウンタ（rte_eth_stats）。ポートstart以降の累積
- sw: ワーカーが数えたカウンタ。ポート追加以降の累積で、tx/rxのstart/stopをまたいで保持される
- hwはNICが受けたすべてを数えるのに対し、swはワーカーが処理したframeのみ（rxワーカー停止中の受信はhwにしか現れない）

# 6. 停止（Txは全frame送信後に自動完了するので、stopは完了後の回収も兼ねる）

```shell
curl -X POST localhost:7878/ports/0000:02:00.0/tx/stop
curl -X POST localhost:7878/ports/0000:02:00.1/rx/stop
curl -X POST localhost:7878/ports/0000:02:00.1/pcap/stop
```

# 7. pcapダウンロード（stop後のみ取得可能）

```shell
curl -o rx.pcapng localhost:7878/ports/0000:02:00.1/pcap
```

# 8. モード変更（全タスク停止中のみ。省略したキーはfalse扱い）

```shell
curl -X PUT localhost:7878/ports/0000:02:00.1/mode -d '{"tx": true, "rx": true}'
```

# 9. ポート削除（全タスク停止中のみ。削除後の再POSTでrte_dev_probeによる再attach）

```shell
curl -X DELETE localhost:7878/ports/0000:02:00.1
```

streamsの省略可能フィールド:
- count(既定1)
- payload_len(既定64、最大1500)
- vlan
- ttl/hop_limit(既定64)
- l4_protocol(既定253)
- arp_op(既定"request")
- rate_pps / rate_mbps(排他、省略時は全力送信)。

送信レートについて:
- rate_pps: 1秒あたりの送信フレーム数。例 `"rate_pps": 10000`
- rate_mbps: L2フレーム換算のMbps（FCS・プリアンブル・IFGは含まない）。小数可。例 `"rate_mbps": 100.5`
- swカウンタと同じ数え方なので、tx_bytes×8/経過秒 ≈ rate_mbps×1e6 で実測確認できる
- `[[tx.streams]]`（TOML設定）でも同じフィールド名で指定可能

エラーはすべて {"error": "..."} で返ります（不正リクエスト400、未知のパス404、シャットダウン中503）。
