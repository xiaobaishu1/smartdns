[2026-06-14 15:27:10,565][ INFO][        request.c:85  ] result: test.com, qtype: 1, rtt: -0.1 ms, 0.0.0.0
[2026-06-14 15:27:10,565][ INFO][        context.c:414 ] result: test.com, qtype: 1, rtcode: 2, id: 49893
[2026-06-14 15:27:10,565][ INFO][        context.c:901 ] result: test.com, client: 127.0.0.1, qtype: 1, id: 49893, group: default, time: 0ms

; <<>> DiG 9.18.39-0ubuntu0.24.04.5-Ubuntu <<>> -p 61053 @127.0.0.1 test.com +tries=1
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 49893
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;test.com.			IN	A

;; Query time: 0 msec
;; SERVER: 127.0.0.1#61053(127.0.0.1) (UDP)
;; WHEN: Sun Jun 14 15:27:10 UTC 2026
;; MSG SIZE  rcvd: 26


cases/test-http2.cc:971: Failure
Expected equality of these values:
  client.GetAnswerNum()
    Which is: 0
  1

[  FAILED  ] HTTP2.BindServerHTTP2 (97 ms)
[ RUN      ] HTTP2.DownstreamDohServerConnectionReuse
unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range
[2026-06-14 15:27:10,875][ INFO][     dns_server.c:610 ] bind ip [::]:60053, type 3
[2026-06-14 15:27:10,876][ INFO][      dualstack.c:60  ] TCP-SYN ping is disabled, no ipv6 tcp-syn check feature
[2026-06-14 15:27:10,876][ INFO][      ping_icmp.c:164 ] create icmpv6 socket failed, Operation not permitted
[2026-06-14 15:27:10,876][ INFO][     dns_server.c:917 ] IPV6 is not ready or speed check is disabled, disable IPV6 features
[2026-06-14 15:27:10,876][ INFO][    server_info.c:517 ] add server 127.0.0.53:53, type: udp
[2026-06-14 15:27:11,121][ INFO][          rules.c:55  ] RULE-MATCH, type: 1, domain: reuse-one.example.com, rule: reuse-one.example.com.
[2026-06-14 15:27:11,121][ INFO][        context.c:901 ] result: reuse-one.example.com, client: 127.0.0.1, qtype: 1, id: 4097, group: default, time: 0ms
cases/test-http2.cc:1005: Failure
Value of: client.Query(second_query, &second_response)
  Actual: false
Expected: true
write request failed

[  FAILED  ] HTTP2.DownstreamDohServerConnectionReuse (541 ms)
[ RUN      ] HTTP2.DownstreamDohServerWithoutContentLengthReadsToEndStream
unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range
[2026-06-14 15:27:11,288][ INFO][     dns_server.c:610 ] bind ip [::]:60053, type 3
[2026-06-14 15:27:11,289][ INFO][      dualstack.c:60  ] TCP-SYN ping is disabled, no ipv6 tcp-syn check feature
[2026-06-14 15:27:11,289][ INFO][      ping_icmp.c:164 ] create icmpv6 socket failed, Operation not permitted
[2026-06-14 15:27:11,289][ INFO][     dns_server.c:917 ] IPV6 is not ready or speed check is disabled, disable IPV6 features
[2026-06-14 15:27:11,290][ INFO][    server_info.c:517 ] add server 127.0.0.53:53, type: udp
[2026-06-14 15:27:11,533][ INFO][          rules.c:55  ] RULE-MATCH, type: 1, domain: no-content-length.example.com, rule: no-content-length.example.com.
[2026-06-14 15:27:11,534][ INFO][        context.c:901 ] result: no-content-length.example.com, client: 127.0.0.1, qtype: 1, id: 12289, group: default, time: 0ms
[       OK ] HTTP2.DownstreamDohServerWithoutContentLengthReadsToEndStream (412 ms)
[ RUN      ] HTTP2.DownstreamDohServerReuseAfterInvalidContentLength
    Which is: 10000
h2-20x500-0-0.example.com: status=-1, error=stream ended without response, status=-1, bytes=0, 

[  FAILED  ] HTTP2.DownstreamDohServerRouterOSLikeConcurrency (778 ms)
[ RUN      ] HTTP2.DownstreamDohServerToHttp2UpstreamSingleConnectionManyConcurrentStreams
unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range
unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range
cases/test-http2.cc:1349: Failure
Expected equality of these values:
  success
    Which is: 1
  stream_count
    Which is: 1024
stream 0: stream ended without response, status=-1, bytes=0, 

[  FAILED  ] HTTP2.DownstreamDohServerToHttp2UpstreamSingleConnectionManyConcurrentStreams (706 ms)
[ RUN      ] HTTP2.DownstreamDohServerSingleConnectionPostBacklogExactDnsBody
unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range
cases/test-http2.cc:1386: Failure
Value of: client.StartQuery(query, &pending[stream_index])
  Actual: false
Expected: true
write request failed

[  FAILED  ] HTTP2.DownstreamDohServerSingleConnectionPostBacklogExactDnsBody (555 ms)
[ RUN      ] HTTP2.UdpDownstreamToHttp2UpstreamManyConcurrentQueries
unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range
unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range
HTTP2 upstream chained stress: total=1024, success=4, failure=1020, duration=1116ms, qps=917.563
cases/test-http2.cc:1461: Failure
Expected equality of these values:
  stats.success
    Which is: 4
  query_count
    Which is: 1024
h2-chain-495056334-0.com: unexpected response: id=32768, qname=h2-chain-495056334-0.com, rcode=2, ancount=0

cases/test-http2.cc:1462: Failure
Expected equality of these values:
  stats.failure
    Which is: 1020
  0
h2-chain-495056334-0.com: unexpected response: id=32768, qname=h2-chain-495056334-0.com, rcode=2, ancount=0

[  FAILED  ] HTTP2.UdpDownstreamToHttp2UpstreamManyConcurrentQueries (1923 ms)
[ RUN      ] HTTP2.DownstreamDohServerHighConcurrencyWithRetry
unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range
cases/test-http2.cc:1516: Failure
Value of: clients[client_index]->StartQuery(query, &pending_by_client[client_index][i])
  Actual: false
Expected: true
write request failed

[  FAILED  ] HTTP2.DownstreamDohServerHighConcurrencyWithRetry (279 ms)
[ RUN      ] HTTP2.ServerMultiStream
unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range
