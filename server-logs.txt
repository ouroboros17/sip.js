<--- Received SIP request (2312 bytes) from WSS:188.163.18.238:24715 --->
INVITE sip:+380974498412@1q2w.pics SIP/2.0
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;branch=z9hG4bK2332089
Max-Forwards: 70
To: <sip:+380974498412@1q2w.pics>
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
Call-ID: iupb42pilq6dsn3iqug0
CSeq: 5882 INVITE
Contact: <sip:ejm9amb4@r64sc02s0e6g.invalid;transport=ws;ob>
Allow: ACK,CANCEL,INVITE,MESSAGE,BYE,OPTIONS,INFO,NOTIFY,REFER
Supported: outbound
User-Agent: SIP.js/0.7.8
Content-Type: application/sdp
Content-Length: 1826

v=0
o=- 4002699638526028954 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
a=msid-semantic: WMS 9d6e66b3-1c41-4c90-b6f0-4fa5a41fc6fe
m=audio 24186 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126
c=IN IP4 188.163.18.238
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:3020520676 1 udp 2122260223 172.23.128.1 52583 typ host generation 0 network-id 1
a=candidate:3696626335 1 udp 2122194687 192.168.0.101 52584 typ host generation 0 network-id 2
a=candidate:1931275169 1 udp 1685987071 188.163.18.238 24186 typ srflx raddr 192.168.0.101 rport 52584 generation 0 network-id 2
a=candidate:3402014332 1 tcp 1518280447 172.23.128.1 9 typ host tcptype active generation 0 network-id 1
a=candidate:2727995399 1 tcp 1518214911 192.168.0.101 9 typ host tcptype active generation 0 network-id 2
a=ice-ufrag:QLyO
a=ice-pwd:RB9b9slMyC5p2u9Un5pAyEaq
a=ice-options:trickle
a=fingerprint:sha-256 5B:2E:C3:75:3E:41:84:25:AE:FA:33:37:EF:A9:8B:00:D9:14:FA:05:48:53:CD:E3:74:E2:1C:D4:39:A6:F1:B2
a=setup:actpass
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=msid:9d6e66b3-1c41-4c90-b6f0-4fa5a41fc6fe e072ba83-a972-4b72-a92e-2c7fcfe80c6d
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=rtpmap:63 red/48000/2
a=fmtp:63 111/111
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:126 telephone-event/8000
a=ssrc:2754714777 cname:mFyqrEytdRAegl2V
a=ssrc:2754714777 msid:9d6e66b3-1c41-4c90-b6f0-4fa5a41fc6fe e072ba83-a972-4b72-a92e-2c7fcfe80c6d

<--- Transmitting SIP response (489 bytes) to WSS:188.163.18.238:24715 --->
SIP/2.0 401 Unauthorized
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;rport=24715;received=188.163.18.238;branch=z9hG4bK2332089
Call-ID: iupb42pilq6dsn3iqug0
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
To: <sip:+380974498412@1q2w.pics>;tag=z9hG4bK2332089
CSeq: 5882 INVITE
WWW-Authenticate: Digest realm="asterisk",nonce="1717586273/5a5fda0a2258ced9ad6f23f29bf20985",opaque="7914cf744c1a960a",algorithm=md5,qop="auth"
Server: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Length:  0


<--- Received SIP request (274 bytes) from WSS:188.163.18.238:24715 --->
ACK sip:+380974498412@1q2w.pics SIP/2.0
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;branch=z9hG4bK2332089
To: <sip:+380974498412@1q2w.pics>;tag=z9hG4bK2332089
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
Call-ID: iupb42pilq6dsn3iqug0
Content-Length: 0
CSeq: 5882 ACK


<--- Received SIP request (2591 bytes) from WSS:188.163.18.238:24715 --->
INVITE sip:+380974498412@1q2w.pics SIP/2.0
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;branch=z9hG4bK7579268
Max-Forwards: 70
To: <sip:+380974498412@1q2w.pics>
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
Call-ID: iupb42pilq6dsn3iqug0
CSeq: 5883 INVITE
Authorization: Digest algorithm=MD5, username="92300", realm="asterisk", nonce="1717586273/5a5fda0a2258ced9ad6f23f29bf20985", uri="sip:+380974498412@1q2w.pics", response="f36bfd702fa589a4b00ab3ce36627a11", opaque="7914cf744c1a960a", qop=auth, cnonce="mrpu83t9mike", nc=00000001
Contact: <sip:ejm9amb4@r64sc02s0e6g.invalid;transport=ws;ob>
Allow: ACK,CANCEL,INVITE,MESSAGE,BYE,OPTIONS,INFO,NOTIFY,REFER
Supported: outbound
User-Agent: SIP.js/0.7.8
Content-Type: application/sdp
Content-Length: 1826

v=0
o=- 4002699638526028954 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
a=msid-semantic: WMS 9d6e66b3-1c41-4c90-b6f0-4fa5a41fc6fe
m=audio 24186 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126
c=IN IP4 188.163.18.238
a=rtcp:9 IN IP4 0.0.0.0
a=candidate:3020520676 1 udp 2122260223 172.23.128.1 52583 typ host generation 0 network-id 1
a=candidate:3696626335 1 udp 2122194687 192.168.0.101 52584 typ host generation 0 network-id 2
a=candidate:1931275169 1 udp 1685987071 188.163.18.238 24186 typ srflx raddr 192.168.0.101 rport 52584 generation 0 network-id 2
a=candidate:3402014332 1 tcp 1518280447 172.23.128.1 9 typ host tcptype active generation 0 network-id 1
a=candidate:2727995399 1 tcp 1518214911 192.168.0.101 9 typ host tcptype active generation 0 network-id 2
a=ice-ufrag:QLyO
a=ice-pwd:RB9b9slMyC5p2u9Un5pAyEaq
a=ice-options:trickle
a=fingerprint:sha-256 5B:2E:C3:75:3E:41:84:25:AE:FA:33:37:EF:A9:8B:00:D9:14:FA:05:48:53:CD:E3:74:E2:1C:D4:39:A6:F1:B2
a=setup:actpass
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendrecv
a=msid:9d6e66b3-1c41-4c90-b6f0-4fa5a41fc6fe e072ba83-a972-4b72-a92e-2c7fcfe80c6d
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=rtpmap:63 red/48000/2
a=fmtp:63 111/111
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:126 telephone-event/8000
a=ssrc:2754714777 cname:mFyqrEytdRAegl2V
a=ssrc:2754714777 msid:9d6e66b3-1c41-4c90-b6f0-4fa5a41fc6fe e072ba83-a972-4b72-a92e-2c7fcfe80c6d

  == Setting global variable 'SIPDOMAIN' to '1q2w.pics'
<--- Transmitting SIP response (318 bytes) to WSS:188.163.18.238:24715 --->
SIP/2.0 100 Trying
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;rport=24715;received=188.163.18.238;branch=z9hG4bK7579268
Call-ID: iupb42pilq6dsn3iqug0
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
To: <sip:+380974498412@1q2w.pics>
CSeq: 5883 INVITE
Server: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Length:  0


[Jun  5 07:17:53] ERROR[162488]: res_rtp_asterisk.c:1892 create_certificate_from_file: Failed to read private key from PEM file '/var/narayana/asterisk/conf/tls/asterisk.crt'
    -- Executing [+380974498412@originate-byuser:1] Set("PJSIP/92300-00000009", "p_debug_str=+380974498412 SIP.js/0.7.8  (ulaw|alaw|opus)") in new stack
    -- Executing [+380974498412@originate-byuser:2] ExecIf("PJSIP/92300-00000009", "0?Set(p_call_owner=):Set(p_call_owner=92300)") in new stack
    -- Executing [+380974498412@originate-byuser:3] NoOp("PJSIP/92300-00000009", ""Call owner is 92300"") in new stack
    -- Executing [+380974498412@originate-byuser:4] Set("PJSIP/92300-00000009", "p_transit_cid_num=3726890004") in new stack
    -- Executing [+380974498412@originate-byuser:5] Set("PJSIP/92300-00000009", "p_transit_cid_name=") in new stack
    -- Executing [+380974498412@originate-byuser:6] Set("PJSIP/92300-00000009", "p_original_exten=+380974498412") in new stack
    -- Executing [+380974498412@originate-byuser:7] Set("PJSIP/92300-00000009", "p_original_context=originate-byuser") in new stack
    -- Executing [+380974498412@originate-byuser:8] ExecIf("PJSIP/92300-00000009", "0?Macro()") in new stack
    -- Executing [+380974498412@originate-byuser:9] ExecIf("PJSIP/92300-00000009", "1?Set(p_originated_by=user)") in new stack
    -- Executing [+380974498412@originate-byuser:10] Goto("PJSIP/92300-00000009", "20") in new stack
    -- Goto (originate-byuser,+380974498412,20)
    -- Executing [+380974498412@originate-byuser:20] ExecIf("PJSIP/92300-00000009", "0?Goto(internal-command,#380974498412,1):Set(p_original_exten=380974498412)") in new stack
    -- Executing [+380974498412@originate-byuser:21] Set("PJSIP/92300-00000009", "p_did_search_result=-1") in new stack
    -- Executing [+380974498412@originate-byuser:22] ExecIf("PJSIP/92300-00000009", "0?NoOp(NEVER DID):Macro(did_search_by_num)") in new stack
    -- Executing [s@macro-did_search_by_num:1] Set("PJSIP/92300-00000009", "p_bill_request=getDIDCount?did=380974498412") in new stack
    -- Executing [s@macro-did_search_by_num:2] Macro("PJSIP/92300-00000009", "billing_request") in new stack
    -- Executing [s@macro-billing_request:1] NoOp("PJSIP/92300-00000009", "") in new stack
    -- Executing [s@macro-billing_request:2] NoOp("PJSIP/92300-00000009", "billing request!") in new stack
    -- Executing [s@macro-billing_request:3] Set("PJSIP/92300-00000009", "b_full_answer=0") in new stack
    -- Executing [s@macro-billing_request:4] ExecIf("PJSIP/92300-00000009", "0?Goto(parse-error,911,1)") in new stack
    -- Executing [s@macro-billing_request:5] ExecIf("PJSIP/92300-00000009", "0?Goto(parse-error,917,1)") in new stack
    -- Executing [s@macro-billing_request:6] ExecIf("PJSIP/92300-00000009", "0?Goto(parse-error,911,1):Set(b_value1=0)") in new stack
    -- Executing [s@macro-billing_request:7] ExecIf("PJSIP/92300-00000009", "1?MacroExit:Set(b_value2=)") in new stack
    -- Executing [s@macro-did_search_by_num:3] ExecIf("PJSIP/92300-00000009", "0?Goto(didtables-resolve,380974498412,1):MacroExit") in new stack
    -- Executing [+380974498412@originate-byuser:23] NoOp("PJSIP/92300-00000009", "-1") in new stack
    -- Executing [+380974498412@originate-byuser:24] Goto("PJSIP/92300-00000009", "30") in new stack
    -- Goto (originate-byuser,+380974498412,30)
    -- Executing [+380974498412@originate-byuser:30] Set("PJSIP/92300-00000009", "p_call_type=E") in new stack
    -- Executing [+380974498412@originate-byuser:31] ExecIf("PJSIP/92300-00000009", "1?Set(p_call_source=176.117.78.73)") in new stack
    -- Executing [+380974498412@originate-byuser:32] Goto("PJSIP/92300-00000009", "call-state-preparing,380974498412,1") in new stack
    -- Goto (call-state-preparing,380974498412,1)
    -- Executing [380974498412@call-state-preparing:1] Set("PJSIP/92300-00000009", "p_undefined_callerid=") in new stack
    -- Executing [380974498412@call-state-preparing:2] Set("PJSIP/92300-00000009", "p_trunk_priority=0") in new stack
    -- Executing [380974498412@call-state-preparing:3] ExecIf("PJSIP/92300-00000009", "0?Macro()") in new stack
    -- Executing [380974498412@call-state-preparing:4] ExecIf("PJSIP/92300-00000009", "0?Set(p_originated_by=undefined)") in new stack
    -- Executing [380974498412@call-state-preparing:5] Goto("PJSIP/92300-00000009", "10") in new stack
    -- Goto (call-state-preparing,380974498412,10)
    -- Executing [380974498412@call-state-preparing:10] Set("PJSIP/92300-00000009", "c_finished=0") in new stack
    -- Executing [380974498412@call-state-preparing:11] ExecIf("PJSIP/92300-00000009", "1?Set(p_trunk_priority=1.000000):mSet(p_trunk_priority=,p_override_priority=)") in new stack
    -- Executing [380974498412@call-state-preparing:12] NoOp("PJSIP/92300-00000009", "") in new stack
    -- Executing [380974498412@call-state-preparing:13] ExecIf("PJSIP/92300-00000009", "0?Macro()") in new stack
    -- Executing [380974498412@call-state-preparing:14] Goto("PJSIP/92300-00000009", "20") in new stack
    -- Goto (call-state-preparing,380974498412,20)
    -- Executing [380974498412@call-state-preparing:20] Set("PJSIP/92300-00000009", "p_bill_request=callPrepare?login=92300&destination=380974498412&callerid=&prior=1.000000&source=176.117.78.73&originated_by=user&from_originate=&rates_override=") in new stack
    -- Executing [380974498412@call-state-preparing:21] Macro("PJSIP/92300-00000009", "billing_request") in new stack
    -- Executing [s@macro-billing_request:1] NoOp("PJSIP/92300-00000009", "") in new stack
    -- Executing [s@macro-billing_request:2] NoOp("PJSIP/92300-00000009", "billing request!") in new stack
    -- Executing [s@macro-billing_request:3] Set("PJSIP/92300-00000009", "b_full_answer=Allowed 8820 92300~3726890004~380974498412 3726890004 UkraineMobileKyivstar PJSIP/default/sip: rdx.narayana.im -1 -1 null nrussian") in new stack
    -- Executing [s@macro-billing_request:4] ExecIf("PJSIP/92300-00000009", "0?Goto(parse-error,911,1)") in new stack
    -- Executing [s@macro-billing_request:5] ExecIf("PJSIP/92300-00000009", "0?Goto(parse-error,917,1)") in new stack
    -- Executing [s@macro-billing_request:6] ExecIf("PJSIP/92300-00000009", "0?Goto(parse-error,911,1):Set(b_value1=Allowed)") in new stack
    -- Executing [s@macro-billing_request:7] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value2=8820)") in new stack
    -- Executing [s@macro-billing_request:8] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value3=92300~3726890004~380974498412)") in new stack
    -- Executing [s@macro-billing_request:9] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value4=3726890004)") in new stack
    -- Executing [s@macro-billing_request:10] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value5=UkraineMobileKyivstar)") in new stack
    -- Executing [s@macro-billing_request:11] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value6=PJSIP/default/sip:)") in new stack
    -- Executing [s@macro-billing_request:12] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value7=rdx.narayana.im)") in new stack
    -- Executing [s@macro-billing_request:13] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value8=-1)") in new stack
    -- Executing [s@macro-billing_request:14] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value9=-1)") in new stack
    -- Executing [s@macro-billing_request:15] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value10=null)") in new stack
    -- Executing [s@macro-billing_request:16] ExecIf("PJSIP/92300-00000009", "0?MacroExit:Set(b_value11=nrussian)") in new stack
    -- Executing [380974498412@call-state-preparing:22] Macro("PJSIP/92300-00000009", "apply_callerid,3726890004") in new stack
    -- Executing [s@macro-apply_callerid:1] Set("PJSIP/92300-00000009", "c_anumber=3726890004") in new stack
    -- Executing [s@macro-apply_callerid:2] ExecIf("PJSIP/92300-00000009", "0?Set(c_anumber=3726890004)") in new stack
    -- Executing [s@macro-apply_callerid:3] ExecIf("PJSIP/92300-00000009", "0?Set(c_anumber=)") in new stack
    -- Executing [s@macro-apply_callerid:4] ExecIf("PJSIP/92300-00000009", "0?Set(c_anumber=anonymous)") in new stack
    -- Executing [380974498412@call-state-preparing:23] ExecIf("PJSIP/92300-00000009", "0?Set(c_bnumber=380974498412):Set(c_bnumber=92300~3726890004~380974498412)") in new stack
    -- Executing [380974498412@call-state-preparing:24] ExecIf("PJSIP/92300-00000009", "0?Macro(kehtima-pitch,-1,tx)") in new stack
    -- Executing [380974498412@call-state-preparing:25] ExecIf("PJSIP/92300-00000009", "0?Macro(kehtima-pitch,-1,rx)") in new stack
    -- Executing [380974498412@call-state-preparing:26] ExecIf("PJSIP/92300-00000009", "0?Macro()") in new stack
    -- Executing [380974498412@call-state-preparing:27] ExecIf("PJSIP/92300-00000009", "0?Goto(parse-error,8820,1)") in new stack
    -- Executing [380974498412@call-state-preparing:28] ExecIf("PJSIP/92300-00000009", "1?Goto(30):Goto(parse-error,925,1)") in new stack
    -- Goto (call-state-preparing,380974498412,30)
    -- Executing [380974498412@call-state-preparing:30] NoOp("PJSIP/92300-00000009", "") in new stack
    -- Executing [380974498412@call-state-preparing:31] ExecIf("PJSIP/92300-00000009", "0?Set(p_originated_call=internal)") in new stack
    -- Executing [380974498412@call-state-preparing:32] ExecIf("PJSIP/92300-00000009", "0?Goto(parse-error,351,1)") in new stack
    -- Executing [380974498412@call-state-preparing:33] ExecIf("PJSIP/92300-00000009", "0?Set(c_custom_dialparams=null)") in new stack
    -- Executing [380974498412@call-state-preparing:34] ExecIf("PJSIP/92300-00000009", "1?Set(c_bytrunk=PJSIP/default/sip:):Macro(override_route)") in new stack
    -- Executing [380974498412@call-state-preparing:35] ExecIf("PJSIP/92300-00000009", "1?NoOp(notlocal):Set(c_bytrunk=)") in new stack
    -- Executing [380974498412@call-state-preparing:36] ExecIf("PJSIP/92300-00000009", "0?Set(c_bytrunk=)") in new stack
    -- Executing [380974498412@call-state-preparing:37] ExecIf("PJSIP/92300-00000009", "0?Set(c_bytrunk=SIP/default/92300~3726890004~)") in new stack
    -- Executing [380974498412@call-state-preparing:38] Set("PJSIP/92300-00000009", "c_maxlen=8820") in new stack
    -- Executing [380974498412@call-state-preparing:39] Goto("PJSIP/92300-00000009", "originate-external,92300~3726890004~380974498412,1") in new stack
    -- Goto (originate-external,92300~3726890004~380974498412,1)
    -- Executing [92300~3726890004~380974498412@originate-external:1] Set("PJSIP/92300-00000009", "CALLERID(num)=3726890004") in new stack
    -- Executing [92300~3726890004~380974498412@originate-external:2] Set("PJSIP/92300-00000009", "CALLERID(name)=3726890004") in new stack
    -- Executing [92300~3726890004~380974498412@originate-external:3] Set("PJSIP/92300-00000009", "__DESTINATION=92300~3726890004~380974498412") in new stack
    -- Executing [92300~3726890004~380974498412@originate-external:4] Set("PJSIP/92300-00000009", "__CALL_OWNER=92300") in new stack
    -- Executing [92300~3726890004~380974498412@originate-external:5] NoOp("PJSIP/92300-00000009", "opasnoste pjsip") in new stack
    -- Executing [92300~3726890004~380974498412@originate-external:6] NoOp("PJSIP/92300-00000009", "") in new stack
    -- Executing [92300~3726890004~380974498412@originate-external:7] ExecIf("PJSIP/92300-00000009", "1?Dial(PJSIP/default/sip:92300~3726890004~380974498412@rdx.narayana.im)") in new stack
    -- Called PJSIP/default/sip:92300~3726890004~380974498412@rdx.narayana.im
<--- Transmitting SIP request (1415 bytes) to UDP:188.241.120.36:5060 --->
INVITE sip:92300~3726890004~380974498412@rdx.narayana.im SIP/2.0
Via: SIP/2.0/UDP 176.117.78.73:5060;rport;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>
Contact: <sip:asterisk@176.117.78.73:5060>
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE
Supported: 100rel, timer
Session-Expires: 1800
Min-SE: 90
Max-Forwards: 70
User-Agent: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Type: application/sdp
Content-Length:   734

v=0
o=- 350438217 350438217 IN IP4 176.117.78.73
s=Asterisk
c=IN IP4 176.117.78.73
t=0 0
m=audio 18760 RTP/SAVP 0 8 101
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:wtBMGc4wIH6/Fxz8Zwh+X3bjShKnHBL0pqw40uVY
a=ice-ufrag:4f5e630b1611ecfb644c539567fa1a94
a=ice-pwd:02e197df584c6aa16dda76eb512ca2a0
a=candidate:Hd9abb8ca 1 UDP 2130706431 fe80::216:3eff:fea6:af44 18760 typ host
a=candidate:Hb0754e49 1 UDP 2130706431 176.117.78.73 18760 typ host
a=candidate:Hd9abb8ca 2 UDP 2130706430 fe80::216:3eff:fea6:af44 18761 typ host
a=candidate:Hb0754e49 2 UDP 2130706430 176.117.78.73 18761 typ host
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:150
a=sendrecv

<--- Transmitting SIP request (1415 bytes) to UDP:188.241.120.36:5060 --->
INVITE sip:92300~3726890004~380974498412@rdx.narayana.im SIP/2.0
Via: SIP/2.0/UDP 176.117.78.73:5060;rport;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>
Contact: <sip:asterisk@176.117.78.73:5060>
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE
Supported: 100rel, timer
Session-Expires: 1800
Min-SE: 90
Max-Forwards: 70
User-Agent: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Type: application/sdp
Content-Length:   734

v=0
o=- 350438217 350438217 IN IP4 176.117.78.73
s=Asterisk
c=IN IP4 176.117.78.73
t=0 0
m=audio 18760 RTP/SAVP 0 8 101
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:wtBMGc4wIH6/Fxz8Zwh+X3bjShKnHBL0pqw40uVY
a=ice-ufrag:4f5e630b1611ecfb644c539567fa1a94
a=ice-pwd:02e197df584c6aa16dda76eb512ca2a0
a=candidate:Hd9abb8ca 1 UDP 2130706431 fe80::216:3eff:fea6:af44 18760 typ host
a=candidate:Hb0754e49 1 UDP 2130706431 176.117.78.73 18760 typ host
a=candidate:Hd9abb8ca 2 UDP 2130706430 fe80::216:3eff:fea6:af44 18761 typ host
a=candidate:Hb0754e49 2 UDP 2130706430 176.117.78.73 18761 typ host
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:150
a=sendrecv

<--- Transmitting SIP request (1415 bytes) to UDP:188.241.120.36:5060 --->
INVITE sip:92300~3726890004~380974498412@rdx.narayana.im SIP/2.0
Via: SIP/2.0/UDP 176.117.78.73:5060;rport;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>
Contact: <sip:asterisk@176.117.78.73:5060>
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE
Supported: 100rel, timer
Session-Expires: 1800
Min-SE: 90
Max-Forwards: 70
User-Agent: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Type: application/sdp
Content-Length:   734

v=0
o=- 350438217 350438217 IN IP4 176.117.78.73
s=Asterisk
c=IN IP4 176.117.78.73
t=0 0
m=audio 18760 RTP/SAVP 0 8 101
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:wtBMGc4wIH6/Fxz8Zwh+X3bjShKnHBL0pqw40uVY
a=ice-ufrag:4f5e630b1611ecfb644c539567fa1a94
a=ice-pwd:02e197df584c6aa16dda76eb512ca2a0
a=candidate:Hd9abb8ca 1 UDP 2130706431 fe80::216:3eff:fea6:af44 18760 typ host
a=candidate:Hb0754e49 1 UDP 2130706431 176.117.78.73 18760 typ host
a=candidate:Hd9abb8ca 2 UDP 2130706430 fe80::216:3eff:fea6:af44 18761 typ host
a=candidate:Hb0754e49 2 UDP 2130706430 176.117.78.73 18761 typ host
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:150
a=sendrecv

<--- Transmitting SIP request (1415 bytes) to UDP:188.241.120.36:5060 --->
INVITE sip:92300~3726890004~380974498412@rdx.narayana.im SIP/2.0
Via: SIP/2.0/UDP 176.117.78.73:5060;rport;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>
Contact: <sip:asterisk@176.117.78.73:5060>
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE
Supported: 100rel, timer
Session-Expires: 1800
Min-SE: 90
Max-Forwards: 70
User-Agent: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Type: application/sdp
Content-Length:   734

v=0
o=- 350438217 350438217 IN IP4 176.117.78.73
s=Asterisk
c=IN IP4 176.117.78.73
t=0 0
m=audio 18760 RTP/SAVP 0 8 101
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:wtBMGc4wIH6/Fxz8Zwh+X3bjShKnHBL0pqw40uVY
a=ice-ufrag:4f5e630b1611ecfb644c539567fa1a94
a=ice-pwd:02e197df584c6aa16dda76eb512ca2a0
a=candidate:Hd9abb8ca 1 UDP 2130706431 fe80::216:3eff:fea6:af44 18760 typ host
a=candidate:Hb0754e49 1 UDP 2130706431 176.117.78.73 18760 typ host
a=candidate:Hd9abb8ca 2 UDP 2130706430 fe80::216:3eff:fea6:af44 18761 typ host
a=candidate:Hb0754e49 2 UDP 2130706430 176.117.78.73 18761 typ host
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:150
a=sendrecv

<--- Transmitting SIP request (1415 bytes) to UDP:188.241.120.36:5060 --->
INVITE sip:92300~3726890004~380974498412@rdx.narayana.im SIP/2.0
Via: SIP/2.0/UDP 176.117.78.73:5060;rport;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>
Contact: <sip:asterisk@176.117.78.73:5060>
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE
Supported: 100rel, timer
Session-Expires: 1800
Min-SE: 90
Max-Forwards: 70
User-Agent: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Type: application/sdp
Content-Length:   734

v=0
o=- 350438217 350438217 IN IP4 176.117.78.73
s=Asterisk
c=IN IP4 176.117.78.73
t=0 0
m=audio 18760 RTP/SAVP 0 8 101
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:wtBMGc4wIH6/Fxz8Zwh+X3bjShKnHBL0pqw40uVY
a=ice-ufrag:4f5e630b1611ecfb644c539567fa1a94
a=ice-pwd:02e197df584c6aa16dda76eb512ca2a0
a=candidate:Hd9abb8ca 1 UDP 2130706431 fe80::216:3eff:fea6:af44 18760 typ host
a=candidate:Hb0754e49 1 UDP 2130706431 176.117.78.73 18760 typ host
a=candidate:Hd9abb8ca 2 UDP 2130706430 fe80::216:3eff:fea6:af44 18761 typ host
a=candidate:Hb0754e49 2 UDP 2130706430 176.117.78.73 18761 typ host
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:150
a=sendrecv

<--- Transmitting SIP request (1415 bytes) to UDP:188.241.120.36:5060 --->
INVITE sip:92300~3726890004~380974498412@rdx.narayana.im SIP/2.0
Via: SIP/2.0/UDP 176.117.78.73:5060;rport;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>
Contact: <sip:asterisk@176.117.78.73:5060>
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE
Supported: 100rel, timer
Session-Expires: 1800
Min-SE: 90
Max-Forwards: 70
User-Agent: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Type: application/sdp
Content-Length:   734

v=0
o=- 350438217 350438217 IN IP4 176.117.78.73
s=Asterisk
c=IN IP4 176.117.78.73
t=0 0
m=audio 18760 RTP/SAVP 0 8 101
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:wtBMGc4wIH6/Fxz8Zwh+X3bjShKnHBL0pqw40uVY
a=ice-ufrag:4f5e630b1611ecfb644c539567fa1a94
a=ice-pwd:02e197df584c6aa16dda76eb512ca2a0
a=candidate:Hd9abb8ca 1 UDP 2130706431 fe80::216:3eff:fea6:af44 18760 typ host
a=candidate:Hb0754e49 1 UDP 2130706431 176.117.78.73 18760 typ host
a=candidate:Hd9abb8ca 2 UDP 2130706430 fe80::216:3eff:fea6:af44 18761 typ host
a=candidate:Hb0754e49 2 UDP 2130706430 176.117.78.73 18761 typ host
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:150
a=sendrecv

<--- Received SIP response (648 bytes) from UDP:188.241.120.36:5060 --->
SIP/2.0 100 Trying
Via: SIP/2.0/UDP 176.117.78.73:5060;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402;received=176.117.78.73;rport=5060
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Server: Asterisk PBX 13.14.1~dfsg-2+deb9u4
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
Supported: replaces, timer
Session-Expires: 1800;refresher=uas
Contact: <sip:92300~3726890004~380974498412@188.241.120.36:5060>
Content-Length: 0


<--- Received SIP response (648 bytes) from UDP:188.241.120.36:5060 --->
SIP/2.0 100 Trying
Via: SIP/2.0/UDP 176.117.78.73:5060;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402;received=176.117.78.73;rport=5060
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Server: Asterisk PBX 13.14.1~dfsg-2+deb9u4
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
Supported: replaces, timer
Session-Expires: 1800;refresher=uas
Contact: <sip:92300~3726890004~380974498412@188.241.120.36:5060>
Content-Length: 0


<--- Received SIP response (648 bytes) from UDP:188.241.120.36:5060 --->
SIP/2.0 100 Trying
Via: SIP/2.0/UDP 176.117.78.73:5060;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402;received=176.117.78.73;rport=5060
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Server: Asterisk PBX 13.14.1~dfsg-2+deb9u4
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
Supported: replaces, timer
Session-Expires: 1800;refresher=uas
Contact: <sip:92300~3726890004~380974498412@188.241.120.36:5060>
Content-Length: 0


<--- Received SIP response (1089 bytes) from UDP:188.241.120.36:5060 --->
SIP/2.0 183 Session Progress
Via: SIP/2.0/UDP 176.117.78.73:5060;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402;received=176.117.78.73;rport=5060
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>;tag=as33fa74b6
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Server: Asterisk PBX 13.14.1~dfsg-2+deb9u4
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
Supported: replaces, timer
Session-Expires: 1800;refresher=uas
Contact: <sip:92300~3726890004~380974498412@188.241.120.36:5060>
Content-Type: application/sdp
Require: timer
Content-Length: 367

v=0
o=root 1892088694 1892088694 IN IP4 188.241.120.36
s=Asterisk PBX 13.14.1~dfsg-2+deb9u4
c=IN IP4 188.241.120.36
t=0 0
m=audio 12320 RTP/SAVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=maxptime:150
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:lFAOTLxKhwQbacXXnFCcS0Dewq9dfijd/in/x45q

    -- PJSIP/default-0000000a is making progress passing it to PJSIP/92300-00000009
<--- Transmitting SIP response (1322 bytes) to WSS:188.163.18.238:24715 --->
SIP/2.0 183 Session Progress
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;rport=24715;received=188.163.18.238;branch=z9hG4bK7579268
Call-ID: iupb42pilq6dsn3iqug0
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
To: <sip:+380974498412@1q2w.pics>;tag=bb6a8be6-08b7-453c-9812-4590d4c22b20
CSeq: 5883 INVITE
Server: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Contact: <sip:176.117.78.73:8089;transport=ws>
Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE
Content-Type: application/sdp
Content-Length:   795

v=0
o=- 820882586 4 IN IP4 176.117.78.73
s=Asterisk
c=IN IP4 176.117.78.73
t=0 0
a=msid-semantic:WMS *
a=group:BUNDLE 0
m=audio 16600 UDP/TLS/RTP/SAVPF 0 8 111 126
a=connection:new
a=setup:active
a=fingerprint:SHA-256
a=ice-ufrag:0f5d6ba402212f0536b973663ab1cbc9
a=ice-pwd:25bebac06fc6c397774915561b8499e2
a=candidate:Hd9abb8ca 1 UDP 2130706431 fe80::216:3eff:fea6:af44 16600 typ host
a=candidate:Hb0754e49 1 UDP 2130706431 176.117.78.73 16600 typ host
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:111 opus/48000/2
a=rtpmap:126 telephone-event/8000
a=fmtp:126 0-16
a=ptime:20
a=maxptime:60
a=sendrecv
a=rtcp-mux
a=ssrc:359635792 cname:27694989-ea33-4c9b-a835-0e95ef43ad39
a=msid:ffc06a45-0981-4da2-9685-fdd9f5be8179 79731a2e-638e-480d-a6af-6bea23fadc29
a=mid:0

    -- PJSIP/default-0000000a is making progress passing it to PJSIP/92300-00000009
<--- Transmitting SIP response (1322 bytes) to WSS:188.163.18.238:24715 --->
SIP/2.0 183 Session Progress
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;rport=24715;received=188.163.18.238;branch=z9hG4bK7579268
Call-ID: iupb42pilq6dsn3iqug0
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
To: <sip:+380974498412@1q2w.pics>;tag=bb6a8be6-08b7-453c-9812-4590d4c22b20
CSeq: 5883 INVITE
Server: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE
Contact: <sip:176.117.78.73:8089;transport=ws>
Content-Type: application/sdp
Content-Length:   795

v=0
o=- 820882586 4 IN IP4 176.117.78.73
s=Asterisk
c=IN IP4 176.117.78.73
t=0 0
a=msid-semantic:WMS *
a=group:BUNDLE 0
m=audio 16600 UDP/TLS/RTP/SAVPF 0 8 111 126
a=connection:new
a=setup:active
a=fingerprint:SHA-256
a=ice-ufrag:0f5d6ba402212f0536b973663ab1cbc9
a=ice-pwd:25bebac06fc6c397774915561b8499e2
a=candidate:Hd9abb8ca 1 UDP 2130706431 fe80::216:3eff:fea6:af44 16600 typ host
a=candidate:Hb0754e49 1 UDP 2130706431 176.117.78.73 16600 typ host
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:111 opus/48000/2
a=rtpmap:126 telephone-event/8000
a=fmtp:126 0-16
a=ptime:20
a=maxptime:60
a=sendrecv
a=rtcp-mux
a=ssrc:359635792 cname:27694989-ea33-4c9b-a835-0e95ef43ad39
a=msid:ffc06a45-0981-4da2-9685-fdd9f5be8179 79731a2e-638e-480d-a6af-6bea23fadc29
a=mid:0

<--- Received SIP response (1075 bytes) from UDP:188.241.120.36:5060 --->
SIP/2.0 200 OK
Via: SIP/2.0/UDP 176.117.78.73:5060;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402;received=176.117.78.73;rport=5060
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>;tag=as33fa74b6
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Server: Asterisk PBX 13.14.1~dfsg-2+deb9u4
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
Supported: replaces, timer
Session-Expires: 1800;refresher=uas
Contact: <sip:92300~3726890004~380974498412@188.241.120.36:5060>
Content-Type: application/sdp
Require: timer
Content-Length: 367

v=0
o=root 1892088694 1892088694 IN IP4 188.241.120.36
s=Asterisk PBX 13.14.1~dfsg-2+deb9u4
c=IN IP4 188.241.120.36
t=0 0
m=audio 12320 RTP/SAVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=maxptime:150
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:lFAOTLxKhwQbacXXnFCcS0Dewq9dfijd/in/x45q

<--- Transmitting SIP request (479 bytes) to UDP:188.241.120.36:5060 --->
ACK sip:92300~3726890004~380974498412@188.241.120.36:5060 SIP/2.0
Via: SIP/2.0/UDP 176.117.78.73:5060;rport;branch=z9hG4bKPjb8a2caf9-71b3-45a8-a667-e4fc8d03d318
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>;tag=as33fa74b6
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 ACK
Max-Forwards: 70
User-Agent: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Length:  0


    -- PJSIP/default-0000000a answered PJSIP/92300-00000009
<--- Transmitting SIP response (1334 bytes) to WSS:188.163.18.238:24715 --->
SIP/2.0 200 OK
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;rport=24715;received=188.163.18.238;branch=z9hG4bK7579268
Call-ID: iupb42pilq6dsn3iqug0
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
To: <sip:+380974498412@1q2w.pics>;tag=bb6a8be6-08b7-453c-9812-4590d4c22b20
CSeq: 5883 INVITE
Server: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE
Contact: <sip:176.117.78.73:8089;transport=ws>
Supported: 100rel, timer
Content-Type: application/sdp
Content-Length:   795

v=0
o=- 820882586 4 IN IP4 176.117.78.73
s=Asterisk
c=IN IP4 176.117.78.73
t=0 0
a=msid-semantic:WMS *
a=group:BUNDLE 0
m=audio 16600 UDP/TLS/RTP/SAVPF 0 8 111 126
a=connection:new
a=setup:active
a=fingerprint:SHA-256
a=ice-ufrag:0f5d6ba402212f0536b973663ab1cbc9
a=ice-pwd:25bebac06fc6c397774915561b8499e2
a=candidate:Hd9abb8ca 1 UDP 2130706431 fe80::216:3eff:fea6:af44 16600 typ host
a=candidate:Hb0754e49 1 UDP 2130706431 176.117.78.73 16600 typ host
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:111 opus/48000/2
a=rtpmap:126 telephone-event/8000
a=fmtp:126 0-16
a=ptime:20
a=maxptime:60
a=sendrecv
a=rtcp-mux
a=ssrc:359635792 cname:27694989-ea33-4c9b-a835-0e95ef43ad39
a=msid:ffc06a45-0981-4da2-9685-fdd9f5be8179 79731a2e-638e-480d-a6af-6bea23fadc29
a=mid:0

    -- Channel PJSIP/default-0000000a joined 'simple_bridge' basic-bridge <1ca8ec70-3a3f-4afb-8ea4-4f4061ee0310>
    -- Channel PJSIP/92300-00000009 joined 'simple_bridge' basic-bridge <1ca8ec70-3a3f-4afb-8ea4-4f4061ee0310>
<--- Received SIP request (369 bytes) from WSS:188.163.18.238:24715 --->
ACK sip:176.117.78.73:8089;transport=ws SIP/2.0
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;branch=z9hG4bK3294832
Max-Forwards: 70
To: <sip:+380974498412@1q2w.pics>;tag=bb6a8be6-08b7-453c-9812-4590d4c22b20
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
Call-ID: iupb42pilq6dsn3iqug0
CSeq: 5883 ACK
Supported: outbound
User-Agent: SIP.js/0.7.8
Content-Length: 0


<--- Received SIP request (421 bytes) from WSS:188.163.18.238:24715 --->
BYE sip:176.117.78.73:8089;transport=ws SIP/2.0
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;branch=z9hG4bK3770415
Max-Forwards: 70
To: <sip:+380974498412@1q2w.pics>;tag=bb6a8be6-08b7-453c-9812-4590d4c22b20
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
Call-ID: iupb42pilq6dsn3iqug0
CSeq: 5884 BYE
Reason: SIP ;cause=488 ;text="Not Acceptable Here"
Supported: outbound
User-Agent: SIP.js/0.7.8
Content-Length: 0


<--- Transmitting SIP response (352 bytes) to WSS:188.163.18.238:24715 --->
SIP/2.0 200 OK
Via: SIP/2.0/WSS r64sc02s0e6g.invalid;rport=24715;received=188.163.18.238;branch=z9hG4bK3770415
Call-ID: iupb42pilq6dsn3iqug0
From: "MRX" <sip:92300@1q2w.pics>;tag=mua0bcikah
To: <sip:+380974498412@1q2w.pics>;tag=bb6a8be6-08b7-453c-9812-4590d4c22b20
CSeq: 5884 BYE
Server: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Length:  0


    -- Channel PJSIP/92300-00000009 left 'simple_bridge' basic-bridge <1ca8ec70-3a3f-4afb-8ea4-4f4061ee0310>
    -- Channel PJSIP/default-0000000a left 'simple_bridge' basic-bridge <1ca8ec70-3a3f-4afb-8ea4-4f4061ee0310>
  == Spawn extension (originate-external, 92300~3726890004~380974498412, 7) exited non-zero on 'PJSIP/92300-00000009'
    -- Executing [h@originate-external:1] ExecIf("PJSIP/92300-00000009", "1?Macro(resolve_finish_status):Hangup()") in new stack
    -- Executing [s@macro-resolve_finish_status:1] Set("PJSIP/92300-00000009", "r_calltime=0") in new stack
    -- Executing [s@macro-resolve_finish_status:2] Set("PJSIP/92300-00000009", "r_status_int=16") in new stack
    -- Executing [s@macro-resolve_finish_status:3] Set("PJSIP/92300-00000009", "r_status_str=ANSWER") in new stack
    -- Executing [h@originate-external:2] Macro("PJSIP/92300-00000009", "process_call_finish") in new stack
    -- Executing [s@macro-process_call_finish:1] Set("PJSIP/92300-00000009", "c_finished=1") in new stack
    -- Executing [s@macro-process_call_finish:2] NoOp("PJSIP/92300-00000009", "92300,status") in new stack
    -- Executing [s@macro-process_call_finish:3] ExecIf("PJSIP/92300-00000009", "1?NoOp(NO DID HERE):Set(tmp_postfix=&is_did=)") in new stack
    -- Executing [s@macro-process_call_finish:4] Set("PJSIP/92300-00000009", "p_bill_request=callFinish?login=92300&destination=92300~3726890004~380974498412&callerid=3726890004&length=0&status=16ANSWER&prior=1.000000&rates_override=") in new stack
    -- Executing [s@macro-process_call_finish:5] ExecIf("PJSIP/92300-00000009", "1?NoOp():Macro(billing_request)") in new stack
    -- Executing [s@macro-process_call_finish:6] NoOp("PJSIP/92300-00000009", "Allowed 8820 92300~3726890004~380974498412 3726890004 UkraineMobileKyivstar PJSIP/default/sip: rdx.narayana.im -1 -1 null nrussian") in new stack
    -- Executing [s@macro-process_call_finish:7] NoOp("PJSIP/92300-00000009", "TDD ") in new stack
    -- Executing [h@originate-external:3] Hangup("PJSIP/92300-00000009", "") in new stack
  == Spawn extension (originate-external, h, 3) exited non-zero on 'PJSIP/92300-00000009'
<--- Transmitting SIP request (503 bytes) to UDP:188.241.120.36:5060 --->
BYE sip:92300~3726890004~380974498412@188.241.120.36:5060 SIP/2.0
Via: SIP/2.0/UDP 176.117.78.73:5060;rport;branch=z9hG4bKPj0193c433-fd1e-4f19-b63b-907158698658
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>;tag=as33fa74b6
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28337 BYE
Reason: Q.850;cause=16
Max-Forwards: 70
User-Agent: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Length:  0


<--- Received SIP response (1075 bytes) from UDP:188.241.120.36:5060 --->
SIP/2.0 200 OK
Via: SIP/2.0/UDP 176.117.78.73:5060;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402;received=176.117.78.73;rport=5060
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>;tag=as33fa74b6
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Server: Asterisk PBX 13.14.1~dfsg-2+deb9u4
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
Supported: replaces, timer
Session-Expires: 1800;refresher=uas
Contact: <sip:92300~3726890004~380974498412@188.241.120.36:5060>
Content-Type: application/sdp
Require: timer
Content-Length: 367

v=0
o=root 1892088694 1892088694 IN IP4 188.241.120.36
s=Asterisk PBX 13.14.1~dfsg-2+deb9u4
c=IN IP4 188.241.120.36
t=0 0
m=audio 12320 RTP/SAVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=maxptime:150
a=sendrecv
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:lFAOTLxKhwQbacXXnFCcS0Dewq9dfijd/in/x45q

<--- Transmitting SIP request (479 bytes) to UDP:188.241.120.36:5060 --->
ACK sip:92300~3726890004~380974498412@188.241.120.36:5060 SIP/2.0
Via: SIP/2.0/UDP 176.117.78.73:5060;rport;branch=z9hG4bKPjb8a2caf9-71b3-45a8-a667-e4fc8d03d318
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>;tag=as33fa74b6
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 ACK
Max-Forwards: 70
User-Agent: Asterisk PBX 16.2.1~dfsg-1+deb12u3
Content-Length:  0


<--- Received SIP response (572 bytes) from UDP:188.241.120.36:5060 --->
SIP/2.0 487 Request Terminated
Via: SIP/2.0/UDP 176.117.78.73:5060;branch=z9hG4bKPj7a4b3743-e548-40d6-8527-61536a2fa402;received=176.117.78.73;rport=5060
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>;tag=as33fa74b6
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28336 INVITE
Server: Asterisk PBX 13.14.1~dfsg-2+deb9u4
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
Supported: replaces, timer
Content-Length: 0


<--- Received SIP response (553 bytes) from UDP:188.241.120.36:5060 --->
SIP/2.0 200 OK
Via: SIP/2.0/UDP 176.117.78.73:5060;branch=z9hG4bKPj0193c433-fd1e-4f19-b63b-907158698658;received=176.117.78.73;rport=5060
From: "3726890004" <sip:3726890004@176.117.78.73>;tag=df1f9f6d-1c2c-4c64-975c-59dd45df253d
To: <sip:92300~3726890004~380974498412@rdx.narayana.im>;tag=as33fa74b6
Call-ID: e2a9c023-a3d1-469e-856c-4139d31056a1
CSeq: 28337 BYE
Server: Asterisk PBX 13.14.1~dfsg-2+deb9u4
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
Supported: replaces, timer
Content-Length: 0


vps4hgf2*CLI>
