# TODO

**2026-09-14 재감사** — `feat/xfr-tsig`의 `5cfd039c` 기준 코드·테스트·설정 및
후속 커밋 검토는 [코드·테스트·설정 재감사](docs/audit-cleanup.md)에 정리했다.
아래 진행 표와 초기 관찰은 작업 이력이다. 특히 #41의 TTL/홀드다운,
#54의 IXFR 임계값, #56의 캐시 단위는 후속 커밋에서 달라졌으므로 재감사의 최종 상태를 참고한다.

전체 코드베이스 감사 결과. 모든 항목은 해당 파일을 직접 읽어 검증했다.
줄 번호는 `70c4eff` 기준. 그 뒤 커밋이 많이 쌓여 낡은 것이 있다.
남은 항목의 재검증 결과는 각 항목에 적는다.

**분류 기준**

| 등급 | 의미 |
| --- | --- |
| P0 | 사용자가 실제로 부딪히는 오동작 |
| P1 | 보안 · 프로토콜 정합성 |
| P2 | 기능 공백 |
| P3 | 운영 · CI · 테스트 |

**진행 상황** — 작업 브랜치 `fix/audit-cleanups`.
완료 항목은 제목에 가로선을 긋고 커밋 해시를 적는다.

| 항목 | 커밋 |
| --- | --- |
| 12. notify_timeout_secs 기본값 | `3997348b` |
| 13. trace 레벨 target (타임스탬프는 남음) | `8b29da05` |
| 60. stdout 출력 | `8b29da05` |
| 67. 패키지 설정 파일 권한 | `a5c796a0` |
| 11. 존파일 오류 줄 번호 | `9670fbb6` |
| 51. created_at 인덱스 | `bc616569` |
| 5. DNS bind 실패 전파 | `cdc80f13` |
| 3, 4. SIGTERM 과 graceful shutdown | `a656eee2` |
| 9. REFUSED 응답 | `2f11f122` |
| 8. NOTIFY 오응답, opcode NOTIMP | `5e77ef0b` |
| 6. 유지보수 태스크 감독 | `135c2cfd` |
| 2. MX/SRV priority 확정 저장 + CHECK | `d2ee1ae6` |
| QR=1 응답 패킷에 응답하던 문제 | `08a0b1d2` |
| 15. SOA 쿼리 ACL | `2b7202b6` `8a351764` |
| 19. UDP 인라인 처리, 동시성 상한 | `20f0bb87` |
| 17. unsigned nsupdate 주소 제한 | `2a9d577f` |
| 16. ACL 호스트명 캐시·타임아웃 | `1c2582be` `089d03be` |
| 22. 페이지 크기 기본값·상한 | `3932e5e4` |
| 59. 설정 검증 (포트 0, 충돌, 주소) | `c35c5e99` |
| 36. DNSSEC 서명 실패 전용 코드 | `17fa6a34` |
| 37. CLI 종료 코드 분류 | `26947de5` |
| 69. UDP 전송 계수 | `d2240216` |
| 13. 로그 타임스탬프 | `8602292e` |
| 36. 오류 응답 형식 통일 | `37727ef4` |
| 70. SQLite 파일 자동 생성 | `ae30e7c6` |
| 44. DS digest 판단 불가 구분 | `30665191` |
| 36 부가, 55. CLI 힌트 전면, IXFR 시리얼 주석 | `ea748093` |
| 45, 46. 부모 탐색 제거, enable 시 부모 필수 | `88ad55d4` |
| 7. 시각을 앱 시계 하나로 통일 | `e4791875` |
| SQLite 시각 문자열 비교 (7번의 회귀 + 기존 버그) | `5be9c17d` |
| 53. 만료 임박 서명 조회 인덱스 탐색 | `3e81452c` |
| 56. 존 캐시 바이트 상한 + 설정 | `cd2e3326` `d0a868b9` |
| 54. IXFR 델타 상한 (RFC 1995 §2 폴백) | `4f4dd7e6` |

---

## P0 — 동작 결함

### ~~1. RRset TTL을 API로 변경할 수 없다~~ (재평가 후 폐기)

**재평가** — "변경 불가" 는 과장이었다. 세 가지가 확인됐다.
레코드가 하나뿐인 RRset 은 지금도 바뀐다(비교 대상이 없다).
`POST /zones/{name}/import` 의 `upsert` 모드에 그 RRset 의 줄만 보내면
**한 번의 원자적 호출로** TTL 이 바뀌고, 무관한 레코드는 건드리지 않으며 serial 도 한 번만 오른다.
CLI 에도 `bindizr zone import` 로 같은 경로가 있다.
지우고 다시 넣는 방법은 5 회 호출에 serial 5 회 증가라 쓸 이유가 없다.

**폐기** — 오류 메시지에 import upsert 경로를 덧붙이는 안을 만들어 검증까지 했으나
소유자 판단으로 기존 메시지가 충분하다고 결정됐다. 되돌렸다. **다시 제안하지 않는다.**

**검토했다가 접은 방안** — 레코드 하나의 TTL 수정을 RRset 전체에 번지게 하는 것.
PUT 하나가 형제를 조용히 바꾸고, 저널에 형제 변경을 모두 남겨야 하며,
다른 RRset 으로 이동하는 경우의 규칙을 새로 정해야 한다.
이미 한 번의 호출로 되는 일에 그만큼의 위험을 더할 이유가 약하다.

- **위치**: `crates/bindizr-service/src/record/validation/mod.rs:86-88`, `:147-156`
- **현재**: `records_at_name`은 `except_record_id`로 **자기 자신만** 제외한다.
  그 뒤 RFC 2181 Section 5.2 검사가 같은 이름·타입의 다른 레코드와 TTL이
  다르면 `record_conflict`를 던진다.
- **문제**: 같은 RRset에 레코드가 둘 이상이면 r1의 TTL을 바꿀 때 r2가 막고,
  r2를 바꿀 때 r1이 막는다. 어느 쪽으로도 진행이 불가능하다.
  `PUT /records/{id}`는 TTL을 받지만 (`record/update.rs:75-81`) 통과할 수 없다.
- **우회로**: `POST /zones/{name}/import` 의 `upsert` / `replace` 모드뿐.
  (`record/import.rs:307`, `:322-327`)
- **조치안**: RRset 단위 TTL 변경 엔드포인트를 두거나,
  단일 레코드 TTL 변경 시 같은 RRset 전체를 함께 갱신한다.
  후자를 택하면 저널 기록도 RRset 전체 변경으로 남겨야 IXFR이 맞는다.

### ~~2. priority가 NULL인 MX/SRV는 nsupdate로 삭제되지 않는다~~

**완료** — `d2ee1ae6`. `RecordType::stored_priority` 로 MX/SRV 는 쓰기 시점에 값을 확정한다.
create·bulk 의 공통 진입점 `parse_record`, 존파일 import, 레코드 수정, nsupdate 네 곳에 적용했다.
세 백엔드에 `CHECK ((record_type IN ('MX','SRV')) = (priority IS NOT NULL))` 를 넣어
서비스 계층 검증에만 있던 짝을 DB 가 강제한다.

**검증** — 같은 시나리오를 변경 전후로 실행. 전: 저장 `None`, nsupdate 삭제 후 MX 1 개 남음,
`?priority=10` 0 건. 후: 저장 `10`, 삭제 성공, 필터 1 건. 실제 `nsupdate` 도구를 썼다.
작업 중 `create` 가 `parse_record` 의 값을 `..` 로 버리는 버그를 만들었는데 CHECK 제약이 즉시 잡았다.

**판단 근거** — "확정 저장하면 존 기본값과 구분이 안 되지 않나" 라는 지적이 있었다.
TTL 은 `$TTL` 상속이 DNS 의 실제 개념이지만 MX preference 와 SRV priority 는 rdata 의 필수 필드라
상속 개념이 없다. 존 SOA 타이머를 미지정 시 확정 저장하는 것과 같은 방식이다.
컬럼은 nullable 로 남는다. 12 개 타입 중 둘만 쓰기 때문이다.

- ~~**위치**: `crates/bindizr-service/src/dynamic_update/mod.rs:377-381`~~
- ~~**현재**: 삭제 매칭이 `record.priority != Some(priority)` 이면 `continue`.~~
  ~~한편 wire 인코딩과 canonical 비교는 NULL을 10으로 채운다.~~
  ~~(`crates/bindizr-core/src/dns/record/value.rs:10` `DEFAULT_PRIORITY = 10`)~~
- ~~**문제**: API로 `priority: null` 로 만든 MX는 존에서 `MX 10 ...` 으로 서빙되지만,~~
  ~~`nsupdate delete host MX 10 mail.example.com.` 은 조용히 아무것도 지우지 않고~~
  ~~NOERROR를 반환한다. 추가 경로는 `canonical_value`를 거쳐 같은 기본값을 적용하므로~~
  ~~비대칭이다.~~
- ~~**파급**: 같은 원인으로 `?priority=10` 필터도 이 레코드를 놓친다.~~
  ~~SQL이 `(? IS NULL OR r.priority = ?)` 이므로 `NULL = 10`은 항상 거짓이다.~~
  ~~API 응답은 `priority: null`을 보여줘 실제 서빙값과 다르다.~~
- ~~**조치안**: MX/SRV 쓰기 시점에 기본값 10을 채워 저장한다.~~
  ~~NULL을 남기는 설계를 유지한다면 삭제 매칭과 필터를 `COALESCE(priority, 10)` 기준으로 통일한다.~~

### ~~3. SIGTERM을 처리하지 않는다~~

**완료** — `a656eee2`. `shutdown.rs` 의 watch 신호를 각 서버에 넘긴다. API 는 이미 수락한
요청을 마치고, DNS·소켓 수락 루프는 빠져나오며, 소켓 파일을 지운다. 데몬은 10 초 상한으로 기다린다.
SIGTERM 이전에 연 연결에서 SIGTERM 1.5 초 뒤 요청을 마쳐 200 OK 를 받는 것으로 검증했다.

**정정** — "처리되지 않은 SIGTERM 이면 systemd 가 TimeoutStopSec 만큼 기다린 뒤 SIGKILL 한다" 는
틀렸다. SIGTERM 의 기본 동작은 즉시 종료다. 실제 피해는 지연이 아니라 무예고 절단과 소켓 파일 잔존이었다.

**남음** — 진행 중인 존 전송은 기다리지 않는다. 끊긴 전송은 secondary 가 폐기하고 재시도하므로
비용 대비 이득이 적다고 판단했다.

- ~~**위치**: `crates/bindizr/src/daemon.rs:51-58`~~
- ~~**현재**: `tokio::signal::ctrl_c()` 와 소켓 control 채널만 select 한다.~~
  ~~`SignalKind::terminate` 핸들러는 워크스페이스 전체에 없다.~~
- ~~**문제**: `systemctl stop`, `docker stop`, k8s 파드 종료는 모두 SIGTERM을 보낸다.~~
  ~~아무도 받지 않으므로 `TimeoutStopSec` 만료 후 SIGKILL로 죽는다.~~
  ~~`packaging/bindizr.service` 에는 `KillSignal` 도 `TimeoutStopSec` 도 없다.~~
- ~~**조치안**: `tokio::signal::unix::signal(SignalKind::terminate())` 를 select에 추가.~~
  ~~4번과 함께 처리한다.~~

### ~~4. graceful shutdown이 전혀 없다~~

**완료** — `a656eee2`. `shutdown.rs` 의 watch 신호를 각 서버에 넘긴다. API 는 이미 수락한
요청을 마치고, DNS·소켓 수락 루프는 빠져나오며, 소켓 파일을 지운다. 데몬은 10 초 상한으로 기다린다.
SIGTERM 이전에 연 연결에서 SIGTERM 1.5 초 뒤 요청을 마쳐 200 OK 를 받는 것으로 검증했다.

**정정** — "처리되지 않은 SIGTERM 이면 systemd 가 TimeoutStopSec 만큼 기다린 뒤 SIGKILL 한다" 는
틀렸다. SIGTERM 의 기본 동작은 즉시 종료다. 실제 피해는 지연이 아니라 무예고 절단과 소켓 파일 잔존이었다.

**남음** — 진행 중인 존 전송은 기다리지 않는다. 끊긴 전송은 secondary 가 폐기하고 재시도하므로
비용 대비 이득이 적다고 판단했다.

- ~~**위치**: `crates/bindizr/src/api/mod.rs:94-98`, `crates/bindizr/src/daemon.rs:74`~~
- ~~**현재**: `axum::serve(listener, ...)` 에 `.with_graceful_shutdown()` 이 없다.~~
  ~~종료 시 그냥 `Ok(())` 를 반환하고 프로세스가 끝난다.~~
- ~~**문제**: 진행 중인 HTTP 요청, 진행 중인 AXFR/IXFR 스트림, 소켓 핸들러가~~
  ~~전부 중간에 끊긴다. IXFR이 중간에 끊기는 상황은 `dns/server/ixfr.rs:178-186`~~
  ~~주석이 직접 "would corrupt the partial IXFR" 라고 경고하는 그 경우다.~~
- ~~**조치안**: shutdown 신호를 broadcast 채널로 배포.~~
  ~~axum은 `with_graceful_shutdown`, DNS TCP는 진행 중 전송 완료 대기,~~
  ~~NOTIFY 큐는 드레인 후 종료.~~

### ~~5. DNS 리스너 bind 실패를 삼키고 기동 성공으로 보고한다~~

**완료** — `cdc80f13`. 두 리스너를 spawn 전에 bind 하고 `initialize()` 가 `Result` 를 반환한다.
포트를 점유한 채 기동해 종료코드 1 과 원인 출력을 확인했고, 정상 기동은 `dig` 로 UDP·TCP 응답을 확인했다.

- ~~**위치**: `crates/bindizr/src/dns/mod.rs:36-46`~~
- ~~**현재**: TCP/UDP 서버를 `tokio::spawn` 하고 `Err`는 `log_error!` 만 한다.~~
  ~~`initialize()` 는 `()` 를 반환하고 `daemon.rs:33` 은 그것을 무시한다.~~
- ~~**문제**: 53번 포트가 이미 사용 중이거나 `CAP_NET_BIND_SERVICE` 가 없으면~~
  ~~로그 한 줄만 남고 데몬은 정상 기동한 것처럼 계속 돈다.~~
  ~~`/health` 는 DB만 확인하므로 오케스트레이터도 정상으로 본다. DNS 평면 전체가 죽은 채 방치된다.~~
- ~~**참고**: API 경로는 이미 올바르게 한다. `api/mod.rs:88-90` 은 spawn 전에 bind 하고 실패를 전파한다.~~
- ~~**조치안**: DNS도 bind를 spawn 밖으로 꺼내 `initialize()` 가 `Result` 를 반환하게 한다.~~

### ~~6. 유지보수 태스크가 panic하면 영구히 멈춘다~~

**완료** — `135c2cfd`. 패스를 `tokio::spawn` 으로 떼어내 `JoinHandle` 을 확인한다.
패닉하면 그 태스크만 죽고 루프는 다음 틱을 돈다. 로그와 `result="panic"` 메트릭에 남는다.
패닉을 주입하고 주기를 2 초로 줄여 9 초간 확인: 연속 4 회 패닉에도 데몬 생존, 매회 기록.
주입을 되돌린 뒤 정상 경로의 `result="ok"` 도 확인했다.

- ~~**위치**: `crates/bindizr-service/src/dnssec/maintenance.rs:30-38`~~
- ~~**현재**: 맨 `tokio::spawn` 이고 `JoinHandle` 을 버린다.~~
  ~~릴리스 프로파일이 `panic = "unwind"` 라 panic은 그 태스크만 되감고 끝난다.~~
- ~~**문제**: 감시자도 재시작도 없다. 재서명, 저널 프루닝, ZSK 롤오버가 전부 멈추고~~
  ~~`bindizr_dnssec_maintenance_runs_total` 이 그냥 증가를 멈출 뿐 오류 신호가 없다.~~
  ~~서명이 만료되기 시작한다.~~
- ~~**비교**: NOTIFY 워커는 안전하게 degrade 한다.~~
  ~~수신자가 죽으면 `enqueue_notify` 가 `false` 를 반환해 호출자가 인라인 전송으로 폴백한다.~~
  ~~(`notify/queue.rs`)~~
- ~~**조치안**: 루프 본문을 `catch_unwind` 또는 감시 태스크로 감싸고,~~
  ~~실패 카운터 메트릭을 추가한다.~~

### ~~7. MySQL 타임스탬프가 서버 타임존으로 기록된다~~

**완료** — `e4791875`. 스키마에서 `DEFAULT CURRENT_TIMESTAMP` 36개를 떼고
INSERT 33개가 `Utc::now()` 를 바인드한다. 내장 정책 시드는 스키마 배열에서 빼내
`create_tables` 가 바인드해 실행한다. UTC+9 MySQL 과 Asia/Seoul PostgreSQL 로 실측했다.
이전 방식은 UTC 보다 32400초 앞섰고 수정 후 0초다.

- **위치**: `crates/bindizr-db/src/schema.rs:20,44,58,78,97,109,134,144`
- **현재**: MySQL은 `created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP`.
  INSERT문이 이 컬럼을 채우지 않으므로 서버가 **세션 타임존**으로 채운다.
  `crates/bindizr-db/src/lib.rs:104` 의 `after_connect` 는 격리수준만 설정하고
  `time_zone` 은 건드리지 않는다. 읽기는 `DateTime<Utc>` 로 받는다.
- **문제**: UTC가 아닌 MySQL 서버에서 모든 저널·버전 타임스탬프가 오프셋만큼 밀린다.
  보존 프루닝 컷오프(`created_at < cutoff`, cutoff는 `Utc::now() - days`)가 틀어지고
  사용자에게 보이는 시각도 전부 틀린다.
- **참고**: Postgres는 `TIMESTAMPTZ`(`schema.rs:240,256,280,301`), SQLite의 `CURRENT_TIMESTAMP`는 UTC.
  MySQL만 어긋난다.
- **조치안**: INSERT에서 `Utc::now()` 를 명시적으로 바인드한다.

**확장** — 조사 중 더 큰 문제가 드러났다. 타임존만이 아니라 **시계가 두 개**다.
모든 `created_at` 은 DB가 `CURRENT_TIMESTAMP` 로 채우고, 나머지 시각 42곳은
bindizr 가 `Utc::now()` 로 만든다. 두 시계가 저널 프루닝
(`zone_change_repository_impl.rs:126`)과 버전 프루닝
(`zone_version_repository_impl.rs:218`)의 `created_at < ?` 에서 섞인다.
오른쪽 cutoff 는 앱이 계산한 값이다.
서명 시작·만료 시각은 서명하는 쪽이 계산할 수밖에 없어 42곳을 DB 시계로 옮길 수는 없다.
따라서 `created_at` 을 앱 시계로 옮기고 스키마에서 `DEFAULT CURRENT_TIMESTAMP` 를 뗀다.
기본값이 남아 있으면 빠뜨린 자리가 조용히 DB 시계를 쓴다.
`SET time_zone` 안은 폐기했다. 쿼리 어디에도 `NOW()` 가 없으므로 마지막
`CURRENT_TIMESTAMP` 가 사라지면 세션 타임존이 영향을 줄 대상이 없다.
SQLite 는 원래 문제가 없었다. sqlite 라이브러리가 bindizr 프로세스 안에서 돌아 시계가 하나다.

### ~~8. 인바운드 NOTIFY가 SOA 응답으로 잘못 처리된다~~

**완료** — `5e77ef0b`. `ParsedQuery` 가 opcode 를 싣고, `echo_question` 이 응답에 되울린다
(RFC 1035, Section 4.1.1). QUERY 가 아닌 opcode 는 NOTIMP 로 답한다. UPDATE 는 그 앞에서 분기된다.
NOTIFY 에 NOTIMP 를 고른 이유는 bindizr 가 primary 라 NOTIFY 를 소비할 일이 없기 때문이다.
실제 패킷으로 확인: NOTIFY→NOTIMP(opcode 4), STATUS→NOTIMP(opcode 2), QUERY SOA→NOERROR, QUERY A→REFUSED.

- ~~**위치**: `crates/bindizr-core/src/dns/message/mod.rs:397-436`, `crates/bindizr/src/dns/mod.rs:131`~~
- ~~**현재**: `is_nsupdate` 는 opcode가 UPDATE(5)인지만 본다~~
  ~~(`crates/bindizr-core/src/dns/nsupdate/mod.rs:22-24`).~~
  ~~`ParsedQuery::parse` 는 헤더에서 ID만 읽고 **opcode를 전혀 읽지 않는다**.~~
- ~~**문제**: NOTIFY는 opcode 4, QTYPE=SOA다. nsupdate 판정을 통과하지 못하고~~
  ~~`qtype == Rtype::SOA` 분기로 들어가 SOA 응답을 받는다.~~
  ~~응답 헤더의 opcode는 `build_message_into` 가 `0x84` 로 하드코딩하므로 0이 된다.~~
  ~~통지를 보낸 쪽은 opcode 불일치로 본다. 아웃바운드 쪽은 이 경우를 정확히 거부한다~~
  ~~(`crates/bindizr-core/src/dns/query/mod.rs:230-236`).~~
- ~~**조치안**: `ParsedQuery` 에 opcode를 싣고, QUERY가 아닌 opcode는~~
  ~~NOTIMP 또는 실제 NOTIFY ack로 분기한다.~~

### ~~9. 일반 쿼리와 ACL 거부에 응답이 없다~~

**완료** — `2f11f122`. ACL 거부와 범위 밖 qtype 모두 REFUSED 로 답한다.
`handle_udp_query` 는 보낼 바이트를 반환하도록 바꿨다. 실제 데몬으로 확인:
거부 시 TCP·UDP 전송 모두 REFUSED, 허용 시 AXFR 34 레코드, SOA 정상, A 는 REFUSED.

**이어서** — 미지원 opcode 의 NOTIMP 는 8 번에서 `5e77ef0b` 로 함께 처리했다.

- ~~**위치**: `crates/bindizr/src/dns/mod.rs:139-145` (TCP), `:187-200` (UDP)~~
- ~~**현재**: TCP는 XFR·SOA가 아니면 `log_info!` 만 하고 끝낸다. UDP는 `else` 자체가 없다.~~
  ~~ACL 거부는 `server/mod.rs:70-73` 이 `XfrError::AccessDenied` 를 반환하고~~
  ~~`run_tcp_server` 가 로그만 남긴 뒤 연결을 닫는다.~~
- ~~**문제**: A/AAAA/NS/ANY 쿼리, IN이 아닌 클래스, QUERY/UPDATE가 아닌 opcode 모두~~
  ~~무응답이라 클라이언트가 타임아웃까지 매달린다.~~
  ~~ACL 거부는 RFC 5936 Section 2.2.1이 REFUSED를 요구하는데 연결만 끊는다.~~
  ~~거부된 secondary 운영자는 진단 불가능한 리셋만 본다.~~
- ~~**이미 있는 것**: `ParsedQuery::error_response(rcode)` 가 존재하고~~
  ~~존을 못 찾을 때 NOTAUTH로 쓰인다 (`server/mod.rs:97`, `soa.rs:46`).~~
  ~~기계는 있고 호출만 없다.~~
- ~~**조치안**: ACL 거부는 REFUSED, 미지원 opcode는 NOTIMP,~~
  ~~범위 밖 쿼리는 REFUSED를 `error_response` 로 보낸다.~~

### ~~10. 존파일 import가 미지원 타입 한 줄에 전체 실패한다~~

**완료** — `2eff5b4d`. 파서가 미지원 타입·클래스를 `errors` 가 아닌 `unsupported` 에 담고,
`skip_unsupported` 를 주면 건너뛴 뒤 `skipped_records` 에 그대로 실어 보낸다.
CLI 는 `--skip-unsupported` 이고 건너뛴 줄을 stderr 에 `~` 로 찍는다.
파싱 실패나 TTL 범위 초과 같은 진짜 오류는 플래그와 무관하게 계속 막는다.

**함께 논의함** — "모든 타입을 지원하면 되지 않나" 를 검토했다. 타입 하나 추가 비용은 작다
(A 16줄, SRV 76줄, CAA 137줄). 그러나 IANA 할당이 90종 가까이 되고 계속 늘어나므로
"모든 타입" 은 끝이 없다. RFC 3597 불투명 저장은 가능하지만 대가가 둘이다.
값 검증이 사라지고, rdata 에 도메인 이름이 든 타입의 DNSSEC 정규화가 틀릴 수 있는데
38번(자기 서명 미검증) 때문에 틀려도 드러나지 않는다.
타입 확장은 24번에서 다루되 38번 뒤가 안전하다. 어느 쪽이든 목록이 유한한 이상
이번 플래그는 필요하다.

- **위치**: `crates/bindizr-service/src/record/import.rs:421`
- **현재**: `let will_apply = errors.is_empty() && !dry_run;`
  `crates/bindizr-core/src/dns/zonefile/mod.rs:70-80` 은 저장 가능한 12종 밖의 타입에
  `unsupported record type` 오류를 넣는다.
- **문제**: 실제 BIND 존파일에 NAPTR이나 HINFO가 한 줄만 있어도 import 전체가 무산된다.
  `skip_unsupported` 같은 플래그가 없다 (`types/import.rs`).
- **대조**: AXFR import는 반대로 동작한다. DNSSEC 타입을 조용히 건너뛴다
  (`dns_client/axfr.rs:124-140`).
- **조치안**: `skip_unsupported` 옵션을 추가하고 건너뛴 줄을 응답에 리포트한다.

### ~~11. 존파일 오류 줄 번호가 2줄 밀린다~~

**완료** — `9670fbb6`. `to_input_line_message` 가 프렐류드 두 줄을 빼고 회귀 테스트를 붙였다.

**정정** — "첫 오류에서 `break` 하는 것" 은 결함이 아니었다. `domain` 의 `next_entry` 문서가
*"If this function returns an error, do not attempt to read any further entries,
as the scanner is in an invalid state at that point."* 라고 명시한다. 기존 코드는 이 계약을
지키고 있었고, 계속 읽게 바꾸면 오히려 패닉한다. 오류를 여러 개 모으려면
입력을 항목 단위로 잘라 항목마다 새 파서 인스턴스를 쓰는 방법뿐이다.

- ~~**위치**: `crates/bindizr-core/src/dns/zonefile/mod.rs:43`~~
- ~~**현재**: 파싱 전에 `$ORIGIN`, `$TTL` 두 줄을 앞에 붙인다.~~
  ~~파서 오류 메시지는 `{line}:{col}: {err}` 형식이라 사용자 파일 기준보다 항상 2 크다.~~
- ~~**부가**: `:151-154` 에서 첫 오류에 `break` 하므로 나머지 파일은 검사되지 않는다.~~
  ~~운영자가 오류를 하나씩만 고칠 수 있다.~~
- ~~**조치안**: 보고 시 줄 번호에서 2를 빼고, `break` 대신 계속 수집한다.~~

### ~~12. `notify_timeout_secs` 기본값이 코드와 문서에서 다르다~~

**완료** — `3997348b`. 코드 기본값을 3으로 맞추고 이 값을 고정하던 테스트를 갱신했다.

- ~~**위치**: `crates/bindizr-core/src/config/mod.rs:199-201` 은 `5`~~
- ~~**문서·샘플**: `bindizr.conf.toml:31`, `docs/configuration.md:53`,~~
  ~~`docker/bindizr.conf.toml`, `charts/values.yaml` 모두 `3`~~
- ~~**조치안**: 한쪽으로 통일. 설정 파일 없이 뜨는 경우와 있는 경우의 동작이 달라진다.~~

### ~~13. trace 레벨에서 로그 target이 사라진다~~

**완료** — `8b29da05`. 비교를 `>= Level::Debug` 로 바꿨다.
`log` 크레이트의 `Level` 은 판별자에서 `Ord` 를 파생하므로 Trace > Debug 다.

**남음** — 아래 "부가" 의 타임스탬프는 아직 없다. 모든 로그 줄의 형식이 바뀌므로 별도로 처리한다.

- ~~**위치**: `crates/bindizr-core/src/logger/mod.rs:56`~~
- ~~**현재**: `if self.log_level == Level::Debug` 로 **동등 비교**한다.~~
  ~~debug일 때만 `{level} - {target}: {args}`, 나머지는 `{level}: {args}`.~~
- ~~**문제**: trace는 debug보다 상세한데 오히려 target이 빠져 정보가 줄어든다.~~
  ~~`<=` 비교가 의도였을 것이다.~~
- **부가**: 로그 라인에 타임스탬프 필드가 아예 없다. journald나 `docker logs` 가
  붙여주지만 stderr를 파일로 리다이렉트하면 시각이 사라진다. (미해결)
- ~~**조치안**: 비교를 `>=` 방향으로 수정하고 타임스탬프를 추가한다.~~

---

## P1 — 보안 · 프로토콜

### ~~14. 존 전송에 TSIG가 없다~~ (완료)

**완료 (2026-09-14)** — 설계 결론(아래) 그대로, 선택제로.

- **메시지 조립** — `build_message_into` 가 ARCOUNT=0 을 박아 additional 섹션을
  실을 수 없던 것이 근본 원인이었다. `domain` 은 MAC 계산을 공개하지 않고
  `ServerSequence::answer` 가 `AdditionalBuilder` 를 받으므로, 봉투를 `domain`
  빌더로 만들도록 바꿨다. 답변 RR 은 이미 조립된 바이트라 `ComposeRecord` 래퍼로
  그대로 밀어 넣어 청킹 산술은 건드리지 않았고, 크기 계산에 `Key::compose_len()`
  을 더해 봉투가 64KB 를 넘지 않게 했다.
- **TSIG 모듈** — `dns/nsupdate/auth/` → `dns/tsig/`. nsupdate 전용이 아니게
  됐다. `TransferSigner`(`ServerSequence`), `verify_tsig_sequence`,
  `signed_key_name`, `signature_len` 추가.
- **인가** — 요청에 TSIG 가 있으면 키로, 없으면 지금까지처럼 주소 ACL 로.
  전송은 존을 통째로 넘기므로 **존 전체를 덮는 grant** 만 인가한다(global 키,
  또는 `*`/`*`). 좁힌 grant 는 nsupdate 는 되고 전송은 안 된다.
  모르는 키는 주소로 떨어지지 않고 BADKEY — 서명이 우회로가 되면 안 된다.
- **`tsig_grants.can_write`** — 없으면 "세컨더리에 키를 준다" 가 "존 전체 쓰기
  권한을 준다" 가 된다. `tsig-key grant ... --read-only` 로 전송 전용 키.
  토큰 grant 가 29번에서 받은 것과 같은 열·같은 이름이다.
- **적용 범위** — AXFR, IXFR, 카탈로그 AXFR, SOA(TCP·UDP). 세컨더리는 SOA 를
  먼저 묻고 키를 설정한 BIND 는 SOA 도 서명해 보낸다. 거부 응답도 키가 통과한
  뒤라면 그 키로 서명한다(RFC 8945, Section 5.3).
- **`bindizr tsig-key export`** — named.conf `key` 블록을 그대로 찍는다.
  `dnssec keys export` 와 같은 모양. 키 배포가 "base64 를 복사해 문법을 찾아
  조립" 에서 "붙여넣기" 가 된다.
- **`secondary_addrs` 는 남는다** — 접근 제어만 키가 가져가고, NOTIFY 대상과
  doctor 감시 대상은 여전히 주소가 필요하다.

**검증** — 단위: 다중 봉투 서명이 `domain` 의 `ClientSequence` 로 검증되는가,
크기 계산에 TSIG 가 반영되는가. e2e: 무서명 전송이 그대로 되는가, 서명 전송의
모든 봉투가 검증되는가, 좁힌/없는 grant 가 거부되는가, read-only 키가 당겨가되
쓰지는 못하는가, 모르는 키가 주소로 떨어지지 않는가. 그리고 실제 BIND9
세컨더리 스택(`BINDIZR_E2E_VERIFY_DNS`).

**부수로 찾은 선행 버그** — compose 전용 하네스가 `/records?...&limit=10000` 을
불러 22번(상한 1000) 이후로 계속 400 을 받고 있었다. 이 스택이 CI 에서 안 돌아
드러나지 않았다(62번 폐기).

**설계 결론 (2026-09-10 논의)** — 아래 네 가지를 확정했다.

**선택제로 넣는다, 필수가 아니다.** TSIG 가 있으면 키로 인가하고, 없으면 지금처럼 주소 ACL 로
판정한다. 기존 사용자는 설정할 것이 하나도 늘지 않고, 키를 쓰는 구성은 살아난다.
NSD 의 `provide-xfr: <주소> NOKEY` / `<주소> <키>` 와 같은 모양이다.
필수로 만들면 첫 설정 부담이 늘어 UX 가 나빠진다.

**지금 실패하는 표준 구성을 살리는 것이 핵심 동기다.** 문서와 예제가 안내하는 BIND 설정에는
키가 없지만(`examples/compose/bind9/named.conf:18`), BIND 사용자의 표준 관행은
`primaries { addr key transfer-key; }` 다. 그렇게 설정하면 지금은 전송이 실패한다.
`DnsMessageBuilder` 가 ARCOUNT 를 0 으로 고정해(`message/mod.rs:348`) 응답에 TSIG 를 실을 수 없고,
BIND 는 서명 없는 응답을 버린다. 즉 현재의 "간단함" 은 사용자가 평소 방식을 버려야 성립한다.

**주소 기반 관문은 사라지지 않는다.** 앞서 "TSIG 를 넣으면 루프백 예외, 매핑 주소 정규화,
리졸버 캐시를 지울 수 있다" 고 적었던 것은 틀렸다. TSIG 를 필수로 할 때만 성립하고,
선택제로 두면 주소 경로가 남으므로 그 조건들도 전부 남는다.
**저 관문들은 임시 발판이 아니라 무설정 경로를 유지하는 영구 비용이다.**

**`secondary_addrs` 는 겸직에서 풀리되 없어지지 않는다.** TSIG 는 "이 호출자가 당겨가도 되나"
하나만 답한다. "어디로 통지하고 무엇을 감시하나" 는 여전히 주소가 필요하다.
`notify_secondaries` 는 주소로 통지를 보내고 `doctor` 는 `probe_secondaries` 로 각 secondary 의
SOA 를 물어 동기화를 확인한다. 키는 주소를 알려주지 않는다.
그래서 목록은 통지·감시용으로 남고 접근 제어 역할만 키가 가져간다.
BIND(`also-notify` / `allow-transfer`), Knot(원격 목록 / `acl`), NSD(`notify:` / `provide-xfr:`)
모두 두 질문을 별개로 답한다. **두 번째 ACL 목록을 추가하지 않아도 겸직이 저절로 풀린다.**

**새로 생기는 문제** — 키만 있으면 목록에 없는 주소에서도 당겨갈 수 있으므로 bindizr 가
모르는 secondary 가 존재할 수 있다. 지금은 목록에 없으면 못 당겨가므로 이 문제가 없다.
관련해서 확인한 사실: bindizr 는 **누가 무엇을 언제 당겨갔는지 전혀 기록하지 않는다.**
전송 이력 테이블이 없고 메트릭도 타입과 성공 여부만 센다(`xfr_total`).
그래서 doctor 가 동기화 상태를 알려면 secondary 에게 능동적으로 물어봐야 한다.
전송을 기록하면 물어보지 않고도 알 수 있고, 목록에 없는 secondary 도 한 번 당겨간 순간부터 보인다.
명시 목록(통지할 곳)과 전송 기록(실제 가져간 곳)이 어긋나는 것 자체가 진단 신호가 된다.

**구현 시 유의** — 다중 메시지 AXFR 의 TSIG 서명 규칙(RFC 8945, Section 5.3)을 다뤄야 하고,
`DnsMessageBuilder` 가 additional 섹션을 실을 수 있어야 한다. 규모가 커서 별도 브랜치가 맞다.

- **위치**: `crates/bindizr/src/dns/server/mod.rs:70`,
  `crates/bindizr-core/src/dns/message/mod.rs:341-357`
- **현재**: AXFR/IXFR 인가는 `validate_secondary_acl(client_ip, ...)` 로 **IP 단독**.
  `DnsMessageBuilder::build_message_into` 는 `ARCOUNT=0` 을 하드코딩해
  additional 섹션 자체를 실을 수 없다. TSIG는 nsupdate 경로에만 있다
  (`crates/bindizr-core/src/dns/nsupdate/auth/mod.rs`).
- **문제**:
  - BIND secondary에 `primaries { x key transfer-key; }` 를 설정하면
    서명된 AXFR을 보내는데 bindizr는 TSIG를 읽지 않고 서명 없이 답한다.
    BIND는 "expected a TSIG"로 전송을 버린다. 즉 **표준 구성과 상호운용되지 않는다**.
  - 존 데이터 인가가 출발지 IP뿐이라 UDP SOA 프로브 경로는 스푸핑 가능하다.
- **조치안**: `DnsMessageBuilder` 에 additional 섹션과 TSIG 서명을 추가하고,
  전송 요청의 TSIG를 검증한다. 키는 기존 `tsig_keys` 테이블을 재사용하되
  전송용 grant를 별도로 둘지 결정이 필요하다.

### ~~15. SOA 쿼리가 ACL을 거치지 않는다~~

**완료** — `2b7202b6`, `8a351764`. SOA 를 기존 전송 게이트 뒤로 옮겼다.
ACL 밖 원격은 REFUSED 를 받고 카탈로그 SOA 를 통한 전체 존 조회와 DB 쓰기를 유발하지 못한다.
데몬 자신(루프백 또는 설정된 `listen_addr`)은 예외다. `bindizr doctor` 가 DNS 평면이 살아 있는지
와이어로 증명하기 때문이다. 존 전송에는 이 예외가 없다.

**Codex 리뷰가 잡은 것** — 처음에는 루프백만 예외로 두었는데, `listen_addr` 이 특정 인터페이스
IP 면 doctor 의 프로브가 그 주소를 출발지로 도착해 REFUSED 를 받았다. 재현 후 `is_self_probe` 로
리슨 주소도 포함했다. 세 가지 리슨 주소 형태 모두 확인했다.

**부수 정리** — `build_soa_reply` 가 `build_soa_response` 와 같은 개념에 두 낱말을 쓰고 있어
두 함수를 합쳤다. `ZoneNotFound` 를 던졌다 한 단계 위에서 잡아 NOTAUTH 로 바꾸던 왕복도 사라졌다.
설정 주석 네 곳이 이 필드를 NOTIFY 대상으로만 설명하던 것도 고쳤다(`crates/bindizr/README.md` 포함).

- ~~**위치**: `crates/bindizr/src/dns/server/soa.rs` 전체에 ACL 호출 없음~~
- ~~**현재**: 누구든 SOA를 물으면 답한다.~~
  ~~존이 없으면 NOTAUTH, 있으면 mname/rname이 담긴 SOA.~~
- ~~**문제**: 인증 없는 존 존재 여부 및 시리얼 오라클.~~
  ~~더 나쁜 것은 `catalog.bind` 경로다. `soa.rs:59-68` 이~~
  ~~`catalog::generate_catalog_zone()` 을 호출하고, 이것이~~
  ~~`ZoneService::list()` 로 **전체 존을 페이지네이션 없이** 읽은 뒤~~
  ~~`advance_catalog_serial` 로 쓰기 트랜잭션을 연다.~~
  ~~스푸핑 가능한 40바이트 UDP 패킷 하나가 전체 존 조회 + DB 쓰기 하나를 유발한다.~~
- ~~**조치안**: SOA에도 ACL을 적용하거나 최소한 카탈로그 SOA 경로를 ACL 뒤로 옮긴다.~~
  ~~카탈로그 시리얼 전진은 다이제스트가 바뀔 때만 쓰도록 한다.~~

### ~~16. ACL에 CIDR이 없고 매 요청마다 호스트명을 재해석한다~~

**완료** — `1c2582be`, `089d03be`. 리터럴 IP 를 먼저 보고, 호스트명 해석에 캐시(성공 60s,
실패 5s)와 타임아웃(2s)을 붙였다. 차가운 캐시에서 대기 질의가 각자 조회하던 것도
비동기 뮤텍스로 묶어 한 번만 조회한다(Codex 지적).

**측정** — macOS 에서는 차이가 없다. mDNSResponder 가 이미 캐시하기 때문이다.
배포 대상은 다르다: 릴리스는 `x86_64-unknown-linux-musl` 이고 musl 의 `getaddrinfo` 는
캐시하지 않는다. Helm 차트가 secondary 를 호스트명으로 넘기므로 이 경로는 실제로 쓰인다.

**미검증** — 멈춘 리졸버를 흉내 낼 수 없어 타임아웃의 실제 거동은 확인하지 못했다.

**CIDR 은 넣지 않았다** — 별도 목록 추가는 14 번 논의에서 접었다.


- **위치**: `crates/bindizr/src/dns/server/acl.rs:23-48`, `:50-69`
- **현재**: 항목은 `Ip(IpAddr)` 아니면 `HostPort(String)` 둘뿐.
  `is_client_allowed` 는 매 요청마다 `lookup_host` 를 순차 호출한다.
  캐시도 타임아웃도 없다.
- **문제**:
  - `192.0.2.0/24`, `2001:db8::/64` 를 표현할 수 없다. IPv6는 정확한 리터럴만 가능.
  - Helm 차트의 `secondaryAddrs` 는 호스트명이므로 모든 전송이 요청 경로 안에서
    리졸버 왕복을 유발한다.
  - ACL 판정이 공격자가 영향을 줄 수 있는 리졸버 응답에 의존한다.
  - NOTIFY 대상 목록과 전송 허용 목록이 **같은** `dns.secondary_addrs` 다.
    별도의 allow-transfer 설정이 없다.
- **조치안**: CIDR 파싱 추가, 해석 결과 TTL 캐시, allow-transfer를 별도 키로 분리.

### ~~17. unsigned nsupdate에 주소 제한이 없다~~

**완료** — `2a9d577f`. 서명 없는 갱신을 데몬 호스트에서만 받는다.
문서가 이미 로컬 테스트 전용이라고 적고 있었으므로 코드가 그 계약을 지키게 한 것이다.
설정 필드를 새로 만들지 않은 이유: 서명 없는 갱신에는 원격 발신자가 증명할 수 있는 신원이 없어
허용 주소 목록을 만들어도 스푸핑 가능한 주소일 뿐이다. 원격은 TSIG 를 쓴다.
검증: 루프백 적용, 원격 REFUSED, 같은 원격 주소의 TSIG 서명 갱신은 적용.


- **위치**: `crates/bindizr/src/dns/server/nsupdate/update/mod.rs:126-141`
- **현재**: `authenticate_request` 는 클라이언트 주소를 **인자로 받지도 않는다**.
  `dns.nsupdate_allow_unsigned` 가 true면 `Ok(None)` 으로 통과.
  `dynamic_update/mod.rs:216-219` 의 `authorize_key` 도 `None` 이면 즉시 `Ok(())`.
  디스패치는 ACL 검사 이전에 일어난다 (`dns/mod.rs:119-121`, `:173-180`).
- **문제**: 이 플래그를 켜면 인터넷의 임의 호스트가 UDP로 임의 존을 고칠 수 있다.
  문서는 "not recommended"라고 하지만 짝이 될 IP 게이트가 아예 없다.
- **조치안**: unsigned 허용 시 반드시 주소 목록을 함께 요구한다.

### ~~18. TSIG 재전송 방어가 fudge 창에만 의존한다~~ (폐기)

**폐기** — 두 가지를 만들었다가 모두 되돌렸다. **다시 제안하지 않는다.**

**MAC 재전송 캐시** — 받아들인 MAC 을 기억해 같은 메시지를 거부하도록 구현하고, 캡처한 패킷을
재전송해 수정 전 NOERROR / 수정 후 REFUSED 로 동작도 확인했다. 그런데 **UDP nsupdate 는 응답이
유실되면 같은 패킷을 그대로 재전송한다.** MAC 이 동일하므로 정당한 재시도가 차단되고, 클라이언트는
이미 성공한 갱신에 대해 REFUSED 를 받는다. e2e 테스트가 이를 잡아냈다.
RFC 8945, Section 5.2.3 이 권하는 "마지막 time_signed 보다 큰 것만 수용" 도 같은 문제를 안는다.
`domain` 이 이 기능을 넣지 않은 이유이기도 하다(소스 주석에 명시).

**시간 창 상한** — 서버가 자체 300 초를 강제하도록 만들었다가 되돌렸다.
`domain` 은 요청의 `fudge`(발신자가 정함, 최대 18 시간)로 시간을 검사한다. 다만 `fudge` 는
HMAC 계산에 포함되므로 **제3자가 위조할 수 없다.** 정상 클라이언트(`nsupdate`, `domain`)의 기본값이
이미 300 이라 상한은 아무것도 바꾸지 않고, **바뀌는 대상은 시계가 안 맞아 일부러 크게 잡은 쪽뿐이라
필요해서 설정한 구성을 거부하게 된다.** 위협도 좁다: 경로상 캡처가 필요하고, nsupdate 연산은
대체로 멱등이며, 키를 가진 쪽은 재전송 없이 새로 서명하면 된다.


- **위치**: `crates/bindizr-core/src/dns/nsupdate/auth/mod.rs:78`
- **현재**: `ServerTransaction::request(&DbKeyStore(key), &mut message, Time48::now())`.
  MAC 검증과 BADTIME/fudge 검사만 한다.
  최근 본 (key, time-signed, MAC) 추적이 없다.
- **문제**: 캡처한 서명 UPDATE를 fudge 창 동안 재전송할 수 있다.
  fudge는 클라이언트가 정하며 파서가 그대로 받고
  (`nsupdate/parser/mod.rs:203-205`) 응답에 되울린다 (`nsupdate/mod.rs:71-74`).
  즉 클라이언트가 아주 큰 창을 요구할 수 있다.
- **조치안**: fudge 상한을 강제하고, 최근 MAC을 짧게 캐시해 중복을 거절한다.

### ~~19. UDP 루프가 모든 처리를 인라인 대기하고, 동시성 제한이 없다~~

**완료** — `20f0bb87`. 데이터그램마다 태스크를 띄우고 루프는 수신만 한다.
존 2 만 개에서 무거운 질의 12 개 뒤의 가벼운 질의가 2,346ms → 13ms.
UDP 는 256 개 초과 시 드롭(재시도를 기대), TCP 는 128 개 연결에 permit 을 accept 보다 먼저 잡아
초과분을 커널 백로그에 남긴다.

**미검증** — 상한 자체의 폭주 거동은 부하 시험으로 확인하지 못했다. 시험 스크립트가
소켓 수백 개를 순차 수신하도록 짜여 두 번 시간 초과했다.


- **위치**: `crates/bindizr/src/dns/mod.rs:162-201`
- **현재**: 단일 `recv_from` 루프가 `handle_udp_nsupdate`(DB 트랜잭션),
  `handle_udp_soa`, `handle_udp_query` 를 그대로 `await` 한다.
  다음 `recv_from` 은 그때까지 못 돈다.
- **문제**: 느린 요청 하나가 모든 UDP DNS 트래픽을 head-of-line 블로킹한다.
  ACL 호스트명 해석(16번)이 이 안에 있으므로 리졸버가 느리면 전체가 멈춘다.
- **부가**: TCP는 연결마다 spawn 하지만 (`dns/mod.rs:63`)
  최대 연결 수, 최대 동시 전송 수, IP당 상한이 전부 없다.
  `TCP_IDLE_TIMEOUT` 은 읽기에만 걸리고 쓰기 타임아웃과 전체 데드라인이 없어
  느린 리더가 AXFR 태스크를 무한정 붙잡을 수 있다.
- **조치안**: UDP는 데이터그램마다 spawn, 세마포어로 동시 전송 수 제한, 쓰기 타임아웃 추가.

### ~~20. HTTP API에 TLS가 없다~~ (완료)

**완료 (2026-09-14)** — 프록시 전제를 문서화하는 최소안 대신 내장 TLS 로 결정.
Compose·systemd 배포에는 TLS 를 종단할 지점이 아예 없고, `listen_addr` 를
`0.0.0.0` 으로 바꾸는 순간 Bearer 토큰이 평문으로 나가는데 제품 어디에도
경고가 없었다.

- **`[api] tls_cert_file` / `tls_key_file`** — 둘 다 주면 같은 포트에서 HTTPS.
  한쪽만 주면 기동 전에 거부한다(HTTPS 일 줄 알았던 포트에서 조용히 평문을
  서빙하는 것이 최악). 파일 문제도 기동 실패로 드러난다.
  `BINDIZR_API_TLS_CERT_FILE`/`_KEY_FILE` 로도 받고, 빈 값은 지운다.
- **서버** — `axum-server` + rustls. rustls·ring·aws-lc-rs 는 이미 의존성
  그래프에 있어 스택이 새로 늘지는 않았다. TCP 바인드는 그대로 `initialize`
  에서 해서 포트 충돌이 백그라운드 태스크가 아니라 기동 실패로 보이게 유지했고,
  graceful shutdown 은 `axum_server::Handle` 로 옮겼다(평문 경로는 그대로).
- **reload** — `[api]` 섹션 전체가 이미 running-fixed 라 인증서 교체는 재시작이
  필요하다. 별도 작업 없음.
- **doctor** — TLS 일 때는 TCP 연결까지만 확인하고 그렇게 보고한다. 인증서와
  키는 기동 때 읽으므로 리스닝 중이면 이미 로드된 것이고, 여기서 TLS 를
  말하려면 상대가 내미는 것을 무조건 믿는 코드를 넣어야 한다.
- **external-dns 어댑터** — `--ca-file`/`BINDIZR_CA_FILE`. 시스템 루트를
  대체하지 않고 더한다. (클라이언트 인증서/mTLS 는 범위 밖 — 자격증명은 토큰이다.)
- **Helm** — `bindizr.api.tls.existingSecret` 으로 `tls.crt`/`tls.key` Secret 을
  마운트하고 config 에 경로를 넣는다. readiness 프로브가 `httpGet` 인데 TLS 면
  절대 통과 못 하므로, scheme 을 명시하지 않았을 때만 HTTPS 로 채운다.
- **검증** — 실제 자체서명 인증서로 HTTPS 200, 같은 포트의 평문 요청 실패,
  CA 파일로 검증 성공, 반쪽 설정 거부, 없는 파일 기동 실패, `helm lint`/
  `helm template` 양쪽 경로, 렌더된 ConfigMap 을 `config check` 통과.
  e2e 는 `TestAppOptions.tls` 로 rcgen 자체서명 쌍을 만들어 HTTPS 로 붙고,
  평문·미신뢰 클라이언트가 둘 다 거부되는 것을 확인한다.

- **위치**: `crates/bindizr/src/api/mod.rs:88-98`
- **현재**: 평문 `TcpListener`. `crates/bindizr/Cargo.toml` 에
  rustls, native-tls, axum-server 어느 것도 없다.
  `tower-http` 은 `features = ["cors"]` 만 받는다.
- **문제**: Bearer 토큰이 평문으로 흐른다. 리버스 프록시가 전제인데
  `docs/http-api/index.md` 에 그 요구사항이 없다.
  ExternalDNS 어댑터 홉에도 클라이언트 인증서 옵션이 없다.
- **조치안**: TLS 설정 키를 추가하거나, 최소한 프록시 전제를 문서에 명시한다.

### ~~21. CORS가 무조건 permissive다~~ (폐기)

**폐기** — 소유자 판단으로 CORS 는 지금 형태를 유지한다. **다시 제안하지 않는다.**
`api.cors_allowed_origins` 설정 필드와 출처 검증, 기본값 닫힘까지 만들었다가 되돌렸다.
아래 관찰 자체가 틀린 것은 아니므로 기록만 남긴다.


- **위치**: `crates/bindizr/src/api/router.rs:76`
- **현재**: `router.layer(CorsLayer::permissive())` 를 조건 없이 적용.
  `ApiConfig` 에 관련 키가 없다 (`config/mod.rs:25-39`).
- **문제**: 존을 만들고 토큰을 발급하는 관리 API에 모든 origin, 메서드, 헤더를 허용한다.
  `Authorization` 헤더만이 유일한 방어선이다.
- **조치안**: allow-list 설정 키를 추가하고 기본은 비활성.

### ~~22. 페이지 크기 상한이 없다~~

**완료** — `3932e5e4`. `normalize_page_limit` 이 생략 시 50 을 주고 1000 초과와 0 을 거부한다.
HTTP 400 에 `ErrorResponse` 형식으로 응답하므로 OpenAPI 가 문서화만 하고 내지 않던 응답이 실제로 나온다.
버전 목록은 이미 인라인 50 을 쓰고 상한이 없었는데 같은 함수로 통일했다.


- **위치**: `crates/bindizr-db/src/repository/{sqlite,mysql,postgres}/record_repository_impl.rs:329/340/340`
- **현재**: `.bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))`.
  서비스 계층에 상한 검증이 없다.
- **문제**: `limit` 미지정이면 테이블 전체가 한 응답에 실린다.
  그런데 `api/zone.rs:293`, `api/record.rs:65` 는
  `(status = 400, "invalid pagination")` 을 문서화한다. 코드가 내지 않는 응답이다.
- **부가**: 페이지네이션이 OFFSET 기반이라 깊은 페이지가 선형으로 느려진다.
- **조치안**: 기본값과 상한을 두고, 초과 시 실제로 400을 반환한다.

### ~~23. rate limit이 없다~~ (폐기)

**폐기 (2026-09-14)** — 소유자 판단. 20번(TLS)과 함께 볼 항목이었으나 도입하지 않는다.

- **현재**: 워크스페이스와 문서 전체에 rate limit 관련 코드가 없다.
  `router.rs:22-78` 은 auth, metrics, CORS만 얹는다.
  유일한 한계는 `api/middleware/body_parser.rs:14` 의 업로드 상한이고
  그나마 일부 라우트에만 적용된다.
- **조치안**: 토큰별 쓰기 요청 상한을 검토. 우선순위는 낮지만 20번, 21번과 함께 본다.

---

## P2 — 기능 공백

### ~~24. 저장 레코드 타입이 12종뿐이다 (DNAME/NAPTR 완료)~~ (폐기)

**남은 타입은 폐기 (2026-09-14)** — SVCB/HTTPS 는 `domain` 크레이트가 파싱을 끝내면 다시 본다.
소유자 판단으로 그때까지 목록에서 내린다.

**DNAME, NAPTR 추가 완료** — 14종. NAPTR은 존파일/nsupdate 양쪽에서 `domain` 의
표시형 대신 파싱된 필드에서 렌더한다. 그쪽은 이미 `.` 로 렌더되는 루트 이름에
절대형 점을 또 붙여 `..` 을 내놓기 때문이다.

**SVCB/HTTPS는 보류** — `domain` 0.12.1 의 SvcParams 파싱이 미완성이다.
`rdata/svcb/value.rs:728` 에 `TODO: implement ALPN escaping` 이 있고 구현이
주석 처리돼 있어, RFC 9460 Appendix D.9 (`alpn="f\\\\oo\\,bar,h2"`) 를
`this implementation does not allow escape sequences in alpn` 으로 거부한다.
D.10 첫 케이스(`alpn` 없는 `no-default-alpn`)도 거르지 못한다. 존파일 import가
합법 레코드를 거부하는 반쪽 지원이 되므로, 크레이트가 채워지면 다시 본다.

- **위치**: `crates/bindizr-core/src/model/record/mod.rs:79-93`
- **지원**: A, AAAA, CAA, CNAME, DNAME, DS, MX, NAPTR, TXT, NS, SRV,
  PTR, SSHFP, TLSA
- **없음**: SVCB, HTTPS, LOC, URI, CERT, HINFO, RP,
  OPENPGPKEY, SMIMEA, RFC 3597 일반 타입(`TYPExxx \# len hex`)
- **타입 하나 추가 시 손대야 하는 곳** (레지스트리가 없어 전부 exhaustive match):

  | 대상 | 위치 |
  | --- | --- |
  | enum, `FromStr`, `as_str` | `model/record/mod.rs:80,138,157` |
  | `from_rtype` | `model/record/mod.rs:176` |
  | `wire_type` | `model/record/mod.rs:195` |
  | `validate_value` | `model/record/mod.rs:214` |
  | `canonical_value` | `model/record/mod.rs:252` |
  | `encoded_value` | `model/record/mod.rs:298` |
  | `display_value` / `presentation_rdata` | `model/record/mod.rs:342,369` |
  | wire RDATA 인코더 | `dns/record/rdata/mod.rs:96` |
  | nsupdate rdata 디코더 | `dns/nsupdate/parser/mod.rs:249` |
  | 값 모듈 + 재export | `dns/record/mod.rs:6-36` |

  존파일 import/export는 `from_rtype` 와 `presentation_rdata` 를 타므로 자동으로 따라온다.
- **난이도**: LOC, URI, HINFO 등은 각각 값 모듈 하나로 끝난다.
  RFC 3597 일반 타입은 `Unknown(u16)` 변형을 전 구간에 끼워야 해서 큼.

### ~~24b. rdata 이름/CAA 값이 오너 이름보다 좁았다~~ (완료)

**완료** — `validate_domain_record_value` 가 이름을 `split('.')` 로 쪼개고 LDH만
받아, 오너 이름이 받는 레이블을 rdata는 거부했다. RFC 2317 Section 4 위임
(`0/25` 레이블)과 `\.` 이스케이프가 그래서 막혔다. `decode_name_labels` 로
바꿔 오너와 같은 규칙을 쓴다. `to_fqdn_lowercase` 도 `trim_end_matches('.')` 가
데이터인 점을 먹던 걸 고쳤다. CAA는 `parse_quoted_string`(255 한계 없는 버전)을
써서 따옴표/역슬래시 거부를 없앴다 — 거부 사유였던 "exporter가 이스케이프를
안 쓴다"는 이제 성립하지 않는다.

### ~~25. 존파일 파서가 `$GENERATE` 와 TTL 단위를 못 읽는다 (TTL 단위 완료)~~ (폐기)

**$GENERATE 폐기 (2026-09-14)** — 소유자 판단. TTL 단위만으로 충분하다.

**TTL 단위 완료** — `9efecac6`. 파싱 전에 단위 표기를 초로 바꾼다. `1h`, `2d`, `1w`,
복합 표기 `1h30m` 을 받는다. RFC 1035 Section 5.1 은 10진 정수만 정의하므로
이건 표준 준수가 아니라 BIND 확장을 받아들이는 것이다. 내보낼 때는 계속 10진수로 쓴다.

건드리는 자리는 `$TTL` 인자와 소유자 다음 한두 토큰뿐이다. 소유자가 `1h` 인 호스트,
인용 문자열 안의 `1h`, 주석 안의 `1h`, 타입 이후는 바이트 그대로 둔다.
전처리는 `zonefile/ttl/` 로 분리했다.

**$GENERATE 는 남음** — 범위 전개는 별도 기능이고 훨씬 덜 쓰인다.

- **위치**: 의존 라이브러리 `domain 0.12.1`
- **확인**: `zonefile/inplace.rs:534,538,547` 이 처리하는 제어 지시자는
  `$ORIGIN`, `$INCLUDE`, `$TTL` 셋뿐. `$GENERATE` 는 `unknown_control` 로 빠져 파싱 오류.
  TTL은 `base/scan.rs:91` 의 `impl_scan_unsigned!(u32)` 를 타므로 순수 10진수만.
  `1h`, `1d`, `2w` 는 전부 실패한다.
- **파급**: 10번과 겹쳐, 단위 표기를 쓴 실제 BIND 파일은 import가 통째로 실패한다.
- **정상 동작 확인됨**: `$ORIGIN`, `$TTL`, 주석, 여러 줄 괄호, 클래스 필드,
  상대·절대 이름, `$TTL` 이 last-TTL보다 우선하는 규칙.
  `$INCLUDE` 는 명시적으로 거부한다 (`zonefile.rs:147-149`).
- **조치안**: TTL 단위는 전처리로 초 단위 변환 가능. `$GENERATE` 는 별도 확장.

### ~~26. 배치 수정·삭제가 없다~~ (삭제 완료, 교체 폐기)

**완료** — `DELETE /records?zone_name=&name=[&record_type=][&value=][&priority=]` 하나로
RRset 을 한 트랜잭션에 지운다. 시리얼 1회, NOTIFY 1회. 좁히기는 RFC 2136 Section 2.5.2
세 형태이고, nsupdate 가 이미 같은 술어를 쓰고 있어 `record::matching` 으로 합쳤다
(테스트 6건). 아무것도 매칭 안 되면 시리얼이 안 움직여 재시도가 공짜다. `name` 필수 —
없으면 존 전체 삭제의 두 번째 경로가 된다.

**폐기(교체)** — `PUT /records/bulk` (RRset 교체)는 만들지 않는다.
`DELETE /records` + `POST /records/bulk`, 존 단위로는 import upsert 로 덮으며,
ExternalDNS 는 자기 경로를 이미 갖고 있다.


- **위치**: `crates/bindizr/src/api/record.rs:29-36`
- **현재**: 배치 라우트는 `POST /records/bulk` 하나. 삽입 전용이다.
- **없음**: `PUT /records/bulk`, `DELETE /records/bulk`,
  조건부 `DELETE /records?zone_name=..&name=..&record_type=..`
- **문제**: RRset 삭제가 `DELETE /records/{id}` N회다.
  각각이 별도 트랜잭션, 별도 시리얼 증가, 별도 NOTIFY를 만든다.
- **부가**: RRset 단위 replace/upsert가 공개 API에 없다.
  존재하는 곳은 `POST /zones/{name}/import` 의 upsert 모드(존 전체)와
  `POST /external-dns/changes`(A/AAAA/CNAME/TXT 한정, 플래그로 켜야 함)뿐.
  `PUT /records/{id}` 는 이름과 달리 merge-patch 의미다 (`api/record.rs:142`).

### ~~27. 감사 로그가 없고 변경 주체를 기록하지 않는다~~ (주체 기록 완료)

- **위치**: `crates/bindizr-db/src/schema.rs` 전체 테이블 13개에 audit 계열 없음
- **테이블 목록**: api_tokens, catalog_zone_state, dnssec_keys, dnssec_policies,
  dnssec_records, dnssec_withdrawals, records, token_grants, tsig_grants,
  tsig_keys, zone_journal, zone_versions, zones
- **현재**: `ZoneVersion` 은 SOA 필드와 `created_at` 만 가진다
  (`crates/bindizr-core/src/model/zone_version.rs`).
  `changed_by`, `api_token_id`, `source`(api/cli/nsupdate/external-dns) 컬럼이 없다.
  변경 흔적은 구조화 로그 라인뿐이고 그마저 호출자를 담지 않는다.
- **문제**: "누가 이 존을 롤백했나", "누가 이 레코드를 지웠나" 를 DB로 답할 수 없다.
- **조치안**: `zone_versions` 에 주체 컬럼을 추가하는 것이 최소 변경.
  별도 audit 테이블은 그다음.
- **완료** — `zone_versions.change_source` + `changed_by`. 모든 시리얼 변경이
  `save_version_tx` 한 곳을 지나므로 거기서 찍는다. source 는
  `token`(API 토큰 이름) / `nsupdate`(서명한 TSIG 키 이름) /
  `system`(DNSSEC 유지보수 스케줄러) / `local`(데몬 소켓, 또는 인증 비활성 상태).
  이름은 FK 가 아니라 복사본이라 토큰이 지워져도 답이 남는다.
  `Caller` 에 `GlobalToken{name}` 을 더하고 `Token` 에 이름을 실었다.
- **남음**: 관리 평면(토큰·TSIG 키·정책 생성/삭제)은 시리얼을 안 움직이므로
  버전 행이 없고 여전히 추적되지 않는다. 별도 audit 테이블이 필요한 부분.

### ~~28. 토큰 lifecycle이 부족하다~~ (폐기)

**폐기** — rotate/update 를 만들지 않는다. 갱신할 거면 토큰을 다시 만들면 되고,
`revoked_at` 은 27번이 이름을 버전 행에 복사해 두면서 감사 근거로서의 값이 사라졌다
(게다가 UNIQUE(name) 때문에 이름 재사용도 막힌다).

- **위치**: `crates/bindizr-service/src/token/mod.rs:25,70,78,86`
- **있음**: `expires_at` 강제, `last_used_at` 기록
  (`crates/bindizr-core/src/model/api_token.rs`)
- **없음**: rotate(같은 이름·grant로 새 시크릿 발급), update(설명·만료 변경),
  명시적 `revoked_at`(현재는 삭제가 유일한 취소이고 흔적이 사라진다),
  "N일 내 만료 토큰 목록". grant 자체에는 만료가 없다.
- **서비스 메서드**: create, list, delete 셋뿐. `lookup_by_name` 은 더 이상 공개 메서드가 아니다.

### ~~29. grant가 쓰기 범위만 좁힌다~~ (완료)

- **위치**: `crates/bindizr-service/src/authorization/mod.rs:32-35`, `:86-91`, `:134-157`
- **현재**: `Caller` 는 `Global` 과 `Token{id, grants}` 두 상태.
  grant는 `zone_id + record_name_pattern + record_types` 를 가진다.
  `zone_visible()` 은 grant가 있는 존의 **모든 레코드 읽기**를 허용하고,
  패턴과 타입 목록은 쓰기에만 적용된다.
- **없음**: 읽기 전용 grant, grant별 `can_write` 플래그,
  "존은 만들되 토큰은 못 만드는" 중간 권한.
  존 lifecycle, 토큰, TSIG, 정책, grant 관리는 전부 `require_global` 이다.
- **완료(B안)**: `token_grants.can_write` 추가(`--read-only`),
  `Caller::record_visible` 로 목록/단건/ExternalDNS 읽기를 패턴·타입으로 좁힘,
  존 전체를 복원 소스로 쓰는 뷰(export, version, diff)는
  `ensure_zone_unrestricted` 로 무제한 grant 또는 Global 에만 허용.
- **완료(SQL 좁히기)** — `grant_record_match_sql` 을 `repository/sql.rs` 에 두고
  3개 백엔드 × 레코드/파생 × 목록·카운트 12곳의 `EXISTS` 절에 넣었다. 백엔드가
  갈리지 않도록 조각은 한 곳에서 렌더한다(MySQL 은 `||` 가 논리합이라 `CONCAT`).
  이제 페이지도 카운트도 같이 좁혀진다. SQL 은 저장형 이름을 레이블로 못 읽으므로
  서브트리 패턴은 과대근사이고(`a\.sub` 가 `sub` 아래처럼 통과), 정확한 판정은
  서비스가 계속 맡는다 — 방향이 안전해서 볼 수 있는 행을 떨어뜨리지 않는다.
  e2e 가 그 불일치까지 고정한다(항목 3개, total 4).

### ~~30. 목록 API가 일관되지 않는다~~ (완료)

**ExternalDNS 적재 완료** — `c373b6a9`. 5,000행씩 읽어 그룹에 접는다. 응답은 프로토콜상
한 번에 다 줘야 하므로 페이지로 나누지 않는다. 줄어드는 것은 원시 행을 그룹과 동시에 들고 있던 부분이다.
5,100 레코드 e2e 로 덮었고, 페이지를 100으로 줄여 51번 돌게 해도 통과하는 것까지 확인했다.

**완료 (2026-09-14)** — 세 가지가 모두 끝났다.

1. **목록 모양 통일** — `/tokens`, `/tsig-keys`, `/dnssec-policies`, grant 목록 5종이
   `{items, pagination}` 을 돌려준다. 전용 봉투 타입 5개는 삭제. 카운트 질의는 만들지
   않았다 — 관리 테이블은 배포당 수십 행이라 `from_collection` 이 전체를 읽고 서비스에서
   자른다(백엔드 3종 × 7 엔드포인트 = 21개 메서드를 추가할 값어치가 없다).
   HTTP 는 50 기본 페이징, 데몬 소켓은 제한 없음(기존 `/zones`·`/records` 와 같은 규칙).
2. **정렬** — `/zones` 와 `/records` 가 `sort`·`order` 를 받는다. 필드는 닫힌 enum 이라
   호출자 텍스트가 SQL 에 닿지 않고, `ORDER BY` 는 **항상 행 id 로 끝난다** — 동률이
   있는 컬럼으로 `LIMIT/OFFSET` 을 하면 페이지 간에 행이 새거나 중복되기 때문이다.
3. **존 필터** — `min_serial`, `max_serial`, `created_after`, `created_before`,
   `signed`(정책을 가진 존인지)를 더했다.

- **페이지네이션 있음**: `/zones`, `/records`, `/zones/{name}/versions`
- **없음 (Vec 그대로 반환)**: `/tokens`, `/tsig-keys`, `/dnssec-policies`,
  grant 목록 4종, `/external-dns/records`
**확인 (2026-09-12)** — 페이지 크기 기본값을 HTTP 경계로 옮긴 뒤에도 이 경로는 그대로다.
`list_records` 는 `RecordService` 를 거치지 않고 저장소를 직접 부르므로 기본값 자리를 지나지 않고,
저장소는 `limit` 이 없으면 `i64::MAX` 를 바인드한다(무제한). 즉 회귀는 없고 원래 문제만 남아 있다.

- **가장 위험**: `ExternalDnsService::list_records`
  (`crates/bindizr-service/src/external_dns/mod.rs:57-63`) 가
  `RecordFilter::default()` 로 grant가 있는 **모든 존의 모든 레코드**를
  한 번에 `BTreeMap` 에 적재한다. external-dns가 sync할 때마다 발생한다.
- **정렬**: `GetZonesFilter`, `GetRecordsFilter` 에 sort/order 필드가 없다.
  존은 `ORDER BY name`, 레코드는 `ORDER BY r.name, r.id` 로 고정.
- **필터 비대칭**: 레코드는 value 부분일치, min/max TTL, min/max priority,
  search, signed를 지원. 존은 mname/rname/default_ttl/serial만 있고
  serial 범위, 생성일, DNSSEC 여부 필터가 없다.

### ~~31. 존에 운영 메타데이터가 없다~~ (완료)

**완료 (2026-09-14)** — `enabled` 와 `description` 을 더했다.

1. **`enabled`** — DNS 평면의 존 조회 세 곳(`ZoneService::find_by_name`,
   `find_by_name_tx`, `list`)이 꺼진 존을 없는 것으로 본다. 그래서 SOA 응답·AXFR·
   IXFR·nsupdate 가 모두 거부되고, 카탈로그 멤버십과 NOTIFY 팬아웃에서 빠진다 —
   세컨더리가 낡은 사본을 붙들지 않고 존을 내린다. 관리 평면의 조회는
   `lookup_by_name`/`get_by_name_tx` 라서 그대로 편집된다.
   켜고 끄는 것이 카탈로그가 싣는 내용을 바꾸므로 rename 과 같이
   `catalog.bind` NOTIFY 를 보낸다.
2. **`description`** — 운영자 메모. bindizr 는 읽지 않는다. 255자 초과와 NUL 은
   백엔드마다 다른 insert 실패 대신 400 으로 막는다. 빈 문자열은 지운다.
3. **필터·CLI** — `/zones?enabled=`, `zone list --enabled`,
   `zone create --description`, `zone update --enabled/--description`,
   `zone list` 표의 SERVED·DESCRIPTION 열.

**하지 않은 것**

- `frozen` — `enabled` 와 구분되는 의미가 없다. 서빙만 멈추는 스위치 하나로 충분하다.
- `tags`, clone/copy, 존 템플릿 — 멀티테넌시 모델을 정하지 않기로 한 32번과 같은 범위다.
- `updated_at` — `zone_versions` 가 이미 변경마다 행을 남기므로 유도된다.
  열로 두면 존 데이터를 쓰는 다섯 자리가 전부 동기화 책임을 지는데, 그 값을
  읽는 곳이 없다.

- **위치**: `crates/bindizr-core/src/model/zone/mod.rs:13-36`
- **필드**: id, name, mname, rname, default_ttl, serial, refresh, retry,
  expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, created_at
- **없음**: `enabled` / `frozen`(삭제하지 않고 서빙만 중단할 방법이 없다),
  `comment` / `description` / `tags`, `updated_at`
- **있음**: rename은 지원된다 (`UpdateZoneRequest.name`).
- **없음**: clone/copy, 존 템플릿

### ~~32. NOTIFY 대상과 전송 ACL이 전역 목록 하나다 (보류)~~ (폐기)

**폐기 (2026-09-14)** — 보류에서 폐기로. 멀티테넌시 모델을 정하지 않는다.

**보류 (2026-09-13)** — 멀티테넌시 모델 전체를 정해야 해서 더 고민이 필요하다는 소유자 판단.
29번(읽기 범위)을 먼저 본다.


- **위치**: `crates/bindizr-service/src/dns_client/notify/mod.rs:54-57`,
  `crates/bindizr/src/dns/mod.rs:33`
- **현재**: 모든 존이 `config...dns.secondary_addrs` 를 읽고,
  서버 전체가 `SecondaryAcl::from_config()` 하나를 쓴다.
- **문제**: 모든 존이 모든 secondary에 통지하고 모든 secondary가 모든 존을 전송받는다.
  존별 also-notify, 존별 allow-transfer, 존별 ACL이 없어 멀티테넌트 격리가 불가능하다.

### ~~33. 존 기본값이 컴파일 상수이고 NS를 하나만 심는다~~ (NS 부분 남음)

**완료** — SOA 타이머 넷과 `default_ttl` 이 `[dns.zone_defaults]` 로 나왔다.
`CreateZoneRequest.default_ttl` 은 선택 필드가 되어 생략하면 설정값을 쓴다. 생성 시점만
읽으므로 설정을 바꿔도 기존 존은 움직이지 않는다. 차트가 `expire` 를 `3.6e+06` 으로
렌더해 TOML 이 정수로 못 읽던 것도 `int64` 로 고쳤다.

**NS 세트는 하지 않기로** — 전역 `nameservers` 를 넣었다가 뺐다. `ttl`/`refresh` 같은
숫자는 모든 존에 같아도 되지만 네임서버 **이름**은 존의 정체성이다. `mname` 이 이미
존별인데 그 옆에 전역 목록을 두면 모델이 엇갈린다. 하려면 존 생성 요청 필드로 받는 게
맞다.


- **위치**: `crates/bindizr-service/src/zone/mod.rs:17-21`
- **상수**: DEFAULT_REFRESH=300, DEFAULT_RETRY=60,
  DEFAULT_EXPIRE=3_600_000, DEFAULT_MINIMUM_TTL=86_400
- **`default_ttl` 은 기본값이 아예 없다.** `CreateZoneRequest.default_ttl` 이
  필수 `i32` 라 존을 만들 때마다 명시해야 한다. `[dns]` 설정에 관련 키가 없다.
- **NS**: `zone/create.rs:97` 이 `created_zone.mname_record(...)` 하나만 넣는다.
  ns1/ns2/ns3 구성이면 나머지를 매번 수동 추가해야 한다.
  설정 가능한 기본 NS 세트가 없다.

### ~~34. ExternalDNS DomainFilter가 좁힌 grant를 표현하지 못한다~~ (완료)

**완료 (2026-09-14)** — 필터가 grant를 말하게 했다.

`GET /external-dns/zones` 는 grant 가 어떻게 좁혀져 있든 **존 이름**만 돌려줬다.
그래서 `*.k8s` 로 좁힌 토큰에게도 external-dns 는 존 전체를 준 것으로 알고,
`www` 같은 바깥 이름을 계획하고, apply 가 all-or-nothing 이라 sync 전체가 죽었다.

이제 `GET /external-dns/domains` 가 grant 가 덮는 **이름**을 돌려준다:
`*` → 존 이름, `*.k8s` → `k8s.<zone>`, 정확한 이름 `www` → `www.<zone>`.
external-dns 의 DomainFilter 는 include 항목이 자기 자신과 그 아래 전부를 덮는
suffix 매칭이므로, 서브트리 grant 는 정확히 표현된다. 쓰기 없는 grant 는
external-dns 가 할 일이 없으므로 필터에서 뺀다.

엔드포인트와 페이로드 이름도 바꿨다 — `k8s.example.com` 은 존이 아니다:
`/external-dns/zones` `{zones}` → `/external-dns/domains` `{domains}`,
`ExternalDnsZonesResponse` → `ExternalDnsDomainsResponse`,
어댑터의 `list_zones` → `list_domains`.

**여전히 표현 못 하는 것** (suffix 필터의 한계이지 구현의 한계가 아니다)

- `record_types` 로 좁힌 grant — DomainFilter 에 타입 개념이 없다.
- `@`(apex 만)와 정확한 이름 grant — 필터 항목은 항상 그 아래를 포함하므로
  실제보다 넓게 읽힌다. 오늘보다 좁아지기는 하지만 정확하지는 않다.
  `regexInclude` 로는 정확히 쓸 수 있으나 external-dns 의 `Match` 는 regex 가
  하나라도 있으면 include/exclude 목록을 통째로 무시하므로, 전부를 하나의 거대한
  정규식으로 합쳐야 한다. 값어치가 없다고 판단.

문서(`docs/external-dns.md`)의 트러블슈팅 행과 grant 설명을 이 경계에 맞춰 고쳤다.

**하지 않은 것**

- 존 단위 `external_dns_enabled` 플래그 — grant 가 이미 그 스위치다.
- owner TXT 레지스트리 인지 처리 — 일반 TXT 로 그대로 저장하는 게 맞다.
  레지스트리의 의미는 external-dns 것이고, bindizr 가 해석하면 두 곳이 어긋난다.
- `setIdentifier`, providerSpecific — 가중치·지역 라우팅은 bindizr 데이터 모델에
  대응물이 없다. 받아서 버리느니 거부하는 지금이 정직하다.

- **위치**: `crates/bindizr-external-dns/src/wire/mod.rs:65-68`
- **현재**: `DomainFilter` 는 `include` 만 직렬화한다.
  `exclude`, `regexInclude`, `regexExclude` 가 없다.
  `list_zone_names` 는 존 이름만 반환한다.
- **문제**: `record_name_pattern` 이나 `record_types` 로 좁힌 grant가
  external-dns에게 보이지 않는다. external-dns가 거부될 변경을 계획하고,
  apply가 all-or-nothing이라 **레코드 하나가 막히면 sync 전체가 실패**한다.
  `docs/external-dns.md` 는 이를 트러블슈팅 항목으로만 적어 두었다.
- **없음**: 존 단위 `external_dns_enabled` 플래그,
  owner TXT 레지스트리 인지 처리(현재는 일반 TXT로 그대로 저장),
  `setIdentifier` 지원(`wire/mod.rs:154-156` 이 거부하므로 가중치·지역 라우팅 불가),
  providerSpecific 유지(`wire/mod.rs:230` 에서 비운다)
- **정상 확인됨**: 웹훅 4개 엔드포인트 전부 구현.
  `GET /`, `GET /records`, `POST /records`, `POST /adjustendpoints`.
  미디어 타입 협상도 정확하다.

### ~~35. API에 없고 소켓·CLI에만 있는 것~~ (폐기)

**폐기 (2026-09-14)** — 소유자 판단. 소켓·CLI 전용으로 남긴다.

- **DNSSEC 키 export/import**: `socket/types.rs:64-65` 에 있고
  `bindizr dnssec keys` 로 노출되지만 `api/dnssec.rs:26-46` 의 라우트에는 없다.
  개인키라 의도적일 수 있으나 그 판단이 문서화되어 있지 않다.
- **doctor**: `socket/server/doctor.rs` 가 DB 검사 + DNS 리스너 + 카탈로그 시리얼 +
  secondary별 SOA/NOTIFY 프로브를 수행한다. 제품에서 가장 깊은 헬스 신호인데
  원격 모니터링에서 접근할 방법이 없다. `/health` 는 DB만 본다
  (`api/health.rs:24-37`).
- **status / config / shutdown / restart**: 소켓 전용.

### ~~36. 응답 오류 본문 형식이 세 가지다~~

**완료 (재검증 2026-09-13)** — 네 경로 전부 `{error, code}` JSON 을 낸다. 라이브로 확인:
없는 경로 `ENDPOINT_NOT_FOUND`, 405 `METHOD_NOT_ALLOWED`, `?limit=abc` 와
`/records/notanumber` 는 `INVALID_INPUT`. `api/error.rs` 가 `Query`/`Path` 를 감싸고
`router.rs` 가 두 fallback 을 `ApiError` 로 낸다. `dnssec_signing_failed` 는 전용
`ErrorCode::DnssecSigningFailed` 를 쓰고, `CliError::hint()` 는 37개 코드를 빠짐없이
처리한다(힌트가 없을 이유가 붙은 `None` 포함). exit code 매핑도 테스트가 있다.


- JSON `ErrorResponse{error, code}` — 핸들러 오류 (`api/error.rs:26-32`)
- 평문 `"404 Not Found"` — 매치 안 된 경로 (`api/router.rs:109-111`)
- axum 기본 평문 400 — `Query`/`Path` 추출 실패.
  `api/error.rs` 는 `JsonRejection` 만 매핑하는데 모든 핸들러가 `Query(...)` 를 직접 받는다.
- **문제**: `.code` 를 파싱하는 클라이언트가 쿼리 파라미터 오타 하나에 깨진다.
  405 응답도 본문이 비어 있다.
- **부가**: `ServiceError::dnssec_signing_failed` 만 전용 코드가 없어
  `ErrorCode::Internal` 로 뭉개진다. 서명 실패와 DB 장애를 구분할 수 없다.
- **부가**: `CliError::hint()` 가 34개 코드 중 5개만 다룬다.
  Forbidden, RecordConflict, TsigKeyInUse, DnssecPolicyInUse, DnssecNotEnabled 등
  자주 나오는 것들에 힌트가 없다.

### ~~37. CLI UX~~ (완료)

**완료 (2026-09-14)** — 남아 있던 셋 중 둘.

1. **exit code** — not-found(3)/충돌(4)/거부(5)는 36번에서 이미 끝났고,
   "데몬 미실행" 만 실패(1) 에 섞여 있었다. `CliError::daemon_unreachable` 로
   분리해 **6** 으로 나간다. 응답이 아예 오지 않은 실패라 `ErrorCode` 가 실을 수
   없으므로 코드가 아니라 별도 플래그로 들고 간다. 스크립트가 재시도할 것(서비스가
   없음)과 재시도해도 소용없는 것(요청이 거부됨)이 이제 갈린다.
2. **`--config` 불일치** — `config check` 가 위치 인자 대신 `start`·`doctor` 와
   같은 `-c/--config` 를 받는다. 세 명령이 한 철자로 통일되고, 셋 다 인자가 없으면
   `BINDIZR_CONFIG_PATH` 로 떨어진다. `docs/cli/index.md` 와
   `docs/configuration.md` 에 이 규칙을 적었다.

**셸 자동완성 — 폐기 (2026-09-14)** — `clap_complete` 의존성과 `bindizr completion
<shell>` 서브커맨드를 만들었다가 소유자 판단으로 되돌렸다.

**`--quiet` — 하지 않음** — 성공 출력은 stdout, 오류·힌트는 stderr 로 이미 갈려
있어서 `> /dev/null` 과 하는 일이 같다. `-q` 는 `zone list`·`record list` 의
`--search` 가 이미 쓰고 있어 짧은 형태도 못 준다. 플래그가 할 일이 없다.

**확인 프롬프트 — 폐기됨 (2026-09-12)**, 다시 제안하지 않는다.

- **위치**: `crates/bindizr/src/cli/mod.rs:115-121`
- **없음**: 셸 자동완성(`clap_complete` 의존성도 `completion` 서브커맨드도 없다),
  `--quiet` / `-q`, 파괴적 작업 확인 프롬프트나 `--yes` / `--force`
- **exit code**: 모든 실패가 `std::process::exit(1)`.
  not-found, 권한 거부, 충돌, "데몬 미실행" 이 스크립트에서 구분 불가.
  `CliError` 는 이미 `ErrorCode` 를 들고 있으므로 매핑만 하면 된다.
- **확인 프롬프트는 폐기됨 (2026-09-12)** — `--yes` 와 TTY 프롬프트를 만들었다가
  소유자 판단으로 되돌렸다. **다시 제안하지 않는다.**
- **`zone delete`** 는 존과 그 아래 모든 레코드를 확인 없이 지운다.
  token/tsig-key/dnssec-policy delete, `zone version rollback` 도 같다.
  유일한 안전장치는 import/bulk/rollback의 `--dry-run`.
- **`--config` 불일치**: `-c/--config` 는 `start` 와 `doctor` 에만 있다.
  `config check` 는 위치 인자로 파일을 받는다.
  `BINDIZR_CONFIG_PATH` 는 동작하지만 `docs/cli/index.md` 에 없다.

### ~~70. SQLite 파일을 스스로 만들지 않는다~~

**완료** — `ae30e7c6`. `SqliteConnectOptions` 에 `create_if_missing` 을 켜고 `connect_with` 로 붙는다.
e2e 하네스가 파일을 미리 만들던 우회 코드도 지웠다.

- **위치**: `crates/bindizr-db/src/lib.rs:192` 의 `.connect(url)`,
  URL 생성은 `crates/bindizr-db/src/utils.rs:11`
- **현재**: URL 이 `sqlite:<path>` 형태이고 `?mode=rwc` 도 `create_if_missing` 도 없다.
  sqlx 기본값이 `create_if_missing = false` 라 파일이 이미 있어야 한다.
- **증거**: e2e 하네스가 `fs::File::create(&db_path)` 로 미리 만든다
  (`crates/bindizr-e2e/tests/common/mod.rs:85`). 없으면
  `(code: 14) unable to open database file` 로 기동이 실패한다. 직접 재현했다.
- **문제**: 클린 설치만 지원하는 프로젝트인데 문서가 안내하는 설정 그대로
  새 경로를 지정하면 기동하지 못한다. 저장소 루트에 `bindizr.db` 가 커밋되어 있어
  개발 중에는 가려진다.
- **조치안**: `create_if_missing` 을 켜거나, 없으면 만들라고 문서에 명시한다.

### ~~71. AXFR 존 가져오기가 텍스트를 거쳐 되파싱한다~~ (폐기)

**폐기 (2026-09-14)** — 확인된 결함이 없고 왕복 비용도 문제가 된 적이 없다.

- **위치**: `crates/bindizr-service/src/dns_client/axfr.rs:125` `render_zone_file`
- **현재**: 전송으로 받은 구조화된 RR 을 존파일 텍스트로 렌더링하고,
  그 텍스트를 import 경로에 넣어 `parse_zone_file` 로 되파싱한다.
- **문제**: import 의 검증·조정 로직을 재사용하려는 의도로 보이지만,
  렌더링과 파싱 양쪽에서 이스케이프를 정확히 맞춰야 한다.
  구조체에서 텍스트로 갔다가 다시 구조체로 오는 왕복이다.
- **조치안**: import 의 조정 단계를 파싱된 RR 을 받는 형태로 분리할 수 있는지 본다.
  당장의 결함은 확인되지 않았으므로 우선순위는 낮다.
- **검증 완료** — 왕복이 이스케이프를 보존하는지 `render_zone_file` → `parse_zone_file`
  회귀 테스트로 고정했다. `domain` 의 `Label` Display 가 `.`/`\`/공백과 비출력 옥텟을
  이스케이프하고, 우리 파서가 같은 규칙으로 되읽는다. 구조 변경은 하지 않았다.

---

## P3 — DNSSEC

### ~~38. 자기가 만든 서명을 한 번도 검증하지 않는다~~ (폐기)

**폐기** — 옵트인 스위트라 평소에 안 돌고, 제대로 하려면 e2e 스택에 이미지가 하나 더 붙는다.
추가 조사: compose 의 amd64 ISC 이미지에만 `dnssec-verify` 가 있고 ARM 오버라이드의
`ubuntu/bind9` 에는 `named-checkzone` 뿐이다(서명 검증을 하지 않음). qemu 로 amd64 ISC 툴을
돌리면 `dnssec-verify` 가 segfault 한다. `debian:trixie-slim` + `bind9-dnsutils`/`bind9-utils`
는 arm64 네이티브로 `dnssec-verify`·`delv` 를 주므로, 되살릴 거면 그 경로다.

- **확인**: `crates/bindizr-core/src/dns/dnssec/` 와
  `crates/bindizr-service/src/dnssec/` 전체에 검증 호출이 0건.
  `delv`, `dnssec-verify`, `named-checkzone -D` 를 쓰는 테스트도 없다.
- **현재**: `sign_zone_locked` (`dnssec/mod.rs:158-252`) 가 조건 없이 diff를 쓰고 저널링한다.
- **문제**: BIND secondary는 AXFR로 받은 존을 검증하지 않는다.
  서명 버그가 조용히 프로덕션에 나가고 리졸버만 알아챈다.
**조사 완료 (미착수)** — "서명 후 자체 검사" 의 값싼 버전은 무의미하다.
서명 검증은 서명 대상 바이트(RRSIG RDATA 앞부분 + 정규 순서 RRset)를 만들어야 하는데,
`domain` 0.12.1 은 그 조립을 노출하지 않는다. `PublicKey::verify(signed_data, signature)`
저수준 함수만 있다 (`crypto/common.rs:188`). validator 모듈은 리졸버용 메시지 검증이라
async 컨텍스트와 `Bytes` 그룹을 요구해 맞지 않는다.

따라서 자체 검사를 넣으려면 그 조립을 다시 구현해야 하는데, **서명할 때 쓴 것과 같은 코드로
검증하면 조립이 틀려도 통과한다.** 키 불일치만 잡고 정규화 오류는 못 잡는다. 잡으려던 걸 못 잡는다.

제대로 하려면 독립 구현, 실질적으로는 외부 검증기가 필요하다. compose 스택에 BIND9 가 있으므로
`dnssec-verify` 나 검증 리졸버로 확인하는 e2e 가 현실적인 길이다. 다만 DNS 검증 e2e 는
`BINDIZR_E2E_VERIFY_DNS` 옵트인이라 기본 스위트에서는 돌지 않는다.

- **조치안**: 서명 후 자체 검사를 넣는다.
  DNSKEY RRset이 published DS가 가리키는 키의 RRSIG로 덮이는지,
  서명 대상 RRset마다 RRSIG가 있는지, 부인 체인이 닫히는지.
  검증 리졸버로 확인하는 e2e도 추가한다.

### ~~39. 부모 DS TTL을 수집만 하고 쓰지 않는다~~ (40번과 함께 완료)

**완료 (2026-09-14)** — 승격을 확인한 그 탐침 응답의 `ds_ttl` 을 `promote_published_keys_tx`
로 넘겨 SEP 키의 은퇴 대기에 쓴다. 보류 사유 두 가지가 모두 사라졌다: 은퇴 홀드다운(2일)을
없앴으므로 "기본값에서 효과 없음"이 아니고, 40번이 들어오면서 그 탐침이 승격을 결정하는
바로 그 답이라 "물어봐야 아는 사실에 기한이 의존한다"가 아니라 **기한을 정하는 답 자체**다.
`--skip-ds-check` 로 탐침을 건너뛰면 TTL 도 없으므로 서명 TTL 만 남는다.


**보류** — 관측한 DS TTL 을 은퇴 `eligible_at` 의 하한으로 넣는 수정을 만들어
검증까지 마쳤으나 소유자 판단으로 되돌렸다. 이유는 두 가지다.

기본값에서 효과가 없다. 내장 정책의 은퇴 대기가 172,800초(2일)이고 레지스트라가
흔히 쓰는 DS TTL 은 86,400초(1일)라 이미 더 길다. 운영자가 대기를 줄였거나
부모 TTL 이 2일을 넘을 때만 동작한다.

그리고 스케줄러가 드는 상태의 성격이 나빠진다. `eligible_at` 은 이미 굳는 기한이지만,
그 값이 **그 순간 부모가 답한 TTL** 에 의존하게 된다. 정책 값은 우리가 아는 사실이고
부모 TTL 은 물어봐야 아는 사실이다. 부모가 나중에 TTL 을 바꿔도 굳은 기한은 안 움직인다.

제대로 다루려면 스케줄러가 지울 시점에 부모를 다시 물어보는 쪽이고 그건 40번의 영역이다.

- **위치**: 생성 `dnssec/delegation.rs:126`, 노출 `types/dnssec.rs:82`
- **미사용 확인**: `ds_ttl` 는 이 두 곳에만 존재한다.
- **현재**: `rollover.rs:250` 의 `retire_wait_floor` 는
  `policy.rollover_retire_holddown_secs` 이고
  `:258-263` 이 `max_signed_ttl` 과만 max를 취한다.
- **문제**: `ds-seen` 이후에도 리졸버는 부모의 DS TTL만큼 예전 DS를 들고 있다.
  레지스트라는 흔히 86400을 쓴다. 그동안 은퇴한 KSK로 검증하는데
  스케줄러는 기본 2일 뒤 그 키를 지운다.
- **조치안**: 관측한 부모 DS TTL과 전파 지연을 은퇴 `eligible_at` 계산에 넣는다.

### ~~40. 스케줄러가 부모를 폴링하지 않아 KSK 롤오버가 자동으로 끝나지 않는다~~ (완료)

**완료 (2026-09-14)** — 이전 폐기 결정을 소유자가 뒤집었다. 유지보수 패스가 발행 대기를
넘긴 SEP 키를 가진 존마다 부모에게 DS 를 물어, 모든 부모 서버가 새 DS 를 서빙하면 승격한다.
`ds-seen` 은 **override 로 남긴다** — `--skip-ds-check`(부모에 닿을 수 없는 배포)와
`--skip-holddown`(키 유출)은 스케줄러가 표현할 수 없는 수단이고, 즉시 끝내는 경로이기도 하다.
부모가 아직 DS 를 안 주거나 답이 없으면 실패가 아니라 대기이므로 `Ok(None)` 으로 넘어간다.

- **위치**: `crates/bindizr-service/src/dnssec/maintenance.rs:43-192`
- **현재 수행 작업**: 저널 프루닝(`:50`), 서명 갱신,
  ZSK 롤 시작(`:99`), ZSK 승격(`:139`), 은퇴 키 제거(`:169`)
- **없음**: `probe_delegation` 호출이 한 건도 없다.
- **문제**: bindizr는 CDS/CDNSKEY를 발행하므로 CDS를 소비하는 부모는
  스스로 새 DS를 설치한다. 그런데 롤오버는 사람이
  `dnssec rollover ds-seen` 을 칠 때까지 멈춰 있다.
- **조치안**: BIND의 checkds에 해당하는 폴링을 추가하고,
  모든 부모 서버가 새 DS를 서빙하면 롤오버를 자동 진행한다.
  `ksk_lifetime_days` 도 함께 필요하다.

### ~~41. 정책에 타이밍 옵션이 부족하다~~ (홀드다운 둘 다 제거)

- **위치**: `crates/bindizr-core/src/model/dnssec_policy.rs:60-88`
- **있음**: signature_validity_days, signature_refresh_days, zsk_lifetime_days,
  rollover_publish_holddown_secs, rollover_retire_holddown_secs
- **없음** (BIND/Knot `dnssec-policy` 대비): publish-safety, retire-safety,
  zone-propagation-delay, parent-propagation-delay, parent-ds-ttl,
  dnskey-ttl, max-zone-ttl, ksk-lifetime
- **부가**: publish 대기는 `max(holddown, zone.default_ttl)` 인데
  기준 시점이 **DB 쓰기 시각**이다. secondary가 지연되거나 죽어 있으면
  그 키를 한 번도 서빙하지 않았는데 홀드다운이 끝난다.
- **폐기(전파 지연)** — `zone_propagation_delay_secs` 를 넣었다가 되돌렸다. 운영자가 적는
  숫자는 추측이고(세컨더리가 30분 죽어 있었으면 거짓말, 같은 랙이면 버리는 시간),
  bindizr 는 `probe_secondaries` 로 실제 도착을 볼 수 있으므로 추측값을 받을 이유가 없다.
  관측형(도착을 본 순간부터 TTL)은 세컨더리가 죽으면 롤오버가 멈추는 대가가 있어 보류.
  **전송은 즉시 도착한다고 가정**하고 대기는 `max(홀드다운, TTL)` 그대로 둔다.
- **제거** — `rollover_publish_holddown_secs` 를 없앴다. publish 대기가 덮어야 하는 건
  **옛 DNSKEY 답 하나**뿐이고 그 TTL 은 `zone.default_ttl` 로 bindizr 가 정확히 안다.
  CSK/KSK 의 "부모에 새 DS 가 들어갔나"는 홀드다운이 아니라 `ds-seen` 이 직접 물어서
  확인하므로, 바닥 위에 얹던 값은 순수 보수성이었다. 대기는 이제 `zone.default_ttl` 하나다.
  `rollover_retire_holddown_secs` 도 없앴다 — 은퇴 대기가 덮는 두 가지가 모두 알려진 값이
  되었다: 키가 만든 서명은 `max_signed_ttl`, 부모의 DS 는 존의 새 `parent_ds_ttl` 이다.
  SEP 키만 후자를 기다린다(ZSK 는 부모에 DS 가 없다).
- **`zones.parent_ds_ttl` 추가** — `dnssec enable` 에서 `parent_ns_addrs` 와 함께 필수로
  받고 `dnssec set` 으로 바꾼다. 부모에게 물어서 알아내지 않는 이유: 은퇴 대기의 시계는
  **부모가 옛 DS 를 내린 순간**부터 도는데 그 순간은 관측할 수 없다(관측하려면 40번).
  TTL 값 자체는 레지스트라가 공표하므로 운영자가 아는 사실이다.
- **나머지 옵션에 대한 판단**:
  - `dnskey-ttl`, `max-zone-ttl`: bindizr 는 존에서 직접 읽는다
    (`zone.default_ttl`, 키별 `max_signed_ttl` 을 서명 패스마다 갱신).
    BIND 는 모르니까 물어보는 값이고, 여기서는 측정값이다.
  - `publish-safety`, `retire-safety`: BIND 는 계산된 간격에 얹는 여유인데
    bindizr 의 홀드다운이 이미 운영자가 정하는 바닥이라 같은 역할이 중복된다.
  - `parent-propagation-delay`, `parent-ds-ttl`: `ds-seen` 이 부모 서버에 직접 물어
    DS 존재를 확인한다(43번). 추정 대신 측정이라 값이 필요 없다.
  - `ksk-lifetime`: KSK 롤은 부모 개입(ds-seen)이 필요해 일정만으로 끝나지 않는다.
    자동 시작해두고 무기한 대기하는 상태를 만들 값어치가 없다고 봤다.

### ~~42. NSEC3 파라미터가 고정이고 denial 모드를 서명 중 바꿀 수 없다~~ (기본값·전환 완료)

- **위치**: `crates/bindizr-core/src/dns/dnssec/signed_view/mod.rs:545-552`
- **현재**: `GenerateNsec3Config::default()` 를 넘긴다.
  주석이 밝히듯 RFC 9276 프로파일(SHA-1, 0 iterations, salt 없음, opt-out 없음)이다.
  이 자체는 현대 권장값이라 기본값으로는 옳다.
- **없음**: opt-out 옵션(위임이 많은 존에 필요), salt 재생성,
  정책의 NSEC3 관련 필드 일체
- **기본값 문제**: 정책 생성 시 denial 기본이 **NSEC** 이다
  (`dnssec_policy/mod.rs:48`). 문서대로 DNSSEC를 켜면 존이 walk 가능해진다.
  `ldns-walk` 로 열거된다.
- **전환 불가**: `lifecycle.rs:181-190` 이 서명 중 NSEC↔NSEC3 변경을 거부한다.
  "disable DNSSEC and re-enable" 하라고 안내한다.
  BIND와 Knot은 온라인 전환을 지원한다.
- **조치안**: 기본을 NSEC3로 바꿀지 결정하고, 온라인 전환 경로를 만든다.
- **완료** — 정책 기본 denial 과 시드된 `default` 정책을 NSEC3 로 바꿨다(백엔드 3종).
  정책 이동 시 denial 거부를 제거했다: bindizr 가 서명에 쓰는 알고리즘(8,10,13,14,15,16)은
  전부 NSEC3-capable 이라(RFC 5155 Section 2) 키 롤 없이 한 시리얼에 사슬이 통째로 교체된다.
  서명 뷰 diff 가 (name,type,ttl,rdata) 집합 차라서 NSEC 제거 + NSEC3/NSEC3PARAM 추가가
  그대로 나온다. e2e 로 양방향 전환을 고정했다.
- **안 함**: opt-out, salt 재생성, NSEC3 정책 필드. RFC 9276 이 salt 없음·0 iterations 를
  권고하고, opt-out 은 위임이 아주 많은 존에만 해당한다.

### ~~43. 부모 DS 응답을 인증 없이 신뢰한다~~ (수용)

**수용 (2026-09-13)** — 위협 모델이 이 경로에만 해당하지 않는다. bindizr 의 모든
아웃바운드 DNS(세컨더리 SOA 탐침, 인바운드 AXFR, NOTIFY 응답)가 같은 평문 DNS 이고,
DS 질의만 특별 취급할 근거가 없다. 감사의 조치안 중 "DO+AD 요구" 는 틀렸다 — AD 는
검증하는 리졸버가 세우는 비트인데 bindizr 는 부모의 권한 서버에 직접 묻는다.

경로 밖 공격자는 `rand::random::<u16>()` query id + OS 임의 소스 포트로 평문 DNS 가
할 수 있는 만큼 이미 막혀 있다. 경로상 공격자는 설정된 **모든** 부모 서버 경로를
동시에, 운영자가 `disable` 을 실행하는 순간에 장악해야 하는데, 그 정도 위치면 존
트래픽을 직접 끊는 편이 쉽다. 유일한 추가 이득은 지속성이다.

진짜 인증(DS RRSIG 검증)은 루트 신뢰 앵커까지의 사슬이 필요해 검증 리졸버를 직접
만드는 일이다 — 38번과 같은 결론.

**대신 한 일** — 합성 규칙을 `to_delegation_info` 로 빼고 테스트 7건으로 고정했다.
`disable` 거부는 합집합(한 서버라도 DS 를 보이면 거부), `ds-seen` 승격은 전원 일치.
둘이 반대 방향인 것 자체가 안전 속성인데 아무도 지키지 않고 있었다.


- **위치**: `crates/bindizr-service/src/dns_client/ds/mod.rs:42-62`, `:259`
**재검증 (2026-09-12)** — 위치가 `dns_client/ds/mod.rs:111` (`query_ds_at`) 로 옮겼다.
그리고 감사의 표현이 부정확하다. `false` 인자는 DO 가 아니라 `rd` 다.
`build_edns_question` 은 OPT 페이로드 크기만 설정하고 DO 를 아예 세우지 않으므로
RRSIG 를 요청하지 않는다. 주장의 실질은 그대로 사실이다.

- **현재**: `build_edns_question(false, ...)` 로 질의하고,
  `extract_ds_rrset` (`crates/bindizr-core/src/dns/query/mod.rs:299-341`) 이
  AA 응답이면 받는다.
- **문제**: `disable` 은 DS가 **보일 때만** 거부한다 (`lifecycle.rs:253-259`).
  경로상 공격자나 거짓말하는 부모 서버가 "DS 없음" 을 답하면
  실제 DS가 살아 있는데 서명을 벗겨낸다. 이 검사가 막으려던 bogus 상태 그 자체다.
- **조치안**: DO+AD를 요구하거나 부모 DNSKEY로 DS RRSIG를 검증한다.
  최소한 여러 서버의 합의를 요구하고 위협 모델을 문서화한다.

### ~~44. 지원하지 않는 digest 타입을 "DS 없음" 으로 읽는다~~

**완료** — `30665191`. 위임 항목에 `ds_digest_unsupported` 를 두고 `ds-seen` 이
`DS_NOT_PUBLISHED` 대신 `DS_UNVERIFIED` 로 답한다. IANA digest 타입은 6종(1 SHA-1,
2 SHA-256, 3 GOST-94, 4 SHA-384, 5 GOST-2012, 6 SM3)이고 bindizr 는 3종을 계산하므로
"판단 불가" 는 코드가 표현해야 하는 상태다. 3번은 RFC 8624 Section 3.3 이 새 위임에
금지하는 폐기 알고리즘이라 지원하지 않기로 했다.

- **위치**: `crates/bindizr-core/src/dns/dnssec/mod.rs:70`
  `pub const DS_DIGEST_TYPES: [u8; 3] = [1, 2, 4];`
- **현재**: `delegation.rs:80-88` 이 부모 레코드를 이 셋으로 거른 뒤 매칭한다.
- **문제**: 부모가 지원 외 digest만 발행하면 `ds_published = false` 가 영구 고정되고
  `ds-seen` 이 `DNSSEC_DS_NOT_PUBLISHED` 로 실패한다. 사실과 다르다. DS는 있다.
- **안전한 쪽**: `disable` 경로는 `ds_key_tags` 가 개수를 세므로 올바르게 거부한다.
- **조치안**: "확인 불가한 digest 타입의 DS 존재" 를 "DS 없음" 과 구분한다.

### ~~45. 부모 탐색이 ANSWER 섹션만 읽는다~~ (탐색 제거로 대체)

**결정** — AUTHORITY 폴백을 만들어 검증까지 했으나 소유자 판단으로 부모 탐색 자체를 없앴다.
`dnssec enable` 이 `parent_ns_addrs` 를 필수로 받는다. 46번도 함께 사라진다.

- **위치**: `crates/bindizr-core/src/dns/query/mod.rs:361-381`
- **현재**: `extract_ns_names` 가 `message.answer()` 만 훑는다.
  owner가 qname과 같은 NS만 취한다. CNAME 케이스는 이 때문에 올바르게 처리된다.
- **문제**: 위임을 AUTHORITY 섹션으로만 돌려주는 리졸버나 포워더에서는
  빈 목록이 나온다. 조상 탐색이 진짜 부모를 지나쳐 루트까지 올라가고,
  루트에 보낸 DS 질의가 권한 없는 리퍼럴을 받아 혼란스러운 메시지로 실패한다.
- **조치안**: AUTHORITY 섹션을 폴백으로 읽거나 "ANSWER에 NS 없음" 을 별도로 보고한다.

### ~~46. 로컬에서 서빙하는 부모를 특별 취급하지 않는다~~ (탐색 제거로 대체)

**결정** — 45번과 같은 변경으로 사라진다. 리졸버를 거치는 경로가 없어졌다.
자식 CDS 로 부모 존 DS 를 갱신하는 건은 별개로 남는다.

- **위치**: `crates/bindizr-service/src/dns_client/ds/mod.rs:24`, `:85-102`, `:124-147`
- **현재**: 탐색이 항상 `/etc/resolv.conf` 를 거친다.
- **문제**: 통상적인 hidden primary 구성에서 호스트 리졸버는
  bindizr가 서빙하는 존을 볼 수 없다.
  bindizr가 관리하는 부모의 자식 존이면 `check-ds`, `ds-seen`, `disable` 이
  전부 `DNSSEC_DS_UNVERIFIED` 로 실패한다.
  운영자가 `parent_ns_addrs` 를 손으로 넣어야 한다.
- **부가**: 자식의 CDS를 읽어 부모 존의 DS를 갱신하는 코드가 없다.
  DS는 사용자 레코드 타입으로 지원되고 위임 DS는 올바르게 서명되므로 재료는 있다.

### ~~47. 키 import가 롤오버 중인 존을 표현하지 못한다~~ (완료)

**완료 (2026-09-14)** — BIND 키 파일이 이미 답을 들고 있었다.

`K*.private` 에는 `dnssec-keygen`·`dnssec-settime` 이 쓴 타이밍 필드가 있다
(`Created`/`Publish`/`Activate`/`Inactive`/`Delete`, UTC `YYYYMMDDHHMMSS`).
BIND 9.20 으로 실제 파일을 만들어 확인했고, `domain` 의 파서가 모르는 필드를
건너뛰므로 이미 그대로 통과하고 있었다. 이제 import 가 그걸 읽는다:

| | |
| --- | --- |
| `Publish` 이후, `Activate` 이전 | `published` |
| `Activate` 이후 | `active` |
| `Inactive` 이후 | `retired`, `eligible_at` 은 `Delete` |
| `Publish` 이전 / `Delete` 이후 | 거부 — BIND 도 안 서빙하는 상태다 |
| 필드 없음 | `active` (정착한 존, 또는 bindizr 자신의 예전 export) |

`state_changed_at` 도 해당 타임스탬프를 그대로 가져간다. 유지보수 스케줄러의
ZSK 수명 계산이 이 값을 읽으므로, 50일 쓴 ZSK 를 이관하면 60일 정책에서
10일 뒤에 구르지 60일 뒤가 아니다.

**export 도 같이 고쳤다** — 저장하는 개인키는 타이밍이 없는 형태라
export→import 왕복이 롤오버를 뭉갰다. 이제 export 가 키의 상태에서 같은
필드를 써 낸다. bindizr 끼리도, BIND 로도 왕복이 성립한다.

**검증** — 상태 판정·왕복 단위 테스트 5개(실제 BIND 키 파일 고정값 사용),
그리고 e2e: 롤오버 시작 → export → disable → import 후 `(tag, state)` 가
그대로이고 `rollover start` 가 "진행 중" 으로 거부되는 것까지.

**부가 항목 둘 — 하지 않음**

- **RSASHA1(5, 7)** — `domain` 의 `SecretKeyBytes::parse_from_bind` 이 8·10·13·
  14·15·16 만 받는다(확인함). 뚫으려면 파서를 우회해야 하는데, 그러면 bindizr 가
  SHA-1 로 **서명**하게 된다. RFC 8624 가 서명 용도로 MUST NOT 한 알고리즘이다.
- **RSA 4096** — todo 의 서술이 틀렸다. 2048 상수는 `generate_key` 에만 있고
  import 는 크기를 보지 않는다. BIND 로 만든 4096비트 RSASHA256 키가 그대로
  들어오는 것을 확인했다. 남는 것은 롤오버가 만드는 **교체 키**가 2048 이라는
  점인데, RFC 8624 가 권하는 크기이고 4096 서명은 응답을 키워 단편화를 부른다.
  줄어드는 쪽이 맞다고 보고 둔다.

- **위치**: `crates/bindizr-core/src/dns/dnssec/mod.rs:230`
- **현재**: `state: DnssecKeyState::Active` 로 하드코딩.
  `keys.rs:87-92` 는 존이 서명되지 않은 상태일 것을 요구한다.
- **문제**: BIND에서 롤오버 도중 이관하는 존(active 하나 + published 하나)을
  표현할 수 없다.
- **부가**: `mod.rs:184-188` 이 지원 6종 밖 알고리즘을 거부한다.
  RSASHA1(5, 7)로 서명된 존은 아예 import가 안 되어 insecure 구간을 강요한다.
  RSA 키 길이도 2048로 고정이라 4096 존을 재현할 수 없다.

### ~~48. disable이 키를 아카이브 없이 삭제한다~~ (폐기)

**폐기 (2026-09-13)** — 소유자 판단. 다시 제안하지 않는다.


- **위치**: `crates/bindizr-service/src/dnssec/lifecycle.rs:297-299`
- **현재**: dnssec_records, dnssec_keys, dnssec_withdrawal 을 모두 삭제한다.
- **문제**: 실수로 disable하면 복구 불가다. 존이 신뢰를 처음부터 다시 세워야 한다.
  export 유도나 아카이브가 없다.
- **참고**: 저장 시 at-rest 암호화는 이전에 과하다고 판단해 제외한 사안이므로 여기서 다루지 않는다.
- **없음**: HSM / PKCS#11 경로.
  `signed_view/mod.rs:376-379` 의 `KeyPair::from_bytes` 가
  프로세스 메모리의 원시 바이트를 요구하므로 signer 트레이트 추상화가 먼저 필요하다.

### ~~49. 재서명 jitter가 갱신 창에 비해 너무 작다~~

**완료** — jitter 를 정책에서 유도한다. `(유효기간 - 갱신창) / 2` 이므로 기본 정책에서
6시간이 4.5일이 된다. 재사용 조건이 `expires > refresh_cutoff` 라 만료가 흩어지면
작업도 흩어진다. 전체 재서명 한 번은 델타가 존 크기에 맞먹어 54번의 AXFR 폴백에
걸리는데, 그 지점을 넘지 않게 된다.

- **위치**: `crates/bindizr-service/src/dnssec/mod.rs:41`
  `MAX_EXPIRATION_JITTER_SECS = 21_600` (6시간)
- **현재**: 존을 한 번에 서명하므로 모든 RRSIG 만료가 6시간 띠 안에 몰린다.
  기본 갱신 창은 5일이다.
- **문제**: 갱신 스캔이 존 전체에 대해 동시에 걸린다.
  약 9일마다 존의 모든 RRSIG가 저널 항목을 하나씩 만들고
  존 크기만 한 IXFR을 밀어낸다.
- **부가**: 1시간 inception backdate(`mod.rs:45`)도 고정이며 설정 불가.
- **조치안**: jitter를 갱신 창에 비례시키거나 패스당 처리량 예산을 둔다.

### ~~50. `dnssec status` 가 건강 상태를 말하지 않는다~~

**완료** — `ca37304d` 가 `signatures`/`expired_signatures`/`next_resign_at` 을 붙였고,
만료 게이지 `bindizr_dnssec_rrsigs_expired_total` 을 더했다. denial 모드는 `policy` 로
이미 나간다. 존별 메트릭은 레이블 카디널리티 때문에 의도적으로 두지 않았다 — 존별
질문은 status API 가 답한다. "존이 검증되는지" 는 38번(외부 검증기 필요)으로 남는다.


- **위치**: `crates/bindizr-service/src/dnssec/status.rs:66-117`
- **반환**: 정책, 키(역할/상태/state_changed_at/eligible_at/알고리즘/태그/DNSKEY),
  DS 레코드, earliest_signature_expires_at, 시리얼, withdrawing, parent_ns_addrs,
  그리고 `check-ds` 를 돌린 경우에만 위임 블록
- **없음**: 존 수준 denial 모드, 서명·파생 행 개수, 다음 재서명 예정,
  **이미 만료된 서명이 있는지**, 존이 검증되는지 여부
- **메트릭**: `bindizr_dnssec_rrsigs_expiring_total` 은 있으나 만료 게이지가 없고
  존별 값도 없다.
- **문제**: 운영자가 `status` 만으로 정상 서명 존과 망가진 존을 구분할 수 없다.

---

## P3 — 데이터베이스 · 런타임

### ~~51. 보존 프루닝이 기댈 인덱스가 없다~~

**완료** — `bc616569`. 세 백엔드의 `zone_journal` 과 `zone_versions` 에 `created_at` 인덱스를 추가했다.
10만 행 중 2% 만 컷오프보다 오래된 분포로 `EXPLAIN` 검증: Postgres 는 두 프루닝 모두
전체 스캔에서 인덱스 스캔으로 바뀌어 2,000 행만 읽는다. SQLite 는 `zone_versions` 만 쓰고
`zone_journal` 은 `GROUP BY zone_id` 가 기존 `(zone_id, serial)` 순서를 재사용해 계획이 그대로다.
통계를 넣어도 커버링 인덱스를 만들어도 바뀌지 않았으나, 스키마를 백엔드마다 가르지 않기 위해 유지했다.

- ~~**위치**: `crates/bindizr-db/src/schema.rs`~~
- ~~**확인**: `created_at` 에 걸린 인덱스가 하나도 없다.~~
  ~~`zone_journal` 과 `zone_versions` 에는 `idx_zone_serial (zone_id, serial)` 와~~
  ~~`UNIQUE(zone_id, serial)` 만 있다.~~
- ~~**현재 쿼리**: `SELECT zone_id, MAX(serial) ... WHERE created_at < $1 GROUP BY zone_id`~~
  ~~(`postgres/zone_change_repository_impl.rs:133-143`,~~
  ~~`postgres/zone_version_repository_impl.rs:197-207`)~~
- ~~**문제**: 가장 큰 두 테이블의 풀 스캔이 매시간 하나의 쓰기 트랜잭션 안에서 돈다.~~
  ~~SQLite에서는 그동안 DB 전체가 쓰기 잠금이다.~~
- ~~**조치안**: `(created_at)` 또는 `(zone_id, created_at)` 인덱스를 추가한다.~~
  ~~스키마는 `CREATE INDEX IF NOT EXISTS` 이므로 클린 설치 정책과 충돌하지 않는다.~~

### ~~52. 커넥션 풀에 타임아웃이 없고 복제본마다 곱해진다~~ (정정: 대부분 사실무근)

**정정** — sqlx 0.9 의 `PoolOptions::new()` 가 이미 기본값을 둔다:
`acquire_timeout` 30 초, `idle_timeout` 10 분, `max_lifetime` 30 분(`sqlx-core/src/pool/options.rs:160`).
"타임아웃이 없다" 는 지적은 틀렸다.

**남는 것 둘** — statement timeout 은 실제로 없다. 다만 큰 존의 import 나 DNSSEC 서명, 대량 프루닝이
값을 넘겨 실패할 수 있어 값 선택이 위험하다. 그리고 `pool_max_connections()` 는 `cores * 4` 를
8..64 로 제한한 **프로세스당** 값이라 Helm 기본 replicas 2 에서 Postgres 기본 `max_connections` 100 을
넘길 수 있다. 둘 다 측정 없이 값을 정하기 어려워 보류한다.


- **위치**: `crates/bindizr-db/src/lib.rs:92-97`, `:103`, `:132`, `:164`
- **현재**: `.max_connections(pool_max_connections())` 만 설정.
  `acquire_timeout`, `idle_timeout`, `max_lifetime`, `min_connections` 가 없고
  어느 백엔드에도 statement timeout이 없다.
- **문제**: `pool_max_connections()` 는 `cores * 4` 를 8..64로 제한한 **프로세스당** 값이다.
  Helm 기본이 replicas 2이므로 16코어 노드에서 128 연결이 되고
  Postgres 기본 `max_connections` 100을 넘는다.
  멈춘 쿼리는 연결을 무기한 붙잡는다.
- **정상 확인됨**: SQLite는 `foreign_keys = ON`, `busy_timeout = 15000`,
  WAL 확인까지 제대로 한다 (`lib.rs:168-186`).

### ~~53. 만료 임박 RRSIG 조회가 인덱스를 못 쓴다~~

**완료** — `3e81452c`.

**측정 완료** — 300,000행 / 3,000존 기준. 실제 컨테이너에서 EXPLAIN ANALYZE 로 쟀다.

| 백엔드 | 현재 | MAX 사전필터 | 사전필터 + 힌트 |
| --- | --- | --- | --- |
| MySQL | 130 ms | 110 ms | 26 ms (`STRAIGHT_JOIN`) |
| PostgreSQL | 51.7 ms | 8.8 ms | 불필요 |
| SQLite | 102 ms | 미측정 | 미측정 |

**정정** — todo 가 "매시간" 이라고 적은 것은 틀렸다. `count_expiring_within_refresh` 는
`api/metrics.rs:68` 에서 **메트릭 스크레이프마다** 실행된다. 인증 없는 엔드포인트다.

**정정** — SQLite 도 같은 문제가 있다. `datetime(r.expires_at)` 로 인덱스 컬럼을 감싸
`idx_dnssec_records_expires` 를 못 쓰고 zone 인덱스로 전량을 읽는다 (102 ms).

**적용 결과** — 세 백엔드 모두 결과값 동일(36,250). MySQL 130→18.4 ms,
PostgreSQL 40.5→11.9 ms, SQLite 91→14 ms.
SQLite 는 `datetime()` 래핑을 그대로 두었다. 사전필터가 범위를 잡아 주므로
정확 비교 쪽의 래핑은 인덱스 사용에 영향을 주지 않는다.

**적용한 조치**
1. 인덱스를 `(expires_at, zone_id)` 커버링으로 바꾼다. MySQL 은 이게 있어야 힌트가 효과를 낸다.
2. 두 쿼리에 `MAX(signature_refresh_days)` 상한 사전필터를 넣는다. PostgreSQL 은 이것만으로 충분하다.
3. MySQL 만 `STRAIGHT_JOIN` 으로 구동 순서를 고정한다. 인덱스 이름을 박는 `FORCE INDEX` 보다 낫다.
4. SQLite 는 `datetime()` 래핑 대신 Rust 로 계산한 상한을 바인드하고, 정책별 정확 비교는
   `unixepoch()` 로 수치 비교한다.

**대안(미채택)** — 행에 `refresh_at` 을 저장하면 조인이 사라져 6.24 ms 다. 21배.
다만 정책의 `signature_refresh_days` 수정이 다음 서명까지 반영되지 않아 의미가 바뀐다.


- **위치**: `crates/bindizr-db/src/repository/mysql/dnssec_record_repository_impl.rs:148-156`
- **현재**: `r.expires_at < DATE_ADD(?, INTERVAL p.signature_refresh_days DAY)`
- **문제**: 우변이 조인된 정책 행마다 달라지므로
  `idx_dnssec_records_expires` 로 범위 seek을 못 한다.
  매시간 모든 RRSIG 행 풀 스캔이다.
- **조치안**: 정책별로 쿼리를 나누거나 만료 임계값을 미리 계산해 컬럼에 둔다.

### ~~54. IXFR이 델타 전체를 메모리에 올린다~~

**완료** — `4f4dd7e6`. 싣기 전에 저널 행 수를 세고, 존의 레코드 수 이상이면 AXFR 로 넘어간다.
4,096행 이하 델타는 존을 세지 않는다. `count_between_serials` 를 저장소 계층에 추가했다.

**검증** — 실제 데몬으로 양쪽 확인. 저널 6,005행 / 레코드 6개인 존에 serial 1 로 IXFR 요청하면
폴백 로그가 찍히고 존 전체가 응답으로 나온다. 1행 델타는 정상 IXFR 프레이밍이 나온다.
자동 테스트는 없다. 63번(인바운드 DNS 경로 단위 테스트 부재)에 속한다.

- **위치**: `crates/bindizr/src/dns/server/ixfr.rs:71-76`, `:103-113`, `:247-251`
- **현재**: `list_journal_between_serials` 에 상한이 없고
  `versions_by_serial` 과 `changes_by_serial` 을 전체 결과로 만든다.
- **문제**: 1년 동안 죽어 있던 secondary가 그 구간의 모든 저널 행을 RAM으로 끌어온다.
  RFC 1995 Section 2는 델타가 존보다 커지면 AXFR로 폴백하라고 권한다.
- **조치안**: 행 수 또는 바이트 상한을 두고 초과 시 AXFR로 폴백한다.

### ~~55. IXFR 시리얼 비교가 RFC 1982를 따르지 않는다~~

**완료** — `ea748093`. 조치안대로 트레이드오프를 주석으로 남겼다.

- **위치**: `crates/bindizr/src/dns/server/ixfr.rs:50`, `:63`
- **현재**: `if client_serial > current_serial` 같은 평범한 u32 비교.
  `serial_lt` 나 mod-2^32 산술이 없다.
- **완화 요인**: bindizr 자신의 시리얼은 `i32::MAX` 에서 멈추고 절대 순환하지 않는다
  (`crates/bindizr-service/src/serial.rs:14-32`).
  따라서 `as i32` 캐스트가 음수가 될 수 없다.
- **남는 문제**: 이전 primary에서 큰 시리얼을 물려받은 secondary가
  조용히 AXFR을 받고 그것을 무시하게 된다.
  RFC 1982 요구를 의도적으로 포기했다는 주석도 없다.
- **조치안**: 최소한 그 트레이드오프를 주석으로 남긴다.

### ~~56. 존 캐시가 바이트가 아니라 항목 수로 제한된다~~

**완료** — `cd2e3326` `d0a868b9`. `dns.zone_cache_max_mb`(기본 64)로 바이트를 제한하고
LRU 로 축출한다. 예산 전체보다 큰 존은 캐시하지 않는다. 조회 결과별 카운터,
축출 카운터, 보유 바이트 게이지를 붙였다.

**측정** — A 레코드 하나가 129바이트(구조체 88 + 라벨 + 값). 기본 64 MiB 는
10 레코드 존을 52,022개 담는다. 이전 상한 1,024개보다 크다.
존당 약 500 레코드를 넘어야 이전보다 적게 담긴다. 서명된 존은 RRSIG rdata 때문에
더 비싸므로 그만큼 적게 담긴다.

- **위치**: `crates/bindizr/src/dns/server/zone_cache/mod.rs:29`
  `const MAX_ENTRIES: usize = 1024;`
- **현재**: 각 항목이 존의 전체 레코드와 DNSSEC 평면을 `Arc<Vec<..>>` 로 들고 있다.
  주석은 이것이 "worst-case memory" 를 제한한다고 말한다.
- **문제**: 실제 상한은 1024 × (가장 큰 존)이라 바이트로는 무제한이다.
  캐시 히트/미스 메트릭도 없다.
- **정상 확인됨**: 무효화는 시리얼 키 기반이라 쓰기와 rename 모두 올바르다.

### ~~57. 유지보수 주기가 하드코딩이다~~ (완료)

**완료 (2026-09-14)** — `dns.maintenance_interval_secs`(기본 3600, env
`BINDIZR_MAINTENANCE_INTERVAL_SECS`). `0` 이면 이 인스턴스는 패스를 돌리지 않는다 —
복제본 여럿이면 하나만 켜두면 중복 작업이 사라진다(하나는 반드시 켜야 서명이 안 만료된다).
차트의 `bindizr.dns.maintenanceIntervalSecs` 로도 노출했고, 렌더된 ConfigMap 을
`bindizr config check` 로 통과시켰다.
**감사 항목 정정**: "재서명 리드타임을 조정할 수 없다"는 틀렸다 — 정책의
`signature_refresh_days` 가 그 값이고 이미 조정 가능하다. 리더 선출은 넣지 않았다.

- **위치**: `crates/bindizr-service/src/dnssec/maintenance.rs:19`
  `const MAINTENANCE_INTERVAL_SECS: u64 = 3600;`
- **문제**: 저널 프루닝 주기와 재서명 리드타임을 조정할 수 없다.
  복제본마다 전체 패스를 돌린다. Helm 기본이 2대다.

### ~~58. 설정 리로드가 없다~~ (완료)

**완료 (2026-09-14)** — `bindizr config reload` 와 SIGHUP 이 파일을 다시 읽는다.
저장이 `OnceCell` 에서 `RwLock<Option<Arc<_>>>` 로 바뀌고 `bindizr_config()` 는 스냅샷을
돌려준다. 실행 중 바꿀 수 없는 것(`[api]`, `[database]`, `dns.listen_addr/listen_port`)이
바뀌면 **통째로 거부**한다 — 부분 적용은 없으므로 저장된 설정이 항상 실행 중인 프로세스를
기술한다. 감사가 지적한 "`initialize()` 두 번이면 조용히 옛 설정 유지"도 에러로 바꿨다.
살아 있게 만든 것: 로그 레벨(설치된 로거가 레코드마다 원자 변수를 읽음), 전송 ACL
(`SecondaryAcl` 을 시작 시 캡처해 15개 시그니처로 넘기던 걸 검사 지점에서 읽게 바꿔
파라미터가 사라짐), 유지보수 주기(틱마다 재확인해 재무장, 0이면 패스를 건너뜀).
`once_cell` 의존성이 필요 없어져 워크스페이스에서 제거했다.

- **위치**: `crates/bindizr-core/src/config/mod.rs:250-259`
- **현재**: `OnceCell::get_or_init` 으로 한 번만 읽는다.
  `DaemonCommandKind` 에 Reload 변형이 없고 SIGHUP 핸들러도 없다.
- **문제**: `dns.secondary_addrs` 나 `logging.log_level` 을 바꾸려면 전체 재시작이고,
  3번·4번 때문에 그 재시작이 우아하지 않다.
  `reexec()` 는 진행 중 전송과 요청을 전부 버린다.
- **부가**: `initialize()` 를 두 번 부르면 조용히 옛 설정을 유지한다. 오류가 아니다.

### ~~59. 설정 검증 범위가 좁다~~

**완료** — `c35c5e99`. `listen_port = 0`, api·dns 포트 충돌, `secondary_addrs` 의 파싱 불가 항목을
거부한다. 주소 검증은 기존 `is_address_target` 를 재사용했다. `bindizr config check` 로 확인.
**폐기** — `notify_after_update = true` 인데 `secondary_addrs` 가 빈 경우는 검증하지 않는다.
소유자 판단으로 정상적인 구성이다. **다시 제안하지 않는다.**


- **위치**: `crates/bindizr-core/src/config/mod.rs:413-429`(DB), `:435-444`(DNS)
- **현재 검사**: DB URL 공백 여부, `secondary_addrs` 가 구분자만으로 채워졌는지
- **검사하지 않음**:
  - `secondary_addrs` 개별 항목이 실제로 파싱되는지.
    오타는 조용히 매칭되지 않는 ACL 항목이자 절대 해석되지 않는 NOTIFY 대상이 된다.
  - `notify_after_update = true` 인데 `secondary_addrs` 가 빈 경우.
    이때 ACL도 비므로 **모든 AXFR/IXFR이 거부된다** (`acl.rs` 는 빈 목록에 false).
  - `listen_port = 0` (임의 포트에 바인드된다)
  - api와 dns가 같은 주소·포트를 쓰는 경우. 5번 때문에 조용히 실패한다.

### ~~60. 로거보다 먼저 stdout에 출력한다~~

**완료** — `8b29da05`. 레벨 안내는 로거 설치 직후이므로 `log::info!` 로 보내
설정 레벨을 따르게 했고, 설정 로딩 안내는 로거보다 앞서므로 `eprintln!` 로 바꿨다.

- ~~**위치**: `crates/bindizr-core/src/config/mod.rs:253`,~~
  ~~`crates/bindizr-core/src/logger/mod.rs:101`~~
- ~~**현재**: 두 곳이 `println!` 로 **stdout** 에 쓴다.~~
  ~~다른 모든 로깅은 stderr로 가고 `log_level` 을 따른다.~~
- ~~**문제**: `log_level = "error"` 로 띄워도 구조화되지 않은 stdout 두 줄이 나온다.~~

---

## P3 — CI · 패키징 · 테스트

### ~~61. CI가 clippy도 fmt도 audit도 돌리지 않는다~~ (폐기)

**폐기** — 소유자 판단으로 CI 강화를 하지 않기로 했다. clippy/fmt/audit/MSRV 잡 추가,
빌드 캐시, `--locked`, `push` 트리거 복원을 묶어 제안했으나 필요하지 않다고 결정됐다.
62 번(Docker e2e 잡)도 같은 제안에 포함되어 있었다. **다시 제안하지 않는다.**
아래 관찰 자체가 틀린 것은 아니므로 기록만 남긴다.

- **위치**: `.github/workflows/ci.yml` (28줄)
- **현재**: checkout → `cargo build -p bindizr` → `cargo test --workspace --all-features`
- **없음**: `cargo clippy` 잡 자체가 없다. `-D warnings` 는 물론이고.
  루트 `Cargo.toml` 에 `[workspace.lints]` 가 있고 CLAUDE.md가
  "빌드는 경고 없이 유지" 를 요구하는데 강제 수단이 없다.
  `cargo fmt --check` 도 없다. rustfmt가 nightly를 요구하므로 드리프트가 보이지 않는다.
  `cargo audit` / `cargo deny`, 커버리지, `--locked`,
  선언된 `rust-version = "1.85"` 에 대한 MSRV 잡도 없다.
- **부가**: `push` 트리거가 주석 처리되어 있어 `main` 병합 시 아무것도 돌지 않는다.
- **조치안**: clippy와 fmt 잡을 먼저 추가한다. 현재 clippy는 통과하므로 지금이 적기다.

### ~~62. BIND9 e2e가 CI에서 한 번도 돌지 않는다~~ (폐기)

**폐기 (2026-09-14)** — CI 강화는 도입하지 않는다(61번과 같은 결정).

- **위치**: `crates/bindizr-e2e/tests/dns/`, `crates/bindizr-e2e/README.md:12-19`
- **있음**: `dns/dnssec.rs`, `dns/nsupdate.rs`, `dns/harness.rs`,
  실제 secondary 검증 헬퍼(`common/dns/`), 완전한 compose 스택
  (`docker-compose.yml`, `bind9/named.conf`, `dnsdist/`)
- **문제**: 전부 `BINDIZR_E2E_VERIFY_DNS=true` 뒤에 있다.
  `.github/workflows/` 어디에도 그 변수도 Docker도 없다.
  CI의 `cargo test` 는 항상 로컬 SQLite 분기를 탄다 (`common/mod.rs:69-74`).
- **결론**: **실제 BIND9 secondary로의 AXFR/IXFR/NOTIFY 전파가 자동으로 검증된 적이 없다.**
  카탈로그 존 전파가 제품의 핵심 약속이므로 가장 값비싼 CI 공백이다.
- **조치안**: Docker 있는 러너에서 도는 별도 잡을 추가한다.

### ~~63. 인바운드 DNS 서빙 경로에 단위 테스트가 없다~~ (폐기)

**폐기 (2026-09-14)** — ixfr·wire·zone_cache 는 이미 덮였고 나머지는 도입하지 않는다.

**재검증 (2026-09-12)** — `zone_cache` 는 이제 테스트가 있다(`zone_cache/tests.rs`).
`external_dns/apply.rs` 는 158줄로 줄었고, 떨어져 나간 변환 절반(`change_set.rs`)은
`external_dns/tests.rs` 가 덮는다. 나머지는 그대로다.

확인 결과 `cfg(test)` 가 없는 파일:

| 파일 | 줄 수 |
| --- | --- |
| ~~`crates/bindizr/src/dns/server/ixfr.rs`~~ | 완료 |
| ~~`crates/bindizr/src/dns/wire.rs`~~ | 완료 |
| ~~`crates/bindizr-service/src/dnssec/maintenance.rs`~~ | 완료 |
| ~~`crates/bindizr-service/src/dnssec/rollover.rs`~~ | 완료 |
| ~~`crates/bindizr-service/src/zone/history.rs`~~ | 완료 |
| `crates/bindizr/src/dns/server/axfr.rs` | 100 |
| `crates/bindizr/src/dns/server/zone_cache/mod.rs` | 135 |
| `crates/bindizr/src/dns/server/soa.rs` | 85 |
| `crates/bindizr/src/dns/wire.rs` | 118 |
| `crates/bindizr-service/src/zone/history.rs` | 577 |
| `crates/bindizr-service/src/record/import.rs` | 563 |
| `crates/bindizr-service/src/record/bulk.rs` | 436 |
| `crates/bindizr-service/src/external_dns/apply.rs` | 472 |
| `crates/bindizr-service/src/dnssec/maintenance.rs` | 368 |
| `crates/bindizr-service/src/dnssec/rollover.rs` | 352 |
| `crates/bindizr-service/src/dnssec/lifecycle.rs` | 336 |

**진행 (2026-09-13)** — `maintenance` 는 은퇴 키 제거 판단(`removable_key_ids`, RFC 6840
Section 5.11)을 6건으로 덮으면서 삭제가 판단보다 먼저 일어나던 결함을 고쳤고, 파일도
`mod.rs`/`steps.rs` 로 갈랐다. `rollover` 는 `ds-seen` 승격 판단(`promotable_sep_key_ids`)을
6건으로 덮었다. `wire.rs` 는 TCP 길이 접두 읽기를 5건으로 덮으면서, `u16` 이라 절대 참이
될 수 없던 크기 상한 검사를 지웠다.

**`ixfr.rs` 완료 (2026-09-13)** — 폴백 판단(저널 시리얼 집합 vs 버전 시리얼 집합)을
`delta_gap` 순수 함수로 빼고 6개 케이스를 테스트로 덮었다. 세 개의 인라인 분기가
하나의 질문으로 합쳐져 `handle_ixfr` 도 짧아졌다. 프레이밍과 `NotStarted`/`Partial`
판단은 소켓·DB 에 묶여 있어 그대로 e2e 가 덮는다.

- **가장 위험**: `ixfr.rs` 는 코드베이스에서 가장 미묘한 로직을 담는다.
  저널과 버전의 시리얼 조정(`:118-148`),
  `NotStarted`/`Partial` 폴백 판단(`:170-186`, `:322-328`),
  델타 SOA 프레이밍(`:250-305`).
  이 분기들이 62번이 보여주듯 CI가 돌리지 않는 e2e로만 덮여 있다.
- **다음**: `dnssec/maintenance.rs` 의 은퇴 키 제거 조건(`:327-347`)은
  RFC 6840 Section 5.11의 "한 알고리즘의 키는 함께 떠난다" 규칙을 담는다.
  RRSIG가 남은 채 DNSKEY를 지우면 존이 깨진다. 가장 위험한 로직인데 테스트가 없다.
- **참고**: `acl.rs` 와 `catalog/` 에는 테스트가 있다. 공백이 특정 파일에 몰려 있다.
- **부가**: ZSK 롤오버를 완료시킬 운영자 명령이 없다.
  `ds-seen` 은 ZSK 전용 롤오버를 명시적으로 거부한다 (`rollover.rs:328-333`).
  테스트에서 도달할 수도, 장애 시 강제할 수도 없다.

### ~~64. 컨테이너 이미지를 빌드·게시하는 워크플로가 없다~~ (폐기)

**폐기 (2026-09-14)** — CI 강화는 도입하지 않는다.

- **확인**: `.github/` 전체에 `docker build`, `build-push-action`, `buildx` 가 없다.
- **현재**: `release.yml` 은 `.deb` 와 `.rpm` 만 만든다.
  그런데 `charts/values.yaml` 은 `kweonminsung/bindizr:0.1.0-beta.7` 을 가리키고
  `docs/deployment/*` 의 모든 경로가 그 이미지를 쓴다.
- **문제**: 문서화된 모든 배포 경로가 의존하는 이미지가 수작업 빌드다.
  서명도 SBOM도 provenance도 없다.
- **부가**: `publish-helm-chart.yml` 은 `charts/**` 푸시에 곧바로 패키징해
  Docker Hub로 밀어 넣는다. `helm lint` 나 `helm template` 검증이 없다.

### ~~65. Helm 차트에 프로브와 가용성 설정이 전부 없다~~

**완료** — readiness 는 `/health`(DB 왕복), liveness 는 일부러 DB 를 안 보고 API 소켓만
(`/health` 를 쓰면 DB 장애가 클러스터 전체 재시작 루프가 된다), startup 은 150초 유예.
`terminationGracePeriodSeconds: 30`, PDB `maxUnavailable: 1` (replicas 2 미만이면 렌더
안 함 — 어느 예산이든 드레인을 아예 막는다).

securityContext 에 `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
`capabilities.drop: [ALL]` + **`add: [NET_BIND_SERVICE]`**. 감사가 제안한 `drop: [ALL]`
만으로는 포트 바인드가 아니라 **exec 자체가 거부된다** — 이미지가 바이너리에 setcap 을
걸어둬서 bounding set 이 비면 커널이 실행을 막는다. Docker 로 확인(`operation not
permitted`). 읽기 전용 루트는 `/run/bindizr` emptyDir 하나만 열어주면 된다.

**안 함**: HPA(스케줄러를 도는 프로세스라 무턱대고 붙일 게 아님), NetworkPolicy(CNI 의존).


- **확인**: `charts/` 전체에 다음이 하나도 없다.
  `livenessProbe`, `readinessProbe`, `startupProbe`,
  `PodDisruptionBudget`, `HorizontalPodAutoscaler`, `NetworkPolicy`,
  `terminationGracePeriodSeconds`,
  `allowPrivilegeEscalation`, `readOnlyRootFilesystem`
- **문제**: `/health` 가 존재하고 오케스트레이터 프로브용으로 명시적으로 만들어졌는데
  (`api/health.rs:6-7`) 차트가 쓰지 않는다.
  replicas 2에 readiness 게이트가 없어 롤아웃이
  DB에 아직 닿지 못한 파드로 트래픽을 보낸다.
- **부가**: 컨테이너 `securityContext` 는 runAsUser/runAsGroup/runAsNonRoot 만 설정하고
  `capabilities.drop: [ALL]` 이 빠져 있다.

### ~~66. systemd 유닛에 하드닝이 없고 root로 돈다~~

**완료** — `bindizr` 시스템 사용자 + `CAP_NET_BIND_SERVICE` 만. 상태 파일은
`/var/lib/bindizr`(`StateDirectory`) 로 옮기고 `WorkingDirectory` 를 거기로 두어
설정의 상대 SQLite 경로가 따라오게 했다. 67번이 미뤄둔 `0640 root:bindizr` 도 함께.
`UMask=0077` 은 `systemd-analyze security` 가 잡아준 것 — 없으면 SQLite 파일이
world-readable 로 생긴다. Debian 12 에서 verify 통과, exposure 1.9; postinstall 은
Debian 12 / Rocky 9 에서 멱등 확인.


- **위치**: `packaging/bindizr.service`
- **현재**: `User=` / `Group=` 이 없다. `docs/deployment/manual.md:159` 가
  "The daemon runs as root" 라고 확인해 준다.
- **없음**: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `CapabilityBoundingSet` / `AmbientCapabilities=CAP_NET_BIND_SERVICE`,
  `RestrictAddressFamilies`, `SystemCallFilter`, `LockPersonality`,
  `ProtectKernelTunables`, `StateDirectory`, `ConfigurationDirectory`,
  `TimeoutStopSec`(3번 참고)
- **부가**: `postinstall.sh` 는 `daemon-reload` 와 `enable` 만 한다.
  서비스 사용자를 만들지도, 소유권을 고치지도 않는다.
- **대조**: Dockerfile은 이미 올바르다. uid 10001 비특권 사용자에
  `setcap cap_net_bind_service` 를 쓴다. 패키지 경로만 뒤처져 있다.

### ~~67. DB 자격증명이 든 설정 파일이 world-readable로 설치된다~~

**완료** — `a5c796a0`. 0644 에서 0600 으로. 데몬이 root 로 실행되므로 잃는 것이 없다.
서비스 사용자를 만드는 66번을 처리할 때 `0640 root:bindizr` 로 다시 좁힌다.

- ~~**위치**: `packaging/scripts/build_packages.sh:27`~~
  ~~`install -p -m 644 bindizr.conf.toml "$TMP_DIR/etc/bindizr/bindizr.conf.toml"`~~
- ~~**문제**: 모드 0644이고 템플릿의 `server_url` 은~~
  ~~`mysql://user:password@hostname:port/database` 형태다.~~
  ~~로컬 사용자 누구나 프로덕션 DB URL을 읽는다.~~
- ~~**조치안**: `0640 root:bindizr` 또는 `0600`. 66번의 서비스 사용자 생성과 함께 처리한다.~~

### ~~68. Dockerfile과 renovate 세부사항~~

**완료** — `--locked` 추가(락파일이 최신임도 함께 확인), `HEALTHCHECK` 는
`bindizr status` 로 데몬 소켓에 묻는다. DB 는 일부러 안 본다 — 재시작이 DB 장애를
고치지 못하고 크래시 루프만 만든다. Docker 로 양방향 검증(정상 healthy, 소켓 제거 후
3회 실패 → unhealthy). renovate 는 major 를 automerge 에서 빼고, 대체된 필드
`matchPackagePatterns` / `baseBranches` 를 정리했다. 후자는 감사가 놓친 것으로,
`renovate-config-validator` 의 마이그레이션 diff 가 알려줬다.

**안 함**: 의존성 캐시 레이어. 워크스페이스 크레이트 6개라 수동 매니페스트 복사는
깨지기 쉽고 `cargo-chef` 는 도구 설치가 는다. 얻는 건 수동 빌드 속도뿐이고 CI 가
생기면 레지스트리 캐시가 정석이다.


- **Dockerfile**:
  - `cargo build` 에 `--locked` 가 없어 `Cargo.lock` 을 지키지 않아도 된다.
  - `HEALTHCHECK` 가 없다.
  - 의존성 캐시 레이어가 없어 소스가 한 줄만 바뀌어도 전 크레이트를 다시 빌드한다.
- **renovate.json**:
  - `"automerge": true` 에 `matchPackagePatterns: [".*"]`, `rangeStrategy: bumpMinor`.
    의존성 트리 전체의 minor 범프를 자동 병합하는데
    게이트는 61번의 28줄 CI뿐이다.
  - `matchPackagePatterns` 는 `matchPackageNames` 로 대체 권장된 필드다.

### ~~69. 메트릭 공백 (일부 완료)~~ (폐기)

**남은 공백은 폐기 (2026-09-14)** — SOA 카운터까지로 충분하다는 소유자 판단.

**재검증 (2026-09-13)** — 감사의 "없음" 목록 중 셋은 틀렸다. `xfr_total` 은 UDP 경로도
`refused`/`truncated` 로 센다. 인가 거부는 `http_requests_total{status}`,
`xfr_total{result="refused"}`, `nsupdate_requests_total{result}` 로 이미 보인다.
NOTIFY 큐는 unbounded 채널이라 드롭이 없다 — `enqueue_notify` 의 `false` 는 워커
미기동뿐이고 그때는 인라인 전송으로 넘어간다.

**완료** — SOA 쿼리 카운터 `bindizr_soa_queries_total{result}` 를 더했다. 세컨더리가
refresh 타이머마다 던지는 가장 잦은 질의인데 깜깜했다. 겸사겸사 메트릭을 쓰는 코드를
전부 `bindizr-core/src/metrics.rs` 의 `track_*` 뒤로 모으고, 라벨을 enum 으로 바꿔
오타가 컴파일 에러가 되게 했다.

**추가 완료** — `bindizr_db_connections{state}` + `_max` (sqlx 는 보유분만 세고 대기 큐는
안 주므로 `in_use` 가 `max` 에 닿는 것이 포화 신호), `bindizr_pruned_rows_total{table}`.

**발견한 결함** — 라벨 달린 시계열이 첫 사건 전까지 아예 없었다. "0에 머무르면 이상"
류의 알림이 `no data` 를 읽어 안 뜬다. 라벨을 enum 으로 바꾼 덕에 `ALL` 로 전 조합을
생성 시점에 한 번씩 건드려 35개 시계열이 0으로 존재한다. `bindizr-external-dns` 는
이미 그렇게 하고 있었다.

**남음**: 전송 바이트·소요 시간, 서버 측 ExternalDNS apply 카운터 — 둘 다
`http_requests_total` 과 `xfr_total` 이 부분적으로 덮어 우선순위가 낮다.


**재검증 (2026-09-12)** — 14종이 아니라 18종이다. `zone_cache_lookups_total`,
`zone_cache_evictions_total`, `zone_cache_records` 가 추가되어 "캐시 히트율" 공백은 닫혔다.
나머지 없음 목록은 그대로다.

- **현재 18종** (`crates/bindizr-core/src/metrics.rs`):
  build_info, started_at_seconds, database_up, zones_total, records_total,
  http_requests_total, http_request_duration_seconds, xfr_total,
  notify_sent_total, nsupdate_requests_total, zone_serial_bumps_total,
  dnssec_zones_total, dnssec_keys_total, dnssec_rrsigs_expiring_total,
  dnssec_maintenance_runs_total, zone_cache_lookups_total,
  zone_cache_evictions_total, zone_cache_records
- **잘 되어 있는 점**: 카디널리티 관리가 좋다.
  `MatchedPath` 로 라우트 패턴을 쓰고 라벨 집합이 고정이다.
  nsupdate는 RCODE별로 라벨링된다. 존별 라벨을 뺀 것은 옳은 판단이다.
- **없음**: NOTIFY 큐 깊이와 드롭 수, DB 풀 사용률과 대기,
  프루닝된 행 수, 인가 거부 카운터,
  서버 측 ExternalDNS apply 카운터,
  UDP XFR과 SOA 쿼리 카운터(`xfr_total` 은 TCP 경로에서만 증가한다),
  거부·드롭·파싱 실패 카운터, 전송 바이트와 소요 시간
- **부가**: 존별 라벨이 없으므로 "어느 존이 전송에 실패하는가" 를 메트릭으로 답할 수 없다.
  `bindizr doctor` 가 그 답을 알지만 35번대로 원격에서 접근할 수 없다.

---

## 검증했으나 문제가 아닌 것

기록을 남긴다. 다시 조사하지 않기 위해서.

- **UDP 절단 응답은 구현되어 있다.** `ParsedQuery::truncated_response()` 가
  `server/mod.rs:118` 에서 UDP 전송 질의에 쓰인다. RFC 5936 Section 4.1.1 준수.
  일반 SOA 응답의 512바이트 검사와 EDNS0 OPT 파싱만 없다.
- **응답 코드가 아예 없는 것은 아니다.** 존을 못 찾으면 NOTAUTH를 보낸다
  (`server/mod.rs:97`, `soa.rs:46`). 빠진 것은 REFUSED와 NOTIMP다.
- **`export --signed` 재import 불가는 의도된 설계다.**
  `zone/export.rs:17-21` 주석이 "an inspection artifact, not an import input" 이라 명시한다.
- **시리얼 상한은 근거와 함께 문서화되어 있다.** `serial.rs:1-9`.
  IXFR이 u32로 인코딩하고 음수를 거부하므로 순환이 불가하다는 설명.
  알려진 제약이지 버그가 아니다. 다만 사용자 문서에 적을 가치는 있다.
- **컨테이너는 root로 돌지 않는다.** Dockerfile이 uid 10001과 setcap을 쓴다.
- **LIKE 와일드카드 이스케이프가 올바르다.** `repository/sql.rs:41-53` 이 처리하고
  세 백엔드 모두 명시적 `ESCAPE` 절을 넘긴다.
- **CNAME-and-other-data 규칙이 다섯 쓰기 경로 전부에서 일관된다.**
  create, bulk, import, external_dns/apply, nsupdate 모두
  해당 이름의 행을 정확히 로드한 뒤 검사한다. apex CNAME 금지도 마찬가지다.
- **RRSIG 델타가 저널링되어 진짜 IXFR이 나간다.**
  `dnssec/mod.rs:218-247` 이 `derived: true` 로 기록하고
  `ixfr.rs:347-351` 이 재생한다. e2e로 덮여 있다.
- **`ProbedSnapshot` 패턴이 TOCTOU를 올바르게 닫는다.** `dnssec/snapshot.rs`.
- **소켓 경로 처리가 꼼꼼하다.** 부모 디렉터리 0700, 소켓 0600,
  stale 소켓 제거 전 liveness 프로브, `AddrInUse` 는 폴백하지 않고 중단
  (`socket/server/mod.rs:200-231`).
- **ExternalDNS 웹훅 4개 엔드포인트가 모두 구현되어 있고 미디어 타입 협상이 정확하다.**
- **레코드 교차 존 검색이 동작한다.** `GET /records?search=..` 를
  `zone_name` 없이 부르면 보이는 모든 존을 검색한다.
- **clippy가 경고 없이 통과한다.** `cargo clippy --workspace --all-targets` exit 0.
  `#[allow(dead_code)]` 도 TODO 주석도 워크스페이스에 없다.

---

## 착수 순서 제안

1. **3, 4, 5, 6** — 데몬 수명주기. 변경량 대비 효과가 가장 크다.
   SIGTERM, graceful shutdown, 리스너 실패 전파, 태스크 감시를 한 묶음으로.
2. **1, 2** — 사용자가 직접 부딪히는 두 버그.
3. **61** — clippy와 fmt 잡 추가. 지금 통과 상태이므로 회귀 방지 비용이 0이다.
4. **9, 15** — REFUSED/NOTIMP 응답과 SOA ACL. 작고 프로토콜 정합성이 오른다.
5. **14** — 전송 TSIG. 표준 BIND 구성과의 상호운용성 문제라 크지만 중요하다.
6. **62, 63** — IXFR 단위 테스트와 Docker e2e 잡. 5번 작업 전에 하면 안전망이 된다.
7. **7, 12, 13, 51** — 작은 정합성 수정들. 언제든 끼워 넣을 수 있다.

---

## PR #179 리뷰에서 받지 않기로 한 것

다시 제안하지 않는다.

- **기존 설치 마이그레이션·하위 호환 4건** — SQLite 옛 형식 타임스탬프 백필,
  인덱스 모양 변경 마이그레이션. CLAUDE.md 가 클린 설치만 지원한다고 명시한다.
- **IXFR 델타를 바이트로 계량** — 길이를 합산하려면 읽을지 말지 정하려는 바로 그 행들을
  읽어야 한다. 행 수 비교의 목적은 RFC 1995 Section 2 의 판단이고 행 대 행이면 충분하다.
  이유를 `ixfr.rs` 주석에 남겼다.
- **존 캐시를 바이트로 계량** — 소유자 판단으로 레코드 개수로 통일했다. 레코드 단가를
  실측했고(A 129바이트, 255바이트 TXT 375바이트, DKIM TXT 860바이트, 최악 64 KiB)
  현실 구간 편차 3~7배를 받아들였다. 캐시가 틀렸을 때의 대가는 DB 재조회뿐이다.
- **405 응답에 Allow 헤더가 없다** — 사실이 아니다. 실제 응답에 `allow: GET,HEAD,POST` 가
  붙는다. axum 0.8 의 `method_not_allowed_fallback` 은 본문만 대체한다. 직접 확인했다.
- **리스너 충돌 검사를 주소 계열별로 제한** — 발동하려면 API 와 DNS 가 같은 포트를 써야 하는데
  그럴 이유가 없다. 고치면 `::` 와 `0.0.0.0` 을 섞어 쓴 진짜 충돌을 놓치게 된다.
  오타로 포트를 겹치는 쪽이 계열별로 나누려고 포트를 공유하는 쪽보다 훨씬 흔하다.
