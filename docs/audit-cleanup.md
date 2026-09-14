# 코드·테스트·설정 재감사

2026-09-14, 작업 시작 시 `feat/xfr-tsig`의 `5cfd039c` 기준.

불필요한 테스트 5개, 도달하지 않는 오류 분기, 중복 변환, 사용하지 않는
의존성과 Helm 권한·설정을 제거했다. 큰 파일에서는 이미 독립적인 역할을 가진
코드와 테스트 묶음을 분리했다. 프로토콜·권한·트랜잭션 검사를 줄일 근거는 없었다.

## 조사 범위와 기준

- 워크스페이스 6개 크레이트, 변경 전 Rust 파일 336개와 테스트 604개의 구조·목록을 조사했다.
  모듈 크기, 함수와 호출부, 테스트가 검증하는 계약, 오류 분기와 기본값 처리,
  공개 범위와 의존성을 확인하고 큰 파일·변경이 집중된 경로를 상세 검토했다.
- `todo.md`의 1–71번과 24b, 폐기 결정, PR #179에서 받지 않은 제안을 읽었다.
  `70c4eff..5cfd039c`의 커밋 92개 중 비병합 커밋 88개의 제목·설명을 대조하고,
  재평가 대상의 diff와 최종 구현을 확인했다.
- Cargo 설정, Helm, Docker/Compose, systemd·패키징, CI·Renovate, 예제,
  Python 벤치마크의 모듈·설정·예외처리도 조사했다.
- `CLAUDE.md`의 인라인 테스트 100줄 기준, `mod.rs` 디렉터리 구조,
  private / `pub(crate)` / `pub` 규칙을 적용했다. 순서가 중요한 트랜잭션은
  유지하고, 독립적인 계약이 없는 함수나 공용 fixture를 새로 만들지 않았다.

이 문서는 현재 코드에 대한 판단이다. 과거 감사 문구나 중간 커밋의 설계를
최종 구현으로 취급하지 않았다. 정적 조사가 모든 실행 환경의 무결함을 증명하지는 않는다.

## 제거한 테스트

테스트 이름을 파일 이동 전후로 대조했다. 아래 5개 외에는 삭제하거나 추가한 테스트가 없다.

| 제거한 테스트 | 이유와 유지한 검증 |
| --- | --- |
| `metrics::tests::encode_includes_build_info_and_startup_gauges` | 두 문자열의 존재만 검사한다. E2E `metrics_reports_zone_totals_and_database_up`가 실제 HTTP 응답에서 같은 두 지표와 수치를 검증한다. |
| SQL `apex_owner_renders_as_a_quoted_sql_literal` | SQL 조각을 리터럴과 비교한다. E2E `apex_filter_finds_apex_records_without_a_zone_filter` 등에서 조각이 포함된 실제 쿼리의 결과를 검증한다. |
| SQL `name_like_types_render_as_a_quoted_sql_list` | 타입 목록의 문자열 복제다. 실제 레코드 목록의 값 정규화·필터 동작과 타입별 변환 테스트를 유지했다. |
| `presentation_rdata_txt_escapes_special_characters` | 이스케이프를 테스트 준비 단계의 `TxtRecordValue`가 이미 수행하고, 검사 대상은 그 문자열을 그대로 반환한다. 고유한 따옴표·역슬래시·제어문자 기대값은 TXT 모듈의 기존 `to_presentation_round_trips_ownership_records` 테스트로 이동했다. |
| `validate_cname_value_accepts_underscore_labels` | 공통 이름 검증의 `accepts_the_labels_an_owner_name_may_carry`와 중복된다. 이스케이프·비호스트 이름·잘못된 이름의 검증은 유지했다. |

SQL grant의 MySQL 문자열 결합 문법, 정렬의 id 동률 처리, RRset 충돌,
권한 검사 순서, DNSSEC 전환, 전송 경계와 잘린 패킷 테스트는 서로 다른 결함을
검출하므로 유지했다. E2E와 단위 테스트가 같은 기능을 다룬다는 이유만으로 제거하지 않았다.

기존 인라인 테스트 모듈 29개는 모두 100줄 미만이었다. 삭제 후 27개이며 최대 85줄이다.
별도 테스트 파일에 인라인 모듈의 100줄 제한을 적용하지 않았다.

## 파일 분리

줄 수는 포맷 적용 후 기준이다. 크기만을 줄이기 위한 빈 중간 계층은 추가하지 않았다.

| 기존 파일 | 변경 |
| --- | --- |
| `bindizr-core/src/config/mod.rs` 713줄 | 577줄. 환경변수 적용과 파싱은 `config/environment.rs` 141줄로 이동. |
| `bindizr-core/src/dns/message/mod.rs` 438줄 | 273줄. SOA·카탈로그·저장 레코드의 answer 구성은 `message/records.rs` 174줄로 이동. |
| `bindizr-core/src/dns/dnssec/signed_view/mod.rs` 583줄 | 402줄. 정규화된 서명 입력과 denial chain 생성은 `signed_view/input.rs` 194줄로 이동. 서명 재사용·차이 계산은 원래 모듈에 유지. |
| `bindizr-service/src/record/import/mod.rs` 630줄 | 451줄. 입력과 기존 레코드의 조정 계획·미리보기는 `import/plan/mod.rs` 182줄로 이동. 단위 테스트도 `plan/tests.rs`로 이동. |
| `bindizr-service/src/zone/history/mod.rs` 598줄 | 432줄. 저널 역적용과 과거 상태 조회는 `history/reconstruction/mod.rs` 189줄로 이동. 단위 테스트도 함께 이동. rollback의 잠금·검증·쓰기 순서는 유지. |
| `bindizr-core/.../signed_view/tests.rs` 1,112줄 | `tests/{keys,reuse,rollover,signing}.rs`로 구분. 작은 Zone/Record fixture는 각 테스트 파일에 둔다. 키 파일 import 테스트 3개는 `key_file/tests.rs`로 이동. |
| `bindizr-e2e/tests/api/zone.rs` 1,940줄 | `zone/{crud,history,import,import_validation,listing,roundtrip,serving,validation}.rs`로 구분. 가장 큰 파일은 419줄. |
| `bindizr-e2e/tests/api/record.rs` 1,450줄 | `record/{bulk,crud,delete,listing,validation}.rs`로 구분. 가장 큰 파일은 562줄. |
| `bindizr-e2e/tests/common/mod.rs` 861줄 | 458줄. 로컬 기동, Compose 기동, ExternalDNS 프로세스 관리를 `local.rs`, `compose.rs`, `external_dns.rs`로 구분. |

유지한 큰 파일의 판단은 다음과 같다.

- `bindizr-service/src/repository.rs`와 `bindizr-db/src/repository/mod.rs`는
  DB 오류 변환과 저장소 인터페이스를 모은 파일이다. 순수 알고리즘 여러 개가
  섞인 파일과 성격이 다르다. 이번에 인터페이스나 동적 디스패치 체계를 교체할 근거는 없다.
- `schema.rs`와 MySQL/PostgreSQL/SQLite 구현은 의도적인 백엔드별 SQL이다.
  공용 매크로나 쿼리 생성 계층으로 합치지 않았다.
- `metrics.rs`, CLI 표 출력, 오류 코드와 API 타입의 열거는 실제 지표·명령·타입에
  대응한다. 파일 길이만으로 다시 분산하면 정의와 매핑을 따라가기 어려워진다.
- 남은 DNSSEC·grant E2E는 같은 상태 전환 또는 권한 계약을 끝까지 확인하는
  시나리오다. 테스트 하나의 준비·행동·검증을 여러 파일로 잘게 나누지 않았다.
- 벤치마크 `report.py`는 392줄이며 집계와 보고서 출력을 담당한다.
  `_aggregate`, `_rows`, 형식별 렌더링은 실제 호출부와 계약이 있어 유지했다.

## 단순화한 로직과 설정

| 위치 | 조치와 근거 |
| --- | --- |
| `record/import/mod.rs` | 순수 이름 정규화와 레코드 제약 검증의 오류를 HTTP 상태로 다시 구분하던 두 분기를 제거했다. 두 함수는 입력 오류만 만들며 DB·I/O 호출이 없다. 실제 DB 오류의 전파는 유지했다. |
| `model/record/mod.rs` | CNAME/DNAME/NS/PTR 비교값 생성에서 parse 성공과 실패가 모두 같은 `to_fqdn_lowercase`로 끝나던 경로를 합쳤다. 쓰기 입력의 유효성 검증은 별도로 남아 있다. |
| 같은 파일 | MX/SRV 표시 함수가 단 하나의 허용 필드 수를 배열로 받던 구조를 정수 1/3으로 줄였다. |
| `config/mod.rs` | 한 호출부에서 설정 파일을 읽어 전달하기만 하던 `load_raw_config`를 `load_config_file`에 합쳤다. 환경변수 적용 후 검증 순서는 같다. |
| `bindizr-external-dns/src/metrics.rs` | 바이트 버퍼 생성 → 인코딩 오류 분기 → UTF-8 변환을 기존 라이브러리의 `encode_to_string`으로 줄였다. 인코딩 실패 시 빈 문자열을 반환하는 기존 동작은 같다. |
| E2E `TestApp` | 생성된 객체에 항상 존재하는 `runtime`의 `Option`을 제거했다. 로컬 자식 프로세스는 Drop에서 종료·회수하고 임시 디렉터리는 필드의 Drop으로 정리한다. |
| socket 서버 테스트 | Unix socket bind의 `PermissionDenied`에서 성공처럼 조용히 종료하던 헬퍼를 제거했다. 실행할 수 없는 테스트는 실패를 드러낸다. |
| `bindizr-service/Cargo.toml` | 사용하지 않는 직접 의존성 `async-trait`를 제거하고 lockfile을 갱신했다. DB 저장소에서 사용하는 워크스페이스 의존성은 유지했다. |
| Helm `rbac.yaml`, `values.yaml` | Bindizr/BIND9에 Kubernetes API 호출부가 없으므로 pods/configmaps/services의 get/list/watch Role과 RoleBinding, `rbac.create`를 제거했다. ServiceAccount 이름·annotation 지원은 유지했다. |
| Helm Deployment | ConfigMap에 같은 값이 이미 기록되는 일반 설정 환경변수 11개를 제거했다. Secret의 DB URL만 `BINDIZR_DATABASE_URL`로 주입한다. |
| `CLAUDE.md` | 기본 E2E에 Docker가 필요하다는 오래된 설명을 실제 SQLite 기본 실행 방식에 맞췄다. 공용 E2E 헬퍼의 `pub(super)` 안내도 전역 가시성 규칙과 일치시켰다. |

## `todo.md`와 커밋의 재평가

과거에 불필요한 복잡도나 회귀가 있었던 사례는 최종 상태와 구분했다.

| 항목·커밋 | 판단 |
| --- | --- |
| #56, `00b87713` → `9c685777` | 바이트별 메모리 추정은 복잡도에 비해 정확한 메모리 상한도 아니었다. 후속 커밋에서 레코드 수 예산으로 이미 단순화했다. 현재 설정은 `zone_cache_max_records`이며 `zone_cache_max_mb`를 복원할 이유가 없다. |
| #54, `ddc637d4` → `4b4b8508` | 4,096행 이하 비교 생략은 작은 존에서 더 큰 IXFR을 선택하게 했다. 현재는 모든 델타를 전송 대상 존의 행 수와 비교한다. 임계값 분기는 이미 없어졌다. |
| #39–41, `1fc04406` | 별도 hold-down 설정 대신 실제 DNSKEY·서명 대상·부모 DS TTL을 사용한다. 과거 논의의 수동 `parent_ds_ttl`이나 hold-down 설정을 현재 필수 설정으로 간주하면 안 된다. |
| #22, `3932e5e4` → `7ab00d0e` | HTTP 페이지 기본값이 CLI에도 번진 것은 불필요한 동작 변경이었다. CLI 제한은 후속 커밋에서 수정했다. HTTP 상한은 여전히 유효하다. |
| #7, `7ea8ad69` → `df53a439` | 앱 시계 통일은 필요했지만 SQLite 날짜 문자열 비교에 회귀를 만들었다. 후속 커밋이 SQLx 저장 표현에 맞춰 수정했다. DB 시계와 앱 시계를 다시 섞지 않는다. |
| #42, `0b0cf56f` | denial 모드 변경을 일괄 거부하던 제약은 현재의 서명 뷰 차이 계산으로 전환을 지원하도록 제거됐다. NSEC3 파라미터 설정을 더 추가할 근거는 없다. |
| #63, `047bdbb6`, `d3f078b2`, `783a4037`, `a32d3707`, `8ab2e956` | import 계획, 저널 역적용, wire framing, IXFR 누락 판정, 은퇴 키 제거는 독립적인 계약이다. 추출 자체가 불필요한 리팩터링은 아니다. 키 삭제 전에 전체 판단을 완료하도록 고친 것은 실제 결함 수정이다. |
| #69, `95989245`, `89449008` | 지표 쓰기를 소유 모듈에 두고 라벨을 enum으로 제한한 것은 메트릭 이름·카디널리티의 계약이다. 문자열 직접 쓰기로 되돌리지 않았다. |
| #14, `c80d9507` | 기존 TSIG 키를 존 전송에도 적용한다. 별도 키 저장소나 새 ACL 프레임워크가 아니며 요청 검증과 응답 MAC 연쇄는 서로 다른 요구다. 주소 ACL과 unsigned 전송 경로도 여전히 필요하다. |
| #29, `ecccd740`, `67563d92` | SQL의 scope 필터와 서비스의 이름 label 검사는 단순 중복이 아니다. SQL은 escaped dot 이름에서 넓게 걸러질 수 있어 서비스가 최종 권한을 판단해야 한다. 이 경우 count가 실제 반환 가능 수보다 클 수 있다는 기존 제한도 남는다. |
| #30, `6a05978b` | 작은 관리 목록의 메모리 pagination은 행이 적다는 계약에 따른 선택이다. 이를 전부 별도 count 쿼리와 공용 저장소 프레임워크로 바꾸지 않았다. 정렬 enum과 id tie-break는 유지했다. |
| #20, #58, `046d65fa`, `e2a1dcdf` | TLS 인증서/키 쌍 검사와 재시작이 필요한 설정의 reload 거부는 실제 실행 상태와 설정이 어긋나지 않게 한다. 예외처리 제거 대상이 아니다. |

나머지 항목도 다음과 같이 분류했다. 같은 번호의 세부 완료·폐기 결정은 기존 기록을 따른다.

| TODO 항목 | 재감사 결론 |
| --- | --- |
| #2–6, #8–9, #15–17, #19 | 저장 우선순위, 기동 실패 전파, 종료 신호, 유지보수 감독, opcode/QR/REFUSED, ACL·동시성 제한은 실제 오동작을 막는다. 제거하지 않는다. |
| #10–13, #24·24b·25, #36–37, #44–46, #59–60, #70 | 지원하는 입력의 정합성, 오류 표현, CLI 종료 코드, 명시적 부모 주소, 설정 검증과 SQLite 생성은 사용자에게 관찰되는 계약이다. 지원 범위를 새로 늘리지 않는다. |
| #26–28, #31, #33–35, #47, #49–50, #57 | 완료된 일괄 삭제·변경 주체·존 활성화·기본값·DomainFilter·키 인계·상태·유지보수 설정을 유지한다. 폐기한 나머지 기능은 재도입하지 않는다. |
| #51–53 | 실제 사용 중인 보존/서명 조회 인덱스는 유지한다. 풀의 acquire timeout이 없다는 초기 지적은 이미 정정됐다. 백엔드별 쿼리 최적화는 일반화하지 않는다. |
| #55 | 현재 시리얼의 저장 범위와 증가 규약을 두고 RFC 1982 wrap-around 계층만 덧붙이지 않는다. |
| #65–68 | readiness, PDB, 실행 권한 축소, 이미지 healthcheck와 lockfile 사용은 배포 동작에 대응한다. 이번에 제거한 것은 호출부 없는 RBAC와 같은 값의 이중 주입이다. |
| #1, #18, #21, #23, #32, #38, #43, #48, #61–64, #69의 잔여 제안, #71 | 기존 폐기·수용 결정을 유지한다. CORS/rate limit, TSIG replay 저장소, DNSSEC 자체 검증·키 아카이브, 신규 CI, 전송 파서 교체를 추가하지 않는다. |

`todo.md` 상단 진행 표와 각 항목 아래의 초기 관찰에는 예전 브랜치·줄 번호·해시가
남아 있다. 특히 #41, #54, #56은 위의 최종 상태를 기준으로 읽어야 한다.
기존 기록을 덮어쓰지 않고 최신 재감사 링크를 상단에 추가했다.

## 유지한 예외처리와 설계

- DNS 외부 조회 후 상태가 달라졌는지 확인하는 `ProbedSnapshot`은 조회 동안의
  상태 변경을 검출한다. 오래 열린 DB 트랜잭션으로 대체하지 않았다.
- 부모 DNS가 응답하지 않는 상황, 지원하지 않는 DS digest, DS 부재는 서로 다른
  운영 상태다. 모두 하나의 실패나 성공으로 합치지 않았다.
- DB unique 충돌을 서비스 오류로 변환하는 처리는 사전 확인 이후의 경쟁을 처리한다.
  rollback 실패 로그는 원래 오류를 보존한다. 둘 다 불필요한 catch가 아니다.
- ACL hostname 조회의 캐시·timeout·동시 요청 합치기는 실제 resolver 부하와 지연을
  줄인다. 리터럴 주소 검사와 mapped IPv4 정규화도 필요하다.
- E2E의 임시 포트 재시도는 예약 소켓을 놓은 뒤 TCP/UDP listener가 기동하는 사이의
  경쟁을 다룬다. `serial_test`는 실행자가 테스트 스레드 수를 명시적으로 늘려도
  공유 자원을 사용하는 시나리오를 직렬화하므로 유지했다.
- DNSSEC rollover E2E의 61초 대기는 실제 프로세스가 TTL 60초를 기다리는지 검증한다.
  대기를 없애거나 프로덕션 시계를 테스트 전용으로 바꾸지 않았다.
- 벤치마크의 제한된 기동 재시도와 요청 실패 계수는 측정 중 실패를 기록하는 장치다.
  선택적인 그래프·환경정보 수집도 핵심 결과 생성과 별도로 실패할 수 있다.

## 검증

| 검증 | 결과 |
| --- | --- |
| 변경 전 `cargo test --workspace --lib --all-features` | 통과. 기존 상태의 라이브러리 테스트 기준 확보. |
| `cargo check --workspace --all-targets --all-features` | 통과. |
| `cargo test --workspace --all-features -- --test-threads=1` | 599개 통과, 실패·ignore 0개. `bindizr` 33, core 209, DB 6, E2E 173, ExternalDNS 22, service 156. |
| 최종 서명 입력/fixture 분리와 TXT 검증 이동 후 `cargo test -p bindizr-core --lib --all-features` | 209개 재검증 통과. |
| 최종 `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 경고 없이 통과. |
| `cargo +nightly fmt --all --check`, `git diff --check` | 통과. |
| 테스트 이름·인라인 모듈 조사 | 604 → 599, 지정한 5개만 제거. 남은 인라인 모듈 최대 85줄. |
| `helm lint charts --set postgresql.enabled=true` | 통과. 기존 icon 권장 메시지만 출력. |
| Helm 렌더링 | PostgreSQL, MySQL, TLS existing Secret, 단일 복제본 구성을 확인. 생성 TOML 4개 모두 실제 `bindizr config check` 통과. |
| Helm 전후 비교 | ConfigMap은 동일. Role/RoleBinding 및 중복 env 11개를 제외한 렌더링 결과는 동일. TLS의 HTTPS probe와 단일 복제본의 PDB 제외도 유지. |

기본 E2E는 로컬 SQLite와 실제 daemon/adapter 프로세스로 실행했다.
Docker Compose의 BIND9 secondary 연동, 실제 MySQL/PostgreSQL 서버,
Kubernetes 배포와 벤치마크 부하 실행은 이번 검증에 포함하지 않았다.
테스트 종료 후 로컬 테스트 daemon이 남아 있지 않은 것도 확인했다.
