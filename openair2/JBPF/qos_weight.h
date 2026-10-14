/*
 * qos_weight.h — Per-UE scheduling weight table for QoS-aware scheduling
 *
 * 역할:
 *   JBPF 코드렛이 결정한 per-UE 스케줄링 가중치를 MAC 스케줄러에 전달하는
 *   호스트 측 저장소. 코드렛(PDCP 스레드)과 스케줄러(MAC 스레드) 사이의
 *   유일한 공유 상태다.
 *
 *   Writer : nr-softmodem 의 JBPF ringbuf consumer (jbpf_io_output_handler)
 *   Reader : MAC 스케줄러 — pf_ul() / pf_dl() 의 PF coef 계산 지점
 *
 * JBPF 와의 독립성:
 *   이 파일은 JBPF_HOOK 매크로와 무관하게 항상 컴파일된다.
 *   JBPF 가 꺼져 있거나 코드렛이 로드되지 않았으면 lookup 이 1.0f 를
 *   돌려주므로, 스케줄러 쪽 코드가 #ifdef 로 갈라지지 않는다.
 *
 * ──────────────────────────────────────────────────────────────
 * 의미론
 * ──────────────────────────────────────────────────────────────
 *
 *   lookup(rnti) 는 [QOS_WEIGHT_MIN, QOS_WEIGHT_MAX] 범위의 곱셈 계수를
 *   반환한다. 정책이 없거나 만료됐으면 1.0f (= PF 기본값).
 *
 *   weight == 1.0f 로 apply 하면 "정책 해제"로 해석되어 엔트리가
 *   비활성화된다. 즉 1.0 은 "1.0 을 적용한 상태"가 아니라 "정책 없음"이다.
 *   두 상태는 lookup 결과가 동일하므로 구분할 이유가 없고, 이렇게 두면
 *   OFF 가 진짜 리셋이 된다 (코드렛 unload 후 가중치 잔존 문제 회피).
 *
 * ──────────────────────────────────────────────────────────────
 * 스레드 안전성
 * ──────────────────────────────────────────────────────────────
 *
 *   Writer 1개 (JBPF IO 스레드), Reader 다수 (스케줄러 스레드들).
 *   내부 pthread_rwlock 으로 보호된다. 읽기는 슬롯 레이트(30kHz SCS 에서
 *   초당 2000회 × UE 수)로 들어오지만 rdlock 이라 경합하지 않는다.
 */

#ifndef QOS_WEIGHT_H
#define QOS_WEIGHT_H

#include <stdint.h>

/* 가중치 허용 범위. 코드렛이 보낸 값은 이 범위로 clamp 된다.
 * 상한을 두는 이유: 검증기가 코드렛의 *값*은 검사하지 않으므로,
 * 버그 있는 코드렛이 스케줄러를 완전히 장악하는 것을 호스트에서 막는다. */
#define QOS_WEIGHT_MIN  0.25f
#define QOS_WEIGHT_MAX  8.0f

/* 주어진 RNTI 의 가중치를 적용(또는 갱신)한다.
 *
 *   rnti   : MAC RNTI. 호출자가 CU-UE-ID 를 미리 변환해서 넘겨야 한다.
 *   weight : 곱셈 계수. [QOS_WEIGHT_MIN, QOS_WEIGHT_MAX] 로 clamp.
 *            정확히 1.0f 이면 정책 해제(엔트리 비활성화).
 *   ttl_ms : 0    = 영구 (clear_all 또는 gNB 재시작까지 유지)
 *            1..N = N ms 후 자동 만료 (heartbeat 모드)
 */
void qos_weight_apply(uint16_t rnti, float weight, uint16_t ttl_ms);

/* 주어진 RNTI 의 활성 가중치를 조회한다.
 *   정책이 없거나 만료됐거나 해시 슬롯이 다른 UE 것이면 1.0f.
 *   어느 스레드에서든 호출 가능하고, 0 이나 음수를 반환하지 않는다.
 */
float qos_weight_lookup(uint16_t rnti);

/* 모든 가중치를 해제한다 (전체 1.0f 복귀).
 *   활성 정책이 없으면 안전한 no-op.
 *   QOS_WEIGHT_TTL_CLEAR_ALL 수신 시 또는 디버그용.
 */
void qos_weight_clear_all(void);

#endif /* QOS_WEIGHT_H */
