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
 * 저장 구조 — 해시가 아니라 선형 탐색이다
 * ──────────────────────────────────────────────────────────────
 *
 *   슬롯이 MAX_MOBILES_PER_GNB(= 16)개뿐이므로 rnti 로 선형 탐색한다.
 *
 *   처음에는 rnti % 16 해시 인덱싱이었는데, 서로 다른 두 UE 의 RNTI 가
 *   16 의 배수만큼 차이나면 같은 슬롯에 떨어지고 나중에 apply 한 쪽이
 *   먼저 온 쪽을 덮어썼다. 덮인 UE 는 lookup 에서 rnti 불일치로 1.0 을
 *   받아 *조용히* 부스트를 잃었다. UE 2대만 붙여도 확률이 1/16 이라
 *   무시할 수 없다. 선형 탐색은 이 충돌 자체를 없앤다.
 *
 *   비용: lookup 이 최대 16회 비교. 매 슬롯 × 매 UE 로 불리지만
 *   (30 kHz SCS = 초당 2000 슬롯) 16 UE 최악의 경우에도 초당 51만 회
 *   정수 비교이고, 일치 시 조기 종료한다. 정확성을 해시로 바꿀 가치가 없다.
 *
 * ──────────────────────────────────────────────────────────────
 * 스레드 안전성
 * ──────────────────────────────────────────────────────────────
 *
 *   Writer 1개 (JBPF IO 스레드), Reader 다수 (스케줄러 스레드들).
 *   내부 pthread_rwlock 으로 보호된다. 읽기는 rdlock 이라 경합하지 않는다.
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
 *   ttl_ms : 0    = 영구 (해제 또는 gNB 재시작까지 유지)
 *            1..N = N ms 후 자동 만료 (heartbeat 모드)
 *
 * 테이블이 꽉 차 있고 신규 RNTI 면 적용하지 못하고 경고를 남긴다
 * (16 UE 를 모두 쓰면서 17번째가 올 수는 없으므로 실제로는 발생하지 않는다).
 */
void qos_weight_apply(uint16_t rnti, float weight, uint16_t ttl_ms);

/* 주어진 RNTI 의 활성 가중치를 조회한다.
 *   정책이 없거나 만료됐으면 1.0f.
 *   어느 스레드에서든 호출 가능하고, 0 이나 음수를 반환하지 않는다.
 */
float qos_weight_lookup(uint16_t rnti);

/* live[] 에 없는 RNTI 의 엔트리를 모두 해제한다.
 *
 * 왜 필요한가:
 *   정책은 기본적으로 영구(ttl_ms = 0)이고, UE 가 접속을 끊어도 엔트리가
 *   남는다. OAI 는 RNTI 를 재사용하므로, 나중에 들어온 다른 UE 가 같은
 *   RNTI 를 받으면 자기가 요청하지도 않은 정책을 그대로 상속한다.
 *
 *   호출자(nr-softmodem 의 JBPF 콜백)는 이미 스케줄러 락 안에서
 *   connected_ue_list 를 순회하므로, 그때 수집한 생존 RNTI 목록을 넘기면
 *   추가 비용 없이 유령 엔트리를 정리할 수 있다.
 *
 *   n == 0 이면 아무것도 하지 않는다 (UE 목록을 못 읽은 상황과
 *   "UE 가 정말 0대"인 상황을 구분할 수 없어, 안전한 쪽을 택한다).
 */
void qos_weight_retain(const uint16_t *live, int n);

/* 모든 가중치를 해제한다 (전체 1.0f 복귀).
 *   활성 정책이 없으면 안전한 no-op.
 *   QOS_WEIGHT_TTL_CLEAR_ALL 수신 시 또는 디버그용.
 */
void qos_weight_clear_all(void);

#endif /* QOS_WEIGHT_H */
