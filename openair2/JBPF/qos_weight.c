/*
 * qos_weight.c — 의미론과 사용법은 qos_weight.h 참조
 */

#include "qos_weight.h"

#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include "openairinterface5g_limits.h"   /* MAX_MOBILES_PER_GNB */

/*
 * 엔트리 하나
 *
 * rnti 를 함께 저장하는 이유:
 *   인덱스가 rnti % MAX_MOBILES_PER_GNB (= % 16) 해시이므로 서로 다른 두
 *   UE 가 같은 슬롯에 떨어질 수 있다. rnti 를 들고 있지 않으면 A 의 정책이
 *   B 에 조용히 적용된다. lookup 에서 이 값을 비교해 충돌을 오적용 대신
 *   안전한 기본값(1.0f)으로 떨어뜨린다.
 *
 * expiry_ns:
 *   UINT64_MAX = 영구. 이 경우 lookup 이 시간 조회를 아예 건너뛴다.
 */
typedef struct {
    float    weight;
    uint64_t expiry_ns;   /* CLOCK_MONOTONIC 기준, UINT64_MAX = 영구 */
    uint16_t rnti;        /* 이 슬롯을 점유한 UE */
    uint8_t  active;
} qos_weight_entry_t;

static qos_weight_entry_t  table[MAX_MOBILES_PER_GNB];
static pthread_rwlock_t    lock = PTHREAD_RWLOCK_INITIALIZER;

static inline int rnti_to_idx(uint16_t rnti)
{
    return rnti % MAX_MOBILES_PER_GNB;
}

static inline uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void qos_weight_apply(uint16_t rnti, float weight, uint16_t ttl_ms)
{
    if (weight < QOS_WEIGHT_MIN) weight = QOS_WEIGHT_MIN;
    if (weight > QOS_WEIGHT_MAX) weight = QOS_WEIGHT_MAX;

    const int idx = rnti_to_idx(rnti);

    /* weight == 1.0f → 정책 해제.
     *
     * float 등가 비교를 쓰는 게 안전한 이유: 유일한 생산자가 Q16.16 변환
     * (weight_q16 / 65536.0f) 이고, 1.0 은 0x00010000 에서 정확히 1.0f 로
     * 떨어진다. 중간 연산이 없으므로 오차가 끼어들 자리가 없다.
     *
     * 1.0 을 "활성 상태로 저장"하지 않고 비활성화하는 이유는 qos_weight.h
     * 의 의미론 설명 참조 — OFF 가 진짜 리셋이 되어야 코드렛을 내린 뒤
     * 가중치가 남지 않는다. */
    if (weight == 1.0f) {
        pthread_rwlock_wrlock(&lock);
        if (table[idx].rnti == rnti || !table[idx].active) {
            table[idx].active    = 0;
            table[idx].weight    = 1.0f;
            table[idx].expiry_ns = 0;
            table[idx].rnti      = 0;
        }
        pthread_rwlock_unlock(&lock);
        return;
    }

    const uint64_t expiry = (ttl_ms == 0)
        ? UINT64_MAX                                  /* 영구 */
        : mono_ns() + (uint64_t)ttl_ms * 1000000ULL;  /* N ms 후 만료 */

    pthread_rwlock_wrlock(&lock);
    table[idx].weight    = weight;
    table[idx].expiry_ns = expiry;
    table[idx].rnti      = rnti;
    table[idx].active    = 1;
    pthread_rwlock_unlock(&lock);
}

void qos_weight_clear_all(void)
{
    pthread_rwlock_wrlock(&lock);
    for (int i = 0; i < MAX_MOBILES_PER_GNB; i++) {
        table[i].active    = 0;
        table[i].weight    = 1.0f;
        table[i].expiry_ns = 0;
        table[i].rnti      = 0;
    }
    pthread_rwlock_unlock(&lock);
}

float qos_weight_lookup(uint16_t rnti)
{
    const int idx = rnti_to_idx(rnti);

    pthread_rwlock_rdlock(&lock);
    const qos_weight_entry_t e = table[idx];   /* 구조체 복사 — 락 구간 최소화 */
    pthread_rwlock_unlock(&lock);

    if (!e.active)      return 1.0f;
    if (e.rnti != rnti) return 1.0f;   /* 해시 충돌 — 다른 UE 의 엔트리 */

    /* 단축 평가가 중요하다. 이 함수는 매 슬롯 × 매 UE 로 호출되므로
     * (30kHz SCS = 초당 2000 슬롯) 영구 엔트리에서 clock_gettime() vDSO
     * 호출을 피하는 것만으로 핫패스 비용이 사라진다. 현재 데모 경로는
     * 전부 영구 모드라 사실상 시간 조회가 일어나지 않는다. */
    if (e.expiry_ns != UINT64_MAX && mono_ns() > e.expiry_ns)
        return 1.0f;

    return e.weight;
}
