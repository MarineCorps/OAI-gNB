/*
 * qos_weight.c — 의미론과 설계 근거는 qos_weight.h 참조
 */

#include "qos_weight.h"

#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include "common/utils/LOG/log.h"
#include "openairinterface5g_limits.h"   /* MAX_MOBILES_PER_GNB */

/*
 * 엔트리 하나
 *
 * rnti 를 키로 선형 탐색한다 (해시 아님 — 이유는 헤더 참조).
 * expiry_ns: UINT64_MAX = 영구. 이 경우 lookup 이 시간 조회를 건너뛴다.
 */
typedef struct {
    float    weight;
    uint64_t expiry_ns;   /* CLOCK_MONOTONIC 기준, UINT64_MAX = 영구 */
    uint16_t rnti;
    uint8_t  active;
} qos_weight_entry_t;

static qos_weight_entry_t  table[MAX_MOBILES_PER_GNB];
static pthread_rwlock_t    lock = PTHREAD_RWLOCK_INITIALIZER;

static inline uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* 활성 엔트리 중 rnti 가 일치하는 슬롯 인덱스. 없으면 -1.
 * 호출자가 락을 들고 있어야 한다. */
static int find_slot(uint16_t rnti)
{
    for (int i = 0; i < MAX_MOBILES_PER_GNB; i++)
        if (table[i].active && table[i].rnti == rnti)
            return i;
    return -1;
}

static inline void clear_slot(int i)
{
    table[i].active    = 0;
    table[i].weight    = 1.0f;
    table[i].expiry_ns = 0;
    table[i].rnti      = 0;
}

void qos_weight_apply(uint16_t rnti, float weight, uint16_t ttl_ms)
{
    if (weight < QOS_WEIGHT_MIN) weight = QOS_WEIGHT_MIN;
    if (weight > QOS_WEIGHT_MAX) weight = QOS_WEIGHT_MAX;

    /* weight == 1.0f → 정책 해제.
     *
     * float 등가 비교가 안전한 이유: 유일한 생산자가 Q16.16 변환
     * (weight_q16 / 65536.0f) 이고 1.0 은 0x00010000 에서 정확히 1.0f 로
     * 떨어진다. 중간 연산이 없으므로 오차가 끼어들 자리가 없다.
     *
     * 1.0 을 "활성 상태로 저장"하지 않고 비활성화하는 이유는 헤더의
     * 의미론 설명 참조 — OFF 가 진짜 리셋이어야 코드렛을 내린 뒤
     * 가중치가 남지 않는다. */
    if (weight == 1.0f) {
        pthread_rwlock_wrlock(&lock);
        const int i = find_slot(rnti);
        if (i >= 0)
            clear_slot(i);
        pthread_rwlock_unlock(&lock);
        return;
    }

    const uint64_t expiry = (ttl_ms == 0)
        ? UINT64_MAX                                  /* 영구 */
        : mono_ns() + (uint64_t)ttl_ms * 1000000ULL;  /* N ms 후 만료 */

    pthread_rwlock_wrlock(&lock);

    int i = find_slot(rnti);
    if (i < 0) {
        /* 신규 RNTI — 빈 슬롯을 찾는다 */
        for (int k = 0; k < MAX_MOBILES_PER_GNB; k++) {
            if (!table[k].active) { i = k; break; }
        }
    }

    if (i < 0) {
        pthread_rwlock_unlock(&lock);
        /* 슬롯이 MAX_MOBILES_PER_GNB 개이고 gNB 당 UE 상한도 같은 값이라
         * 정상 동작에서는 도달할 수 없다. 도달했다면 qos_weight_retain()
         * 이 호출되지 않아 유령 엔트리가 쌓인 상황이다. */
        LOG_W(GNB_APP, "[QoS] 가중치 테이블이 가득 차 rnti=%04x 적용 실패\n", rnti);
        return;
    }

    table[i].weight    = weight;
    table[i].expiry_ns = expiry;
    table[i].rnti      = rnti;
    table[i].active    = 1;
    pthread_rwlock_unlock(&lock);
}

void qos_weight_retain(const uint16_t *live, int n)
{
    if (!live || n <= 0)
        return;   /* UE 목록을 못 읽은 상황과 구분할 수 없으므로 아무것도 안 한다 */

    pthread_rwlock_wrlock(&lock);
    for (int i = 0; i < MAX_MOBILES_PER_GNB; i++) {
        if (!table[i].active)
            continue;
        int alive = 0;
        for (int k = 0; k < n; k++) {
            if (live[k] == table[i].rnti) { alive = 1; break; }
        }
        if (!alive) {
            LOG_I(GNB_APP, "[QoS] rnti=%04x 접속 종료 → 가중치 엔트리 정리\n",
                  table[i].rnti);
            clear_slot(i);
        }
    }
    pthread_rwlock_unlock(&lock);
}

void qos_weight_clear_all(void)
{
    pthread_rwlock_wrlock(&lock);
    for (int i = 0; i < MAX_MOBILES_PER_GNB; i++)
        clear_slot(i);
    pthread_rwlock_unlock(&lock);
}

float qos_weight_lookup(uint16_t rnti)
{
    float    weight    = 1.0f;
    uint64_t expiry_ns = UINT64_MAX;

    pthread_rwlock_rdlock(&lock);
    for (int i = 0; i < MAX_MOBILES_PER_GNB; i++) {
        if (table[i].active && table[i].rnti == rnti) {
            weight    = table[i].weight;
            expiry_ns = table[i].expiry_ns;
            break;                      /* 일치하면 즉시 종료 */
        }
    }
    pthread_rwlock_unlock(&lock);

    if (weight == 1.0f)
        return 1.0f;                    /* 정책 없음 — 시간 조회 불필요 */

    /* 단축 평가가 중요하다. 이 함수는 매 슬롯 × 매 UE 로 호출되므로
     * (30 kHz SCS = 초당 2000 슬롯) 영구 엔트리에서 clock_gettime() vDSO
     * 호출을 피하는 것만으로 핫패스 비용이 사라진다. 현재 데모 경로는
     * 전부 영구 모드라 사실상 시간 조회가 일어나지 않는다. */
    if (expiry_ns != UINT64_MAX && mono_ns() > expiry_ns)
        return 1.0f;

    return weight;
}
