/* qos_weight 멀티-UE 로직 단위 테스트 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "qos_weight.h"

static int pass = 0, fail = 0;
#define CHECK(cond, fmt, ...) do { \
    if (cond) { pass++; printf("  ✓ " fmt "\n", ##__VA_ARGS__); } \
    else      { fail++; printf("  ✗ " fmt "   ← 실패\n", ##__VA_ARGS__); } } while (0)

int main(void)
{
    /* ── T1: B2 해시 충돌 — RNTI 가 16 배수만큼 차이나는 두 UE ── */
    printf("[T1] 해시 충돌 (0x59a2 / 0x59b2 — 둘 다 %%16 == 2)\n");
    qos_weight_clear_all();
    qos_weight_apply(0x59a2, 8.0f, 0);
    qos_weight_apply(0x59b2, 2.0f, 0);
    CHECK(qos_weight_lookup(0x59a2) == 8.0f, "UE-A 가 8.0 유지 (실제 %.2f)", qos_weight_lookup(0x59a2));
    CHECK(qos_weight_lookup(0x59b2) == 2.0f, "UE-B 가 2.0 유지 (실제 %.2f)", qos_weight_lookup(0x59b2));

    /* ── T2: OFF 가 남의 엔트리를 지우지 않는다 ── */
    printf("[T2] 충돌 슬롯에서 OFF 격리\n");
    qos_weight_apply(0x59b2, 1.0f, 0);          /* B 만 OFF */
    CHECK(qos_weight_lookup(0x59a2) == 8.0f, "A 는 그대로 8.0 (실제 %.2f)", qos_weight_lookup(0x59a2));
    CHECK(qos_weight_lookup(0x59b2) == 1.0f, "B 는 해제됨 (실제 %.2f)",     qos_weight_lookup(0x59b2));

    /* ── T3: B3 유령 엔트리 정리 + RNTI 재사용 ── */
    printf("[T3] 접속 종료 UE 정리 → RNTI 재사용 시 상속 없음\n");
    qos_weight_clear_all();
    qos_weight_apply(0x1111, 8.0f, 0);
    qos_weight_apply(0x2222, 4.0f, 0);
    uint16_t live[] = { 0x2222 };               /* 0x1111 접속 종료 */
    qos_weight_retain(live, 1);
    CHECK(qos_weight_lookup(0x1111) == 1.0f, "떠난 UE 엔트리 제거 (실제 %.2f)", qos_weight_lookup(0x1111));
    CHECK(qos_weight_lookup(0x2222) == 4.0f, "생존 UE 는 유지 (실제 %.2f)",     qos_weight_lookup(0x2222));

    printf("[T4] retain(n=0) 은 아무것도 하지 않는다 (UE 목록 못 읽은 경우 보호)\n");
    qos_weight_retain(NULL, 0);
    CHECK(qos_weight_lookup(0x2222) == 4.0f, "n=0 에 전체 삭제 안 됨 (실제 %.2f)", qos_weight_lookup(0x2222));

    /* ── T5: clamp ── */
    printf("[T5] 범위 clamp\n");
    qos_weight_clear_all();
    qos_weight_apply(0x3333, 99.0f, 0);
    CHECK(qos_weight_lookup(0x3333) == 8.0f,  "상한 8.0 clamp (실제 %.2f)", qos_weight_lookup(0x3333));
    qos_weight_apply(0x4444, 0.01f, 0);
    CHECK(qos_weight_lookup(0x4444) == 0.25f, "하한 0.25 clamp (실제 %.2f)", qos_weight_lookup(0x4444));

    /* ── T6: TTL 만료 ── */
    printf("[T6] TTL 만료 (150ms)\n");
    qos_weight_clear_all();
    qos_weight_apply(0x5555, 8.0f, 150);
    CHECK(qos_weight_lookup(0x5555) == 8.0f, "만료 전 8.0 (실제 %.2f)", qos_weight_lookup(0x5555));
    usleep(200000);
    CHECK(qos_weight_lookup(0x5555) == 1.0f, "만료 후 1.0 (실제 %.2f)", qos_weight_lookup(0x5555));

    /* ── T7: 16 UE 전부 + 재적용 ── */
    printf("[T7] 16 UE 동시 수용\n");
    qos_weight_clear_all();
    for (int i = 0; i < 16; i++) qos_weight_apply(0x100 + i * 16, 2.0f, 0);  /* 전부 %16 동일! */
    int ok = 1;
    for (int i = 0; i < 16; i++) if (qos_weight_lookup(0x100 + i * 16) != 2.0f) ok = 0;
    CHECK(ok, "모든 RNTI 가 %%16 동일한 최악 경우에도 16대 전부 수용");
    qos_weight_apply(0x100, 4.0f, 0);
    CHECK(qos_weight_lookup(0x100) == 4.0f, "기존 UE 재적용은 슬롯 추가 안 함 (실제 %.2f)", qos_weight_lookup(0x100));

    /* ── T8: 미등록 UE ── */
    printf("[T8] 정책 없는 UE\n");
    CHECK(qos_weight_lookup(0xBEEF) == 1.0f, "기본값 1.0 (실제 %.2f)", qos_weight_lookup(0xBEEF));

    printf("\n═══ 통과 %d / 실패 %d ═══\n", pass, fail);
    return fail ? 1 : 0;
}
