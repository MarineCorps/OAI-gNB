// Copyright (c) 2025 OpenAirInterface
//
// JBPF Codelet: BSR(Buffer Status Report) 모니터링
//
// UE로부터 BSR MAC CE를 수신할 때마다 호출된다.
// BSR은 UE가 "내 UL 버퍼에 X바이트 데이터가 있다"고 gNB에 알리는 시그널.
// 이 codelet은 BSR 발생 빈도와 버퍼 크기 추이를 추적한다.
//
// Hook: mac_bsr_event
// 위치: gNB_scheduler_ulsch.c - Short/Long BSR MAC CE 처리 직후

#include "jbpf_defs.h"
#include "jbpf_helper.h"

/* Context 구조체 (mac_scheduler_hooks.h와 동일) */
struct mac_bsr_event_ctx {
    uint64_t data;
    uint64_t data_end;
    uint64_t meta_data;
    uint16_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint8_t  bsr_type;         /* 0=Short, 1=Long */
    uint32_t estimated_bytes;
    uint8_t  lcg_id;
    uint8_t  _pad[2];
};

/*
 * BSR 이벤트 보고 구조체
 *
 * bsr_type:
 *   0 = Short BSR: 단일 LCG, 소량 데이터 발생 시
 *   1 = Long BSR:  전체 LCG 보고, 대량 데이터 또는 주기 보고
 *
 * lcg_id:
 *   Short BSR: 0~7 (어느 LCG의 데이터인지)
 *   Long BSR:  0xFF (다중 LCG 포함)
 *
 * bsr_rate_per_sec:
 *   마지막 1초(약 2000슬롯, SCS=30kHz) 동안의 BSR 발생 횟수.
 *   높은 값 = UE가 활발하게 데이터를 생성 중
 */
struct bsr_report {
    uint64_t timestamp;
    uint32_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint8_t  bsr_type;
    uint32_t estimated_bytes;  /* 이번 BSR이 보고한 버퍼 크기 */
    uint8_t  lcg_id;
    uint32_t bsr_count;        /* 이 UE의 누적 BSR 횟수 */
    uint32_t peak_bytes;       /* 최대 버퍼 크기 기록 */
};

struct bsr_ue_state {
    uint32_t bsr_count;    /* 누적 BSR 발생 횟수 */
    uint32_t peak_bytes;   /* 최대 버퍼 크기 */
    uint32_t last_bytes;   /* 마지막 BSR 버퍼 크기 */
};

jbpf_ringbuf_map(bsr_output, struct bsr_report, 32);

struct jbpf_load_map_def SEC("maps") bsr_ue_state_map = {
    .type        = JBPF_MAP_TYPE_HASHMAP,
    .key_size    = sizeof(uint32_t),
    .value_size  = sizeof(struct bsr_ue_state),
    .max_entries = 64,
};

SEC("jbpf_generic")
uint64_t
jbpf_main(void* state)
{
    struct mac_bsr_event_ctx *ctx = (struct mac_bsr_event_ctx *)state;
    uint32_t rnti = ctx->rnti;

    struct bsr_ue_state *bsr_state = jbpf_map_lookup_elem(&bsr_ue_state_map, &rnti);

    if (!bsr_state) {
        /*
         * 이 UE의 첫 번째 BSR
         *
         * peak_bytes 초기화: estimated_bytes를 첫 최대값으로.
         * 이후 더 큰 값이 오면 peak_bytes를 업데이트.
         */
        struct bsr_ue_state new_state = {
            .bsr_count  = 1,
            .peak_bytes = ctx->estimated_bytes,
            .last_bytes = ctx->estimated_bytes,
        };
        jbpf_map_update_elem(&bsr_ue_state_map, &rnti, &new_state, 0);

        /* 첫 BSR은 항상 즉시 출력 */
        struct bsr_report report = {
            .timestamp       = ctx->meta_data,
            .rnti            = rnti,
            .frame           = ctx->frame,
            .slot            = ctx->slot,
            .bsr_type        = ctx->bsr_type,
            .estimated_bytes = ctx->estimated_bytes,
            .lcg_id          = ctx->lcg_id,
            .bsr_count       = 1,
            .peak_bytes      = ctx->estimated_bytes,
        };
        jbpf_ringbuf_output(&bsr_output, &report, sizeof(report));
        return 0;
    }

    /* 상태 업데이트 */
    bsr_state->bsr_count++;
    bsr_state->last_bytes = ctx->estimated_bytes;

    /*
     * Peak 업데이트
     *
     * 조건 연산자 (삼항 연산자): condition ? value_if_true : value_if_false
     * estimated_bytes가 기존 peak보다 크면 갱신
     */
    if (ctx->estimated_bytes > bsr_state->peak_bytes)
        bsr_state->peak_bytes = ctx->estimated_bytes;

    /*
     * 출력 조건:
     *   1) 50번마다 주기적 출력 (약 25ms 주기)
     *   2) 버퍼 크기가 100KB 이상인 대용량 BSR은 즉시 출력
     *      (100000바이트 = 약 100KB, 트래픽 폭발 감지)
     */
    int should_output = (bsr_state->bsr_count % 50 == 0) ||
                        (ctx->estimated_bytes >= 100000);

    if (should_output) {
        struct bsr_report report = {
            .timestamp       = ctx->meta_data,
            .rnti            = rnti,
            .frame           = ctx->frame,
            .slot            = ctx->slot,
            .bsr_type        = ctx->bsr_type,
            .estimated_bytes = ctx->estimated_bytes,
            .lcg_id          = ctx->lcg_id,
            .bsr_count       = bsr_state->bsr_count,
            .peak_bytes      = bsr_state->peak_bytes,
        };
        jbpf_ringbuf_output(&bsr_output, &report, sizeof(report));
    }

    return 0;
}
