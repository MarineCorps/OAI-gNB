// Copyright (c) 2025 OpenAirInterface
//
// JBPF Codelet: SR(Scheduling Request) 감지 모니터링
//
// UE가 PUCCH를 통해 SR을 전송하고 gNB가 이를 유효하게 감지했을 때 호출된다.
// SR은 UE가 UL 데이터 발생을 gNB에 알리는 가장 첫 번째 시그널링이다.
//
// UL 시그널링 흐름 전체를 이 codelet이 추적하는 시작점으로 볼 수 있다:
//   SR 감지 → UL grant → BSR 수신 → UL PRB 할당 → 데이터 전송
//
// Hook: mac_sr_detect
// 위치: gNB_scheduler_uci.c - PUCCH Format 0/1 UCI 처리 직후

#include "jbpf_defs.h"
#include "jbpf_helper.h"

/* Context 구조체 (mac_scheduler_hooks.h와 동일) */
struct mac_sr_detect_ctx {
    uint64_t data;
    uint64_t data_end;
    uint64_t meta_data;
    uint16_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint8_t  sr_detected;  /* 항상 1 (유효한 SR만 hook 호출) */
    uint8_t  ul_cqi;       /* PUCCH 수신 품질 (0~255) */
    uint8_t  _pad[1];
};

/*
 * SR 이벤트 보고 구조체
 *
 * sr_count: 이 UE의 누적 SR 발생 횟수
 *   SR이 자주 발생하면 → UE가 데이터를 많이 생성 중
 *
 * avg_ul_cqi: 누적 평균 UL CQI
 *   높은 값 = 좋은 채널 품질 (UE가 gNB 근처에 있거나 좋은 경로)
 *   148 = SNR 10dB 기준선
 *
 * sr_rate_per_sec:
 *   초당 SR 발생 횟수 추정 (2000슬롯 = 1초, SCS=30kHz 기준)
 */
struct sr_report {
    uint64_t timestamp;
    uint32_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint8_t  ul_cqi;
    uint32_t sr_count;      /* 누적 SR 횟수 */
    uint32_t avg_ul_cqi;    /* 평균 UL CQI × 100 (소수점 2자리 보존) */
};

struct sr_ue_state {
    uint32_t sr_count;         /* 누적 SR 횟수 */
    uint64_t sum_ul_cqi;       /* CQI 합산 (평균 계산용) */
};

jbpf_ringbuf_map(sr_output, struct sr_report, 32);

struct jbpf_load_map_def SEC("maps") sr_ue_state_map = {
    .type        = JBPF_MAP_TYPE_HASHMAP,
    .key_size    = sizeof(uint32_t),
    .value_size  = sizeof(struct sr_ue_state),
    .max_entries = 64,
};

SEC("jbpf_generic")
uint64_t
jbpf_main(void* state)
{
    struct mac_sr_detect_ctx *ctx = (struct mac_sr_detect_ctx *)state;
    uint32_t rnti = ctx->rnti;

    struct sr_ue_state *sr_state = jbpf_map_lookup_elem(&sr_ue_state_map, &rnti);

    if (!sr_state) {
        /* 이 UE의 첫 SR */
        struct sr_ue_state new_state = {
            .sr_count   = 1,
            .sum_ul_cqi = ctx->ul_cqi,
        };
        jbpf_map_update_elem(&sr_ue_state_map, &rnti, &new_state, 0);

        struct sr_report report = {
            .timestamp   = ctx->meta_data,
            .rnti        = rnti,
            .frame       = ctx->frame,
            .slot        = ctx->slot,
            .ul_cqi      = ctx->ul_cqi,
            .sr_count    = 1,
            .avg_ul_cqi  = ctx->ul_cqi * 100,  /* × 100: 소수점 보존 */
        };
        jbpf_ringbuf_output(&sr_output, &report, sizeof(report));
        return 0;
    }

    /* 상태 업데이트 */
    sr_state->sr_count++;
    sr_state->sum_ul_cqi += ctx->ul_cqi;

    /*
     * 평균 CQI 계산
     *
     * avg_ul_cqi_x100 = (sum_ul_cqi * 100) / sr_count
     *
     * eBPF에서 64비트 나눗셈은 helper 없이 가능하다.
     * 결과를 uint32_t로 저장 (최대값: 255 × 100 = 25500)
     */
    uint32_t avg_cqi_x100 = (uint32_t)(sr_state->sum_ul_cqi * 100 / sr_state->sr_count);

    /*
     * 출력 조건:
     *   1) 10번마다 주기적 출력
     *   2) 첫 10번은 모두 출력 (트래픽 시작 포착)
     */
    if (sr_state->sr_count <= 10 || sr_state->sr_count % 10 == 0) {
        struct sr_report report = {
            .timestamp   = ctx->meta_data,
            .rnti        = rnti,
            .frame       = ctx->frame,
            .slot        = ctx->slot,
            .ul_cqi      = ctx->ul_cqi,
            .sr_count    = sr_state->sr_count,
            .avg_ul_cqi  = avg_cqi_x100,
        };
        jbpf_ringbuf_output(&sr_output, &report, sizeof(report));
    }

    return 0;
}
