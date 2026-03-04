// Copyright (c) 2025 OpenAirInterface
//
// JBPF Codelet: MAC UL(Uplink) PRB 점유율 통계 수집
//
// UE별 UL PRB 점유율, 처리량, 버퍼 압력(buffer pressure)을 수집한다.
// 버퍼 압력: buffer_bytes(요청량) vs tb_size(실제 제공량)의 비율로 측정.
//
// Hook: mac_ul_prb_alloc
// 위치: gNB_scheduler_ulsch.c - post_process_ulsch() 직후

#include "jbpf_defs.h"
#include "jbpf_helper.h"

/* Context 구조체 (mac_scheduler_hooks.h와 동일) */
struct mac_ul_prb_alloc_ctx {
    uint64_t data;
    uint64_t data_end;
    uint64_t meta_data;
    uint16_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint16_t rb_start;
    uint16_t rb_size;
    uint8_t  mcs;
    uint32_t tb_size;
    int32_t  buffer_bytes;
    int32_t  sched_ul_bytes;
    uint8_t  harq_pid;
    uint8_t  is_retx;
    uint8_t  _pad[2];
};

/*
 * UL PRB 보고 구조체
 *
 * buffer_pressure_pct:
 *   UE가 요청한 바이트(buffer_bytes) 대비 실제 할당된 바이트(tb_size)의 비율.
 *   100% = 요청량 전부 수용
 *   < 100% = 스케줄러가 UE의 요청보다 적게 줌 (PRB 부족 또는 다른 UE와 경쟁)
 */
struct ul_prb_report {
    uint64_t timestamp;
    uint32_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint16_t rb_start;
    uint16_t rb_size;
    uint8_t  mcs;
    uint32_t tb_size;          /* 이 슬롯 전송 가능 바이트 */
    int32_t  buffer_bytes;     /* UE 요청 바이트 (BSR 기반 추정) */
    uint8_t  harq_pid;
    uint8_t  is_retx;
    uint32_t total_ul_bytes;   /* 누적 UL 바이트 */
    uint32_t total_slots;      /* 누적 스케줄 횟수 */
    /*
     * buffer_pressure_pct:
     *   (tb_size / buffer_bytes) × 100 으로 계산하되
     *   buffer_bytes가 0이면 100으로 설정 (idle grant)
     *   200 이상이면 tb_size > buffer_bytes (오버프로비저닝)
     */
    uint8_t  buffer_pressure_pct;
};

struct ul_ue_stats {
    uint32_t total_ul_bytes;
    uint32_t total_slots;
    uint32_t total_retx;
};

jbpf_ringbuf_map(ul_prb_output, struct ul_prb_report, 32);

struct jbpf_load_map_def SEC("maps") ul_ue_stats_map = {
    .type        = JBPF_MAP_TYPE_HASHMAP,
    .key_size    = sizeof(uint32_t),
    .value_size  = sizeof(struct ul_ue_stats),
    .max_entries = 64,
};

SEC("jbpf_generic")
uint64_t
jbpf_main(void* state)
{
    struct mac_ul_prb_alloc_ctx *ctx = (struct mac_ul_prb_alloc_ctx *)state;
    uint32_t rnti = ctx->rnti;

    /*
     * 버퍼 압력 계산
     *
     * buffer_bytes는 int32_t이므로 음수가 될 수 있다.
     * (estimated_ul_buffer - sched_ul_bytes가 음수인 경우)
     * 음수이거나 0이면 idle grant로 간주, 압력 100%로 설정.
     *
     * eBPF에서는 나눗셈 주의:
     *   - 0으로 나누기 → verifier가 허용하지 않음
     *   - 반드시 0 체크 후 나누기
     */
    uint8_t pressure = 100;  /* 기본값: 100% (요청량 전부 수용) */
    if (ctx->buffer_bytes > 0 && ctx->tb_size > 0) {
        /*
         * pressure = (tb_size * 100) / buffer_bytes
         *
         * * 100을 먼저 하는 이유: 정수 나눗셈에서 소수점 손실 방지.
         * (10/30)*100 = 0  ← 틀림
         * (10*100)/30 = 33 ← 올바름
         *
         * 최대값 255로 클램핑 (uint8_t 범위)
         */
        uint32_t p = (ctx->tb_size * 100) / (uint32_t)ctx->buffer_bytes;
        pressure = (p > 255) ? 255 : (uint8_t)p;
    }

    struct ul_ue_stats *stats = jbpf_map_lookup_elem(&ul_ue_stats_map, &rnti);

    if (!stats) {
        struct ul_ue_stats new_stats = {
            .total_ul_bytes = ctx->tb_size,
            .total_slots    = 1,
            .total_retx     = ctx->is_retx ? 1 : 0,
        };
        jbpf_map_update_elem(&ul_ue_stats_map, &rnti, &new_stats, 0);

        struct ul_prb_report report = {
            .timestamp           = ctx->meta_data,
            .rnti                = rnti,
            .frame               = ctx->frame,
            .slot                = ctx->slot,
            .rb_start            = ctx->rb_start,
            .rb_size             = ctx->rb_size,
            .mcs                 = ctx->mcs,
            .tb_size             = ctx->tb_size,
            .buffer_bytes        = ctx->buffer_bytes,
            .harq_pid            = ctx->harq_pid,
            .is_retx             = ctx->is_retx,
            .total_ul_bytes      = ctx->tb_size,
            .total_slots         = 1,
            .buffer_pressure_pct = pressure,
        };
        jbpf_ringbuf_output(&ul_prb_output, &report, sizeof(report));
        return 0;
    }

    stats->total_ul_bytes += ctx->tb_size;
    stats->total_slots++;
    if (ctx->is_retx)
        stats->total_retx++;

    if (stats->total_slots % 100 == 0) {
        struct ul_prb_report report = {
            .timestamp           = ctx->meta_data,
            .rnti                = rnti,
            .frame               = ctx->frame,
            .slot                = ctx->slot,
            .rb_start            = ctx->rb_start,
            .rb_size             = ctx->rb_size,
            .mcs                 = ctx->mcs,
            .tb_size             = ctx->tb_size,
            .buffer_bytes        = ctx->buffer_bytes,
            .harq_pid            = ctx->harq_pid,
            .is_retx             = ctx->is_retx,
            .total_ul_bytes      = stats->total_ul_bytes,
            .total_slots         = stats->total_slots,
            .buffer_pressure_pct = pressure,
        };
        jbpf_ringbuf_output(&ul_prb_output, &report, sizeof(report));
    }

    return 0;
}
