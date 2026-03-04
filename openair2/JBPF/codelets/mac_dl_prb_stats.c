// Copyright (c) 2025 OpenAirInterface
//
// JBPF Codelet: MAC DL(Downlink) PRB 점유율 통계 수집
//
// 이 codelet은 gNB 스케줄러가 DL PRB를 UE에게 할당할 때마다 호출된다.
// UE별 DL PRB 점유율, 처리량, MCS 이력을 수집하고 주기적으로 출력한다.
//
// Hook: mac_dl_prb_alloc
// 위치: gNB_scheduler_dlsch.c - post_process_dlsch() 직후

/*
 * jbpf_defs.h: jbpf 맵, SEC() 매크로, 기본 타입 정의
 * jbpf_helper.h: jbpf_map_lookup_elem, jbpf_map_update_elem,
 *                jbpf_ringbuf_output, jbpf_printf_debug 등
 */
#include "jbpf_defs.h"
#include "jbpf_helper.h"

/*
 * Context 구조체 (mac_scheduler_hooks.h와 동일해야 함)
 *
 * 중요: 이 구조체는 gNB 측 hook 정의와 필드 순서, 타입, 크기가
 * 정확히 일치해야 한다. 불일치 시 잘못된 값을 읽게 된다.
 */
struct mac_dl_prb_alloc_ctx {
    uint64_t data;       /* 항상 0 */
    uint64_t data_end;   /* 항상 0 */
    uint64_t meta_data;  /* CPU 타임스탬프 */
    uint16_t rnti;       /* UE RNTI */
    uint16_t frame;      /* 프레임 번호 */
    uint8_t  slot;       /* 슬롯 번호 */
    uint16_t rb_start;   /* 시작 PRB */
    uint16_t rb_size;    /* 할당 PRB 수 */
    uint8_t  mcs;        /* MCS 인덱스 */
    uint32_t tb_size;    /* 전송 블록 크기 */
    uint8_t  harq_pid;   /* HARQ 프로세스 ID */
    uint8_t  is_retx;    /* 0=신규, 1=재전송 */
    uint8_t  _pad[2];
};

/*
 * 출력 데이터 구조체
 *
 * 이 구조체가 ringbuf를 통해 userspace 애플리케이션으로 전달된다.
 * 슬롯별 DL 할당 정보를 담는다.
 */
struct dl_prb_report {
    uint64_t timestamp;    /* CPU 사이클 카운터 */
    uint32_t rnti;         /* UE 식별자 */
    uint16_t frame;
    uint8_t  slot;
    uint16_t rb_start;     /* 시작 PRB */
    uint16_t rb_size;      /* 할당 PRB 수 */
    uint8_t  mcs;
    uint32_t tb_size;      /* 바이트 단위 처리량 */
    uint8_t  harq_pid;
    uint8_t  is_retx;
    uint32_t total_dl_bytes; /* 이 UE의 누적 DL 바이트 */
    uint32_t total_slots;    /* 이 UE의 누적 할당 슬롯 수 */
};

/*
 * UE별 누적 통계 저장 구조체
 * HashMap에 RNTI를 키로 저장
 */
struct dl_ue_stats {
    uint32_t total_dl_bytes;   /* 누적 DL 바이트 */
    uint32_t total_slots;      /* 스케줄된 슬롯 수 */
    uint32_t total_retx;       /* 재전송 횟수 */
    uint8_t  last_mcs;         /* 마지막 사용 MCS */
};

/*
 * Ringbuf 출력 맵
 *
 * jbpf_ringbuf_map(이름, 타입, 엔트리수) 매크로:
 *   내부적으로 jbpf_load_map_def 구조체를 JBPF_MAP_TYPE_RINGBUF 타입으로 생성.
 *   크기 32: 최대 32개 메시지를 버퍼링. overflow 시 오래된 항목 덮어씀.
 *
 * Ringbuf는 Zero-copy 방식: 포인터를 직접 userspace와 공유.
 * 고성능 로깅에 적합 (per-slot 이벤트 기록에 이상적).
 */
jbpf_ringbuf_map(dl_prb_output, struct dl_prb_report, 32);

/*
 * UE별 통계 저장 HashMap
 *
 * struct jbpf_load_map_def: jbpf 맵 정의 구조체
 *   .type        : 맵 종류 (HASHMAP = 키-값 쌍, O(1) 조회)
 *   .key_size    : 키 크기 (RNTI = uint32_t = 4바이트)
 *   .value_size  : 값 크기 (dl_ue_stats 구조체)
 *   .max_entries : 최대 항목 수 (동시 UE 수)
 *
 * SEC("maps"): ELF 섹션 지정. jbpf 로더가 이 섹션을 파싱하여 맵을 생성.
 */
struct jbpf_load_map_def SEC("maps") dl_ue_stats_map = {
    .type        = JBPF_MAP_TYPE_HASHMAP,
    .key_size    = sizeof(uint32_t),    /* key: RNTI */
    .value_size  = sizeof(struct dl_ue_stats),
    .max_entries = 64,                  /* 최대 64 UE 지원 */
};

/*
 * ============================================================
 * jbpf_main: Codelet 진입점
 *
 * MAC DL PRB 할당 이벤트가 발생할 때마다 호출된다.
 * 즉, gNB 스케줄러가 어떤 UE에게 DL PRB를 줄 때마다 실행.
 *
 * @param state: hook_mac_dl_prb_alloc()가 전달한 context 포인터
 *               (struct mac_dl_prb_alloc_ctx*)로 캐스팅하여 사용
 * @return: 0 (성공), 1 (실패, 패킷 처리에는 영향 없음)
 * ============================================================
 */
SEC("jbpf_generic")
uint64_t
jbpf_main(void* state)
{
    /*
     * 1단계: Context 포인터 캐스팅
     *
     * state는 void*로 전달된다. 이를 실제 구조체 타입으로 캐스팅해야
     * 필드에 접근할 수 있다.
     *
     * C에서 캐스팅은 메모리 레이아웃을 그대로 유지하면서
     * 다른 타입으로 해석하는 것이다. 따라서 구조체 정의가 양쪽에서
     * 일치해야 올바른 값을 읽는다.
     */
    struct mac_dl_prb_alloc_ctx *ctx = (struct mac_dl_prb_alloc_ctx *)state;

    /* 2단계: 필드 추출 */
    uint32_t rnti = ctx->rnti;   /* uint16_t → uint32_t (HashMap 키 크기 맞춤) */

    /* 3단계: UE별 통계 조회 */
    struct dl_ue_stats *stats = jbpf_map_lookup_elem(&dl_ue_stats_map, &rnti);

    if (!stats) {
        /*
         * 새로운 UE: 초기 통계 생성
         *
         * C에서 구조체 초기화: .필드명 = 값 형태로 지정 초기화(designated initializer).
         * 나머지 필드는 0으로 초기화된다.
         *
         * jbpf_map_update_elem(맵, 키포인터, 값포인터, 플래그):
         *   플래그 0 = BPF_ANY: 있으면 업데이트, 없으면 삽입
         */
        struct dl_ue_stats new_stats = {
            .total_dl_bytes = ctx->tb_size,
            .total_slots    = 1,
            .total_retx     = ctx->is_retx ? 1 : 0,
            .last_mcs       = ctx->mcs,
        };
        jbpf_map_update_elem(&dl_ue_stats_map, &rnti, &new_stats, 0);

        /* 새 UE 첫 할당은 즉시 출력 */
        struct dl_prb_report report = {
            .timestamp       = ctx->meta_data,
            .rnti            = rnti,
            .frame           = ctx->frame,
            .slot            = ctx->slot,
            .rb_start        = ctx->rb_start,
            .rb_size         = ctx->rb_size,
            .mcs             = ctx->mcs,
            .tb_size         = ctx->tb_size,
            .harq_pid        = ctx->harq_pid,
            .is_retx         = ctx->is_retx,
            .total_dl_bytes  = ctx->tb_size,
            .total_slots     = 1,
        };
        jbpf_ringbuf_output(&dl_prb_output, &report, sizeof(report));
        return 0;
    }

    /* 4단계: 기존 UE 통계 업데이트 */
    stats->total_dl_bytes += ctx->tb_size;
    stats->total_slots++;
    if (ctx->is_retx)
        stats->total_retx++;
    stats->last_mcs = ctx->mcs;

    /*
     * 5단계: 출력 결정
     *
     * 매 슬롯마다 출력하면 ringbuf가 금방 넘친다.
     * 100슬롯마다 한 번 출력하여 부하를 줄인다.
     * 100슬롯 = 100 × 0.5ms = 50ms 주기 (SCS=30kHz 기준)
     *
     * % 연산: 나머지. total_slots가 100의 배수일 때만 출력.
     */
    if (stats->total_slots % 100 == 0) {
        struct dl_prb_report report = {
            .timestamp       = ctx->meta_data,
            .rnti            = rnti,
            .frame           = ctx->frame,
            .slot            = ctx->slot,
            .rb_start        = ctx->rb_start,
            .rb_size         = ctx->rb_size,
            .mcs             = ctx->mcs,
            .tb_size         = ctx->tb_size,
            .harq_pid        = ctx->harq_pid,
            .is_retx         = ctx->is_retx,
            .total_dl_bytes  = stats->total_dl_bytes,
            .total_slots     = stats->total_slots,
        };
        jbpf_ringbuf_output(&dl_prb_output, &report, sizeof(report));
    }

    return 0;
}
