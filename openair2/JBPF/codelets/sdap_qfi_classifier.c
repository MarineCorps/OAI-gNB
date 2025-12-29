// Copyright (c) 2025 OpenAirInterface
//
// JBPF Codelet: QFI별 트래픽 분류 및 모니터링
// 5G QoS Flow Identifier(QFI)를 기반으로 트래픽을 분류하고 통계를 수집합니다.

#include "jbpf_defs.h"
#include "jbpf_helper.h"

/*
 * SDAP 계층 Context (sdap_packet_stats.c와 동일)
 */
struct sdap_uplink_ctx {
    uint64_t data;
    uint64_t data_end;
    uint64_t meta_data;

    uint32_t ue_id;
    uint8_t pdusession_id;
    uint8_t rb_id;
    uint8_t qfi;
    uint8_t dc_bit;
    uint32_t gtp_len;
};

/*
 * QFI별 통계 구조체
 * UE와 QFI 조합별로 트래픽 특성을 추적
 */
struct qfi_stats {
    uint32_t ue_id;           // UE 식별자
    uint8_t qfi;              // QoS Flow Identifier
    uint8_t padding[3];       // 정렬을 위한 패딩
    uint64_t packet_count;    // 패킷 수
    uint64_t byte_count;      // 바이트 수
};

/*
 * QFI Map의 복합 키
 * UE + QFI 조합으로 트래픽 플로우 식별
 */
struct qfi_key {
    uint32_t ue_id;
    uint8_t qfi;
    uint8_t padding[3];       // 8바이트 정렬
} __attribute__((packed));

/*
 * Output Ringbuf: QFI 통계를 애플리케이션으로 전송
 */
jbpf_ringbuf_map(qfi_output, struct qfi_stats, 16);

/*
 * QFI Map: (UE, QFI) → 통계
 * 최대 1024개 플로우 지원 (예: 256 UE × 4 QFI)
 */
struct jbpf_load_map_def SEC("maps") qfi_map = {
    .type = JBPF_MAP_TYPE_HASHMAP,
    .key_size = sizeof(struct qfi_key),
    .value_size = sizeof(struct qfi_stats),
    .max_entries = 1024,
};

/*
 * Codelet 메인 함수
 *
 * QFI 값의 의미 (3GPP TS 23.501 참고):
 * - QFI 1: GBR (Guaranteed Bit Rate) - Conversational Video
 * - QFI 5: Non-GBR - IMS Signaling (높은 우선순위)
 * - QFI 9: Non-GBR - Default bearer (Best effort)
 * - QFI 65-127: Operator-specific
 */
SEC("jbpf_generic")
uint64_t
jbpf_main(void* state)
{
    struct sdap_uplink_ctx* ctx = (struct sdap_uplink_ctx*)state;

    /* 복합 키 생성 */
    struct qfi_key key = {
        .ue_id = ctx->ue_id,
        .qfi = ctx->qfi,
        .padding = {0, 0, 0}
    };

    /* QFI 플로우 조회 */
    struct qfi_stats* stats = jbpf_map_lookup_elem(&qfi_map, &key);

    if (!stats) {
        /*
         * 새로운 QFI 플로우 발견
         * 이는 다음을 의미할 수 있음:
         * 1. UE의 새로운 QoS Flow 생성
         * 2. 특정 서비스 시작 (예: VoIP 통화, 비디오 스트리밍)
         */
        struct qfi_stats new_stats = {
            .ue_id = ctx->ue_id,
            .qfi = ctx->qfi,
            .padding = {0, 0, 0},
            .packet_count = 1,
            .byte_count = ctx->gtp_len
        };
        jbpf_map_update_elem(&qfi_map, &key, &new_stats, 0);

        /*
         * 새 QFI 플로우 즉시 알림
         * 애플리케이션에서 QoS 정책 적용 가능
         */
        jbpf_ringbuf_output(&qfi_output, &new_stats, sizeof(new_stats));
        return 0;
    }

    /* 기존 플로우: 통계 업데이트 */
    stats->packet_count++;
    stats->byte_count += ctx->gtp_len;

    /*
     * 특정 QFI에 대한 특별 처리
     * 예시: QFI 5 (IMS Signaling)는 100 패킷마다 리포트
     * 실제 환경에서는 QFI별로 다른 정책 적용 가능:
     * - QFI 1 (Video): 지연시간 모니터링
     * - QFI 5 (IMS): 패킷 손실률 추적
     * - QFI 9 (Default): 대역폭 사용량 제한
     */
    if (ctx->qfi == 5 && stats->packet_count % 100 == 0) {
        jbpf_ringbuf_output(&qfi_output, stats, sizeof(*stats));
    }

    /*
     * QFI 9 (Default Bearer)는 1000 패킷마다 리포트
     */
    if (ctx->qfi == 9 && stats->packet_count % 1000 == 0) {
        jbpf_ringbuf_output(&qfi_output, stats, sizeof(*stats));
    }

    return 0;
}
