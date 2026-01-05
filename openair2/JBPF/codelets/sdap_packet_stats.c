// Copyright (c) 2025 OpenAirInterface
//
// JBPF Codelet: SDAP Uplink 패킷 통계 수집
// 이 codelet은 UE별로 업링크 패킷 통계를 수집하고 주기적으로 리포트합니다.

#include "jbpf_defs.h"
#include "jbpf_helper.h"

/*
 * SDAP 계층 Context 구조체
 * 주의: 이 구조체는 nr_sdap_entity.c의 Hook 정의와 정확히 일치해야 함
 */
struct sdap_uplink_ctx {
    uint64_t data;          // gtp_buf 포인터
    uint64_t data_end;      // gtp_buf + gtp_len (verifier를 위한 경계)
    uint64_t meta_data;     // 타임스탬프 (rdtsc_oai)

    /* SDAP 특화 필드 */
    uint32_t ue_id;         // UE 식별자 (RNTI)
    uint8_t pdusession_id;  // PDU Session ID
    uint8_t rb_id;          // DRB ID
    uint8_t qfi;            // QoS Flow Identifier (0-63)
    uint8_t dc_bit;         // Data/Control PDU 구분
    uint32_t gtp_len;       // GTP 패킷 크기
};

/*
 * 패킷 통계 구조체
 * UE별로 누적 통계를 저장
 */
struct packet_stats {
    uint64_t rx_packets;      // 수신 패킷 수
    uint64_t rx_bytes;        // 수신 바이트 수
    uint64_t last_timestamp;  // 마지막 패킷 타임스탬프
};

/*
 * Output Ringbuf: 통계를 애플리케이션으로 전송
 * 크기 16: 최대 16개 메시지를 버퍼링 가능
 */
jbpf_ringbuf_map(stats_output, struct packet_stats, 16);

/*
 * State Map: UE별 통계 저장
 * Type: HASHMAP (키-값 쌍 저장)
 * Key: ue_id (uint32_t)
 * Value: packet_stats 구조체
 * Max entries: 256 UE까지 지원
 */
struct jbpf_load_map_def SEC("maps") ue_stats_map = {
    .type = JBPF_MAP_TYPE_HASHMAP,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct packet_stats),
    .max_entries = 256,
};

/*
 * Codelet 메인 함수
 * SDAP Hook이 호출될 때마다 실행됨
 *
 * @param state: Hook에서 전달된 context (sdap_uplink_ctx)
 * @return 0: 성공, 1: 실패 (실패해도 패킷 처리는 계속 진행)
 */
SEC("jbpf_generic")
uint64_t
jbpf_main(void* state)
{
    /* Context 캐스팅 */
    struct sdap_uplink_ctx* ctx = (struct sdap_uplink_ctx*)state;

    /* 메타데이터 추출 */
    uint32_t ue_id = ctx->ue_id;
    uint64_t timestamp = ctx->meta_data;
    uint32_t packet_size = ctx->gtp_len;

    /* UE별 통계 조회 */
    struct packet_stats* stats = jbpf_map_lookup_elem(&ue_stats_map, &ue_id);

    if (!stats) {
        /*
         * 새 UE 발견: 초기 통계 생성
         * 첫 패킷이므로 카운트를 1로 설정
         */
        struct packet_stats new_stats = {
            .rx_packets = 1,
            .rx_bytes = packet_size,
            .last_timestamp = timestamp
        };
        jbpf_map_update_elem(&ue_stats_map, &ue_id, &new_stats, 0);
        return 0;
    }

    /*
     * 기존 UE: 통계 업데이트
     * 주의: Map에서 조회한 포인터는 직접 수정 가능 (in-place update)
     */
    stats->rx_packets++;
    stats->rx_bytes += packet_size;
    stats->last_timestamp = timestamp;

    /*
     * 디버그 로그: 모든 패킷 모니터링
     * jbpf_printf_debug()는 USE_JBPF_PRINTF_HELPER 빌드 옵션 필요
     */
    jbpf_printf_debug("[SDAP STATS] UE=%u QFI=%u Session=%u: pkt=%llu bytes=%llu\n",
                      ue_id, ctx->qfi, ctx->pdusession_id,
                      stats->rx_packets, stats->rx_bytes);

    /*
     * 1000 패킷마다 통계를 애플리케이션으로 전송
     * ringbuf_output: Zero-copy 방식으로 데이터 전송
     */
    if (stats->rx_packets % 1000 == 0) {
        jbpf_ringbuf_output(&stats_output, stats, sizeof(*stats));
    }

    return 0;
}
