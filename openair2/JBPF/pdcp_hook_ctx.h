/*
 * ============================================================
 * pdcp_hook_ctx.h
 * ============================================================
 *
 * PDCP JBPF Hook Context 구조체 정의 — gNB 와 코드렛의 single source of truth.
 *
 * 이 헤더는 두 쪽에서 include 된다:
 *   1) gNB C 소스  : nr_pdcp_oai_api.c  (DECLARE_JBPF_HOOK 의 ctx 타입)
 *   2) eBPF 코드렛 : intent_parser.c, header_parser.c  (ctx 포인터 캐스팅)
 *
 * 왜 공유 헤더인가:
 *   코드렛은 호스트가 채운 메모리를 구조체로 *그대로 캐스팅해서* 읽는다.
 *   양쪽이 정의를 따로 들고 있으면 한쪽에 필드를 추가한 순간 오프셋이
 *   어긋나면서 조용히 쓰레기 값을 읽는다 (컴파일 에러도, 런타임 에러도
 *   나지 않는다). qos_weight_msg.h 와 같은 원칙이다.
 *
 * include 경로:
 *   코드렛 쪽은 Makefile / CMakeLists 의 -I${SRC}/openair2/JBPF 덕분에
 *   파일명만으로 가져올 수 있다 — #include "pdcp_hook_ctx.h"
 *
 * 구조체 규칙 (eBPF 제약):
 *   - data / data_end / meta_data 가 반드시 맨 앞에 와야 한다.
 *     검증기가 이 세 필드로 포인터 접근 경계를 추적한다.
 *   - 8바이트 정렬을 유지할 것 (필드 추가 시 패딩 확인).
 *   - 코드렛은 동적 할당·역참조가 불가능하므로 필요한 값은 모두
 *     이 구조체에 복사해서 전달해야 한다.
 * ============================================================
 */

#ifndef PDCP_HOOK_CTX_H
#define PDCP_HOOK_CTX_H

#include <stdint.h>

/*
 * 호출 시점:
 *   deliver_sdu_drb() — PDCP 복호화가 끝나고 SDAP 으로 넘기기 직전.
 *   즉 UL 사용자 패킷의 평문 IP 헤더를 볼 수 있는 가장 이른 지점이다.
 */
struct pdcp_uplink_ctx {
    /* ── eBPF 검증기 필수 필드 ─────────────────────────────── */
    uint64_t data;          /* IP 패킷 시작 (SDAP 헤더 오프셋 적용 후) */
    uint64_t data_end;      /* 패킷 끝 — 경계 검사용 */
    uint64_t meta_data;     /* CPU 타임스탬프 (rdtsc_oai) */

    /* ── 5G 메타데이터 ─────────────────────────────────────── */
    uint32_t ue_id;         /* PDCP 내부 UE ID (= CU-UE-ID, MAC RNTI 아님) */
    uint8_t  pdusession_id; /* PDU Session ID */
    uint8_t  rb_id;         /* Radio Bearer ID (DRB) */
    uint8_t  has_sdap_rx;   /* SDAP RX 헤더 존재 여부 (1=존재) */
    uint8_t  qfi;           /* QoS Flow Identifier (0~63) */

    /* ── 패킷 크기 ─────────────────────────────────────────── */
    uint32_t total_size;    /* 전체 버퍼 크기 (SDAP 헤더 포함) */
    uint32_t ip_size;       /* IP 패킷 크기 (SDAP 헤더 제외) */
};

#endif /* PDCP_HOOK_CTX_H */
