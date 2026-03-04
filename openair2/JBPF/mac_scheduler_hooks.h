/*
 * ============================================================
 * mac_scheduler_hooks.h
 * ============================================================
 *
 * MAC 스케줄러 JBPF Hook Context 구조체 정의 파일
 *
 * 이 헤더는 두 가지 역할을 합니다:
 *   1) gNB C 소스코드: Hook을 선언하고 호출하는 쪽에서 include
 *   2) eBPF Codelet: codelet 소스(.c)에서 동일한 구조체를 사용하기 위해 include
 *
 * 포함된 Hook:
 *   [1] mac_dl_prb_alloc  - DL PRB 할당 (PDSCH 스케줄링)
 *   [2] mac_ul_prb_alloc  - UL PRB 할당 (PUSCH 스케줄링)
 *   [3] mac_bsr_event     - BSR(Buffer Status Report) 수신
 *   [4] mac_sr_detect     - SR(Scheduling Request) 감지
 *
 * 중요 규칙:
 *   - Context 구조체는 gNB 쪽(Hook 정의)과 Codelet 쪽이 정확히 일치해야 함
 *   - eBPF verifier를 위해 data/data_end/meta_data 필드가 맨 앞에 위치해야 함
 *   - 구조체는 반드시 8바이트 정렬(padding 주의)
 *   - eBPF 환경은 커널처럼 동작하므로, 동적 메모리 할당/포인터 역참조 불가
 *     → 필요한 값은 모두 context 구조체에 복사해서 전달
 * ============================================================
 */

#ifndef MAC_SCHEDULER_HOOKS_H
#define MAC_SCHEDULER_HOOKS_H

#include <stdint.h>

/* ============================================================
 * [Hook 1] mac_dl_prb_alloc
 *
 * 언제 호출되나?
 *   DL (Downlink) 스케줄러가 특정 UE에게 PRB를 할당하고
 *   post_process_dlsch()를 호출한 직후.
 *   즉, "이 UE에게 이 슬롯에 이만큼 DL PRB를 줬다"는 사실이 확정된 시점.
 *
 * 왜 이 시점인가?
 *   post_process_dlsch() 이후에는 rbStart, rbSize, MCS, TBS가 모두
 *   확정되어 NFAPI 구조체에 기록된다. Hook을 이 시점 바로 뒤에 넣으면
 *   최종 확정값을 관측할 수 있다.
 *
 * 무엇을 알 수 있나?
 *   - 어떤 UE(rnti)가
 *   - 몇 번째 슬롯(frame, slot)에
 *   - 어느 PRB 범위(rb_start ~ rb_start+rb_size)를
 *   - 어떤 MCS/코드레이트로 받았는지
 *   - 전송 블록 크기(tb_size)는 얼마인지
 *   - 신규 전송인지 재전송인지(is_retx)
 * ============================================================ */
struct mac_dl_prb_alloc_ctx {
    /*
     * [필수] eBPF verifier 요구 필드
     *
     * eBPF 프로그램은 메모리 안전성을 컴파일 시간에 검증한다.
     * data / data_end 는 "이 범위 안에서만 포인터를 사용해도 된다"는
     * 경계를 verifier에게 알려주는 역할이다.
     *
     * MAC 스케줄러 hook은 패킷 데이터가 없으므로 data = data_end = 0으로 설정.
     * meta_data에는 CPU 타임스탬프(rdtsc)를 담아 성능 측정에 활용한다.
     */
    uint64_t data;        /* 항상 0 (MAC hook은 패킷 버퍼 없음) */
    uint64_t data_end;    /* 항상 0 */
    uint64_t meta_data;   /* CPU 타임스탬프 (rdtsc_oai() 값) */

    /*
     * UE 식별자
     *
     * rnti (Radio Network Temporary Identifier):
     *   gNB가 각 UE에 임시로 부여하는 16비트 ID.
     *   0x0001 ~ 0xFFFE 범위. UE가 재접속하면 바뀔 수 있다.
     *   스케줄러에서 UE를 구분하는 주요 키.
     */
    uint16_t rnti;

    /*
     * 시간 정보
     *
     * 5G NR에서 시간은 frame.slot 단위로 표현된다.
     *   - frame: 10ms 단위 (0~1023, 10.24초 주기로 롤오버)
     *   - slot: frame 내 슬롯 번호 (SCS=30kHz 기준 0~19)
     */
    uint16_t frame;       /* 10ms 프레임 번호 (0~1023) */
    uint8_t  slot;        /* 슬롯 번호 (SCS 의존, 30kHz=20슬롯/프레임) */

    /*
     * PRB (Physical Resource Block) 할당 정보
     *
     * 5G NR에서 주파수 자원은 PRB 단위로 관리된다.
     *   - 1 PRB = 12 부반송파 × 0.5ms(슬롯)
     *   - FR1(sub-6GHz): 최대 275 PRB (100MHz @ 30kHz SCS)
     *
     * rb_start: BWP (Bandwidth Part) 시작점 기준 상대 인덱스
     * rb_size:  할당된 PRB 개수 (점유율 = rb_size / bwp_size × 100%)
     *
     * 예: rb_start=10, rb_size=25 → PRB #10~#34를 이 UE가 점유
     */
    uint16_t rb_start;    /* 시작 PRB 인덱스 (BWP 상대) */
    uint16_t rb_size;     /* 할당 PRB 수 */

    /*
     * MCS (Modulation and Coding Scheme)
     *
     * mcs: 0~28 값. 숫자가 클수록 고효율(고SNR 필요)
     *   - 낮은 값(0~9): QPSK, 낮은 코드레이트 → 원거리/열악한 채널
     *   - 중간(10~19): 16QAM
     *   - 높은 값(20~28): 64QAM/256QAM → 근거리/좋은 채널
     *
     * tb_size: Transport Block Size (바이트)
     *   실제로 이 슬롯에 전송할 데이터 크기.
     *   rb_size, mcs, 심볼 수, DMRS 오버헤드로 결정됨.
     */
    uint8_t  mcs;         /* Modulation and Coding Scheme (0~28) */
    uint32_t tb_size;     /* 전송 블록 크기 (바이트) */

    /*
     * HARQ (Hybrid ARQ) 정보
     *
     * HARQ는 전송 오류 시 재전송하는 메커니즘.
     *   - harq_pid: 0~15, 어떤 HARQ 프로세스인지 식별
     *   - is_retx: 0=신규 전송, 1=재전송
     *     재전송 시 스케줄러는 이전과 동일한 MCS를 사용하고
     *     수신기에서 두 전송을 합산(chase combining)하거나
     *     다른 버전(incremental redundancy)으로 보낼 수 있다.
     */
    uint8_t  harq_pid;    /* HARQ 프로세스 ID (0~15) */
    uint8_t  is_retx;     /* 재전송 여부: 0=신규, 1=재전송 */

    uint8_t  _pad[2];     /* 정렬 패딩 (구조체 크기를 8바이트 배수로) */
};

/* ============================================================
 * [Hook 2] mac_ul_prb_alloc
 *
 * 언제 호출되나?
 *   UL (Uplink) 스케줄러에서 UE의 PUSCH 전송을 위한 PRB를 확정하고
 *   post_process_ulsch()를 호출한 직후.
 *
 * DL hook과의 차이:
 *   - buffer_bytes: RLC에서 보고한 UE의 UL 버퍼 크기
 *                   (UE가 보낼 데이터가 얼마나 쌓여 있는지)
 *   - sched_ul_bytes: 이미 예약된 UL 바이트 (미처리 그랜트)
 *
 * 무엇을 알 수 있나?
 *   - UL 방향 PRB 점유율
 *   - UE가 얼마나 많은 데이터를 올리려 하는지(buffer_bytes)
 *   - 스케줄러가 실제로 얼마만큼의 전송 기회를 줬는지(tb_size)
 * ============================================================ */
struct mac_ul_prb_alloc_ctx {
    uint64_t data;        /* 항상 0 */
    uint64_t data_end;    /* 항상 0 */
    uint64_t meta_data;   /* CPU 타임스탬프 */

    uint16_t rnti;
    uint16_t frame;
    uint8_t  slot;

    uint16_t rb_start;    /* 시작 PRB (BWP 상대) */
    uint16_t rb_size;     /* 할당 PRB 수 */

    uint8_t  mcs;
    uint32_t tb_size;     /* 전송 블록 크기 (바이트) */

    /*
     * UL 버퍼 상태
     *
     * buffer_bytes: UE의 RLC 버퍼에 쌓인 전송 대기 데이터 (바이트)
     *   BSR(Buffer Status Report)을 기반으로 추정.
     *   스케줄러는 이 값을 보고 몇 개의 PRB를 줄지 결정한다.
     *
     * sched_ul_bytes: 이미 그랜트했지만 아직 수신 안 된 바이트 수
     *   이미 준 기회가 많으면 추가 그랜트를 줄이기도 한다.
     */
    int32_t  buffer_bytes;    /* UL RLC 버퍼 크기 (바이트) */
    int32_t  sched_ul_bytes;  /* 예약된 UL 바이트 */

    uint8_t  harq_pid;
    uint8_t  is_retx;
    uint8_t  _pad[2];
};

/* ============================================================
 * [Hook 3] mac_bsr_event
 *
 * 언제 호출되나?
 *   UE가 MAC PDU에 BSR(Buffer Status Report) MAC CE를 포함하여
 *   gNB로 PUSCH를 전송했고, gNB가 이를 성공적으로 디코딩한 직후.
 *
 * BSR이란?
 *   UE가 자신의 UL RLC 버퍼 상태를 gNB에 보고하는 MAC 제어 메시지.
 *   gNB는 이 값을 바탕으로 다음 슬롯의 UL PRB 할당량을 결정한다.
 *
 *   BSR 종류:
 *   ┌──────────────────────────────────────────────────────────┐
 *   │  Short BSR (S-BSR, S-T-BSR)                             │
 *   │    - 1개의 LCG(Logical Channel Group)에 대한 버퍼 크기  │
 *   │    - 5비트 인덱스 → 테이블 조회로 바이트 변환           │
 *   │    - 소량 데이터 발생 시 신속하게 보고                  │
 *   ├──────────────────────────────────────────────────────────┤
 *   │  Long BSR (L-BSR, L-T-BSR)                              │
 *   │    - 최대 8개 LCG에 대한 버퍼 크기 모두 보고            │
 *   │    - 8비트 인덱스 × LCG 수 → 더 정밀한 보고            │
 *   │    - 버퍼가 클 때 또는 주기적 트리거 시 사용            │
 *   └──────────────────────────────────────────────────────────┘
 *
 * bsr_type 값:
 *   0 = Short BSR (S-BSR / S-Truncated BSR)
 *   1 = Long BSR  (L-BSR / L-Truncated BSR)
 *
 * estimated_bytes:
 *   OAI가 BSR 인덱스를 바이트로 변환한 추정값 (overestimated).
 *   BSR 인덱스는 로그 스케일로 범위를 표현하므로, 실제 값은
 *   그 범위 안 어딘가에 있다. OAI는 안전하게 상한값을 사용.
 *
 * 시그널링 관점:
 *   BSR은 UE→gNB 방향의 스케줄링 시그널링 중 가장 핵심이다.
 *   BSR이 없으면 gNB는 UE에게 UL grant를 줄 수 없다.
 *   BSR → gNB 스케줄링 결정 → DCI(UL grant) → PUSCH 흐름
 * ============================================================ */
struct mac_bsr_event_ctx {
    uint64_t data;
    uint64_t data_end;
    uint64_t meta_data;

    uint16_t rnti;
    uint16_t frame;
    uint8_t  slot;

    /*
     * BSR 타입 및 추정 버퍼 크기
     *
     * bsr_type: 0=Short, 1=Long
     * estimated_bytes: gNB가 추정한 UE의 전체 UL 버퍼 크기 (바이트)
     *   이 값이 크면 스케줄러는 다음 슬롯에 더 많은 PRB를 줄 것
     *
     * lcg_id: Short BSR에서 보고한 LCG ID (0~7)
     *         Long BSR은 여러 LCG를 포함하므로 0xFF로 표시
     * LCG(Logical Channel Group): DRB들을 묶는 논리 채널 그룹.
     *   예) LCG0=SRB(제어), LCG1=인터넷, LCG2=VoLTE 등
     */
    uint8_t  bsr_type;         /* 0=Short, 1=Long */
    uint32_t estimated_bytes;  /* 전체 UL 버퍼 추정 크기 (바이트) */
    uint8_t  lcg_id;           /* Short BSR: LCG ID (0~7), Long BSR: 0xFF */

    uint8_t  _pad[2];
};

/* ============================================================
 * [Hook 4] mac_sr_detect
 *
 * 언제 호출되나?
 *   UE가 PUCCH Format 0/1을 통해 SR(Scheduling Request)을 보냈고,
 *   gNB가 이를 유효하다고 판단한 직후.
 *
 * SR이란?
 *   UE에게 보낼 UL 데이터가 생겼을 때, UE가 gNB에 "UL grant를 주세요"
 *   라고 요청하는 1비트 시그널링. PUCCH를 통해 전송된다.
 *
 *   SR 발생 → gNB가 UL grant 포함 DCI 전송 → UE가 PUSCH로 BSR+데이터 전송
 *
 * SR vs BSR 차이:
 *   SR: "데이터 있어요, grant 주세요" (1비트, PUCCH)
 *   BSR: "데이터가 X바이트 있어요" (세밀한 정보, MAC CE in PUSCH)
 *
 *   SR이 먼저 오고, BSR은 SR에 의해 받은 grant로 PUSCH를 보낼 때 포함됨.
 *
 * ul_cqi: PUCCH 수신 품질 (0~255)
 *   148 이상이면 SNR ≥ 10dB로 신뢰할 만한 수신.
 *   필터링 기준: sr_indication=1, confidence=0, ul_cqi≥148
 * ============================================================ */
struct mac_sr_detect_ctx {
    uint64_t data;
    uint64_t data_end;
    uint64_t meta_data;

    uint16_t rnti;
    uint16_t frame;
    uint8_t  slot;

    /*
     * SR 감지 결과
     * sr_detected: 1이면 유효한 SR로 판단됨
     * ul_cqi: PUCCH 수신 품질 지표 (148 이상 = SNR ≥ 10dB)
     */
    uint8_t  sr_detected;
    uint8_t  ul_cqi;     /* PUCCH ul_cqi (0~255) */

    uint8_t  _pad[1];
};

#endif /* MAC_SCHEDULER_HOOKS_H */
