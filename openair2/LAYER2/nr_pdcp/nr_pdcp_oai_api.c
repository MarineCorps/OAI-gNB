/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "nr_pdcp_oai_api.h"
#include <errno.h>
#include <fcntl.h>
#include <openair3/ocp-gtpu/gtp_itf.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "LAYER2/MAC/mac_extern.h"
#include "LTE_DRB-ToAddModList.h"
#include "LTE_DRB-ToReleaseList.h"
#include "LTE_PMCH-InfoList-r9.h"
#include "LTE_SRB-ToAddModList.h"
#include "NR_DRB-ToAddMod.h"
#include "NR_QFI.h"
#include "NR_SDAP-Config.h"
#include "NR_SRB-ToAddMod.h"
#include "SDAP/nr_sdap/nr_sdap_entity.h"
#include "assertions.h"
#include "common/ngran_types.h"
#include "common/platform_constants.h"
#include "common/ran_context.h"
#include "common/utils/T/T.h"
#include "common/utils/tun_if.h"
#include "cuup_cucp_if.h"
#include "executables/lte-softmodem.h"
#include "executables/softmodem-common.h"
#include "f1ap_messages_types.h"
#include "gnb_config.h"
#include "gtpv1_u_messages_types.h"
#include "hashtable.h"
#include "intertask_interface.h"
#include "common/utils/LOG/log.h"
#include "nfapi/oai_integration/vendor_ext.h"
#include "nr_pdcp_asn1_utils.h"
#include "nr_pdcp_timer_thread.h"
#include "nr_pdcp_ue_manager.h"
#include "openair2/F1AP/f1ap_ids.h"
#include "openair2/SDAP/nr_sdap/nr_sdap.h"
#include "pdcp.h"
#include "pdcp_messages_types.h"
#include "openair2/LAYER2/nr_rlc/nr_rlc_oai_api.h"
#include "utils.h"

#if defined(JBPF_HOOK) && !defined(NR_UE)

#include "jbpf.h"
#include "jbpf_hook.h"
#include "jbpf_defs.h"
#include "common/utils/time_meas.h"
#include <pthread.h>
/*
 * ============================================================
 * Thread-Local Storage (TLS) 설명
 * ============================================================
 * 
 * __thread 키워드:
 * - 각 스레드마다 독립적인 변수 생성
 * - Thread A: jbpf_pdcp_thread_registered = 0 (독립)
 * - Thread B: jbpf_pdcp_thread_registered = 0 (독립)
 * 
 * 왜 필요한가?
 * - JBPF는 thread마다 한 번씩 등록 필요
 * - 전역 변수 사용 시 한 번만 등록되어 다른 thread에서 에러
 * - TLS 사용으로 각 thread가 독립적으로 등록 관리
 */

 static __thread int jbpf_pdcp_thread_registered = 0;

/*
 * ============================================================
 * PDCP Uplink Context 구조체 정의
 * ============================================================
 *
 * 이 구조체는 Application → Codelet으로 전달되는 데이터 컨테이너입니다.
 *
 * eBPF Verifier 필수 필드:
 * - data, data_end: Codelet에서 접근할 메모리 영역의 시작/끝 포인터
 *   (Verifier가 경계 검사를 수행하여 메모리 안전성 보장)
 * - meta_data: 타임스탬프 등 메타정보 저장
 *
 * 5G 네트워크 메타데이터:
 * - ue_id: UE 식별자 (RNTI)
 * - pdusession_id: PDU Session 식별자
 * - rb_id: Radio Bearer 식별자 (DRB)
 * - has_sdap_rx: SDAP 헤더 존재 여부 (1=있음, 0=없음)
 * - qfi: QoS Flow Identifier (0-63, SDAP 헤더에서 추출)
 *
 * 패킷 크기 정보:
 * - total_size: 전체 크기 (SDAP 헤더 포함)
 * - ip_size: IP 패킷 크기 (SDAP 헤더 제외)
 */
struct pdcp_uplink_ctx {
    /* eBPF Verifier 필수 필드 */
    uint64_t data;          // IP 패킷 시작 포인터 (SDAP 헤더 이후)
    uint64_t data_end;      // 패킷 끝 포인터 (경계 검사용)
    uint64_t meta_data;     // 타임스탬프 (rdtsc_oai)

    /* 5G Network 메타데이터 */
    uint32_t ue_id;         // UE 식별자 (RNTI)
    uint8_t pdusession_id;  // PDU Session ID
    uint8_t rb_id;          // Radio Bearer ID (DRB)
    uint8_t has_sdap_rx;    // SDAP RX 헤더 존재 여부 (1=존재, 0=없음)
    uint8_t qfi;            // QoS Flow Identifier (0-63)

    /* 패킷 크기 정보 */
    uint32_t total_size;    // 전체 패킷 크기 (SDAP 헤더 포함)
    uint32_t ip_size;       // IP 패킷 크기 (SDAP 헤더 제외)
};

/*
 * ============================================================
 * PDCP Uplink Hook 선언
 * ============================================================
 *
 * DECLARE_JBPF_HOOK 매크로 파라미터 설명:
 *
 * ① pdcp_uplink
 *    - Hook 이름 (식별자)
 *    - 실제 생성되는 함수: hook_pdcp_uplink()
 *
 * ② struct pdcp_uplink_ctx ctx
 *    - Context 타입과 변수 선언
 *    - Codelet에 전달될 데이터 컨테이너
 *
 * ③ ctx
 *    - Context 변수명 (②에서 선언한 변수명 반복)
 *
 * ④ HOOK_PROTO(...)
 *    - Hook 함수 시그니처 (호출점에서 전달할 파라미터 정의)
 *    - 실제 호출: hook_pdcp_uplink(buf, size, entity, ue)
 *
 *    파라미터 설명:
 *    - uint8_t* buf: 패킷 버퍼 ([SDAP 헤더?][IP 패킷])
 *    - int size: 전체 버퍼 크기
 *    - nr_pdcp_entity_t* entity: PDCP 엔티티 (설정 정보 포함)
 *    - nr_pdcp_ue_t* ue: UE 정보 (ue_id 등)
 *
 * ⑤ HOOK_ASSIGN(...)
 *    - Hook 호출 직전에 실행되는 Context 초기화 코드
 *    - HOOK_PROTO의 파라미터들을 사용하여 ctx 구조체 채움
 *    - 임시 변수 선언 가능
 *
 * 실행 흐름:
 * 1. deliver_sdu_drb()에서 hook_pdcp_uplink(buf, size, entity, ue) 호출
 * 2. HOOK_ASSIGN 코드 실행 (Context 초기화)
 * 3. 등록된 모든 Codelet 실행 (Context 전달)
 */
DECLARE_JBPF_HOOK(
    pdcp_uplink,                                  // ① Hook 이름
    struct pdcp_uplink_ctx ctx,                   // ② Context 선언
    ctx,                                          // ③ Context 변수명

    // ④ Hook 함수 시그니처
    HOOK_PROTO(uint8_t* buf, int size, nr_pdcp_entity_t* entity, nr_pdcp_ue_t* ue),

    // ⑤ Context 초기화 코드 (Hook 호출 직전 실행)
    HOOK_ASSIGN(
        /*
         * SDAP 헤더 오프셋 계산
         * - has_sdap_rx = 1 (true): SDAP 헤더 1바이트 존재 → offset = 1
         * - has_sdap_rx = 0 (false): SDAP 헤더 없음 → offset = 0
         *
         * 버퍼 구조:
         * [SDAP 1byte][IP Packet...] ← has_sdap_rx = 1 일 때
         * [IP Packet...]             ← has_sdap_rx = 0 일 때
         */
        int sdap_offset = entity->has_sdap_rx ? 1 : 0;

        /*
         * QFI 추출 (SDAP 헤더에서)
         * - SDAP 헤더 구조: [DC(1bit)][R(1bit)][QFI(6bit)]
         * - QFI 추출: buf[0] & 0x3F (하위 6비트만 추출)
         *   예: buf[0] = 0b11001010
         *       0x3F   = 0b00111111 (마스크)
         *       결과   = 0b00001010 = 10 (QFI 값)
         */
        uint8_t qfi_value = 0;
        if (entity->has_sdap_rx && size > 0) {
            qfi_value = buf[0] & 0x3F;  // 하위 6비트 추출
        }

        /*
         * Context 필드 채우기 (Codelet에 전달될 데이터)
         */

        /* 메모리 영역 포인터 설정 (eBPF Verifier 필수) */
        ctx.data = (uint64_t)(void*)(buf + sdap_offset);  // IP 패킷 시작 주소
        ctx.data_end = (uint64_t)(void*)(buf + size);     // 패킷 끝 주소

        /*
         * 포인터 타입 캐스팅 설명:
         * 1. buf + sdap_offset → uint8_t* (SDAP 헤더 건너뛴 위치)
         * 2. (void*) 캐스팅 → 범용 포인터로 변환
         * 3. (uint64_t) 캐스팅 → 64비트 정수로 변환 (Context 저장용)
         *
         * Codelet에서는 역으로 변환:
         * uint64_t → void* → struct iphdr*
         */

        /* 타임스탬프 (RDTSC: Read Time-Stamp Counter) */
        ctx.meta_data = rdtsc_oai();  // CPU 사이클 카운터 읽기

        /* 5G 네트워크 메타데이터 */
        ctx.ue_id = ue->ue_id;                        // UE 식별자 (RNTI)
        ctx.pdusession_id = entity->pdusession_id;    // PDU Session ID
        ctx.rb_id = entity->rb_id;                    // Radio Bearer ID
        ctx.has_sdap_rx = entity->has_sdap_rx ? 1 : 0; // SDAP 헤더 존재 여부
        ctx.qfi = qfi_value;                          // QoS Flow Identifier

        /* 패킷 크기 정보 */
        ctx.total_size = size;              // 전체 크기 (SDAP 포함)
        ctx.ip_size = size - sdap_offset;   // IP 패킷 크기 (SDAP 제외)
    )
)

/*
 * ============================================================
 * PDCP Uplink Hook 정의
 * ============================================================
 *
 * DEFINE_JBPF_HOOK 매크로:
 * - Hook 메타데이터를 ELF section에 저장
 * - JBPF 런타임이 Hook 위치를 찾을 수 있도록 함
 * - DECLARE_JBPF_HOOK과 반드시 같은 파일에 있어야 함
 *
 * ELF Section 생성:
 * __attribute__((section("jbpf_hooks")))
 * struct jbpf_hook_metadata {
 *     .name = "pdcp_uplink",
 *     .address = &hook_pdcp_uplink,
 *     ...
 * }
 */
DEFINE_JBPF_HOOK(pdcp_uplink)

#endif  // JBPF_HOOK && !NR_UE


#define TODO do { \
    printf("%s:%d:%s: todo\n", __FILE__, __LINE__, __FUNCTION__); \
    exit(1); \
  } while (0)

static nr_pdcp_ue_manager_t *nr_pdcp_ue_manager;

/* necessary globals for OAI, not used internally */
hash_table_t  *pdcp_coll_p;
static uint64_t pdcp_optmask;

static ngran_node_t node_type;

nr_pdcp_entity_t *nr_pdcp_get_rb(nr_pdcp_ue_t *ue, int rb_id, bool srb_flag)
{
  nr_pdcp_entity_t *rb;

  if (srb_flag) {
    if (rb_id < 1 || rb_id > 2)
      rb = NULL;
    else
      rb = ue->srb[rb_id - 1];
  } else {
    if (rb_id < 1 || rb_id > MAX_DRBS_PER_UE)
      rb = NULL;
    else
      rb = ue->drb[rb_id - 1];
  }

  return rb;
}

/****************************************************************************/
/* rlc_data_req queue - begin                                               */
/****************************************************************************/


#include <pthread.h>

/* NR PDCP and RLC both use "big locks". In some cases a thread may do
 * lock(rlc) followed by lock(pdcp) (typically when running 'rx_sdu').
 * Another thread may first do lock(pdcp) and then lock(rlc) (typically
 * the GTP module calls 'nr_pdcp_data_req' that, in a previous implementation
 * was indirectly calling 'rlc_data_req' which does lock(rlc)).
 * To avoid the resulting deadlock it is enough to ensure that a call
 * to lock(pdcp) will never be followed by a call to lock(rlc). So,
 * here we chose to have a separate thread that deals with rlc_data_req,
 * out of the PDCP lock. Other solutions may be possible.
 * So instead of calling 'rlc_data_req' directly we have a queue and a
 * separate thread emptying it.
 */

typedef struct {
  protocol_ctxt_t ctxt_pP;
  srb_flag_t      srb_flagP;
  rb_id_t         rb_idP;
  mui_t           muiP;
  confirm_t       confirmP;
  sdu_size_t      sdu_sizeP;
  uint8_t *sdu_pP;
} rlc_data_req_queue_item;

#define RLC_DATA_REQ_QUEUE_SIZE 10000

typedef struct {
  rlc_data_req_queue_item q[RLC_DATA_REQ_QUEUE_SIZE];
  volatile int start;
  volatile int length;
  pthread_mutex_t m;
  pthread_cond_t c;
} rlc_data_req_queue;

static rlc_data_req_queue q;

static void *rlc_data_req_thread(void *_)
{
  int i;

  pthread_setname_np(pthread_self(), "RLC queue");
  while (1) {
    if (pthread_mutex_lock(&q.m) != 0) abort();
    while (q.length == 0)
      if (pthread_cond_wait(&q.c, &q.m) != 0) abort();
    i = q.start;
    if (pthread_mutex_unlock(&q.m) != 0) abort();

    nr_rlc_data_req(&q.q[i].ctxt_pP,
                    q.q[i].srb_flagP,
                    q.q[i].rb_idP,
                    q.q[i].muiP,
                    q.q[i].sdu_sizeP,
                    q.q[i].sdu_pP);

    if (pthread_mutex_lock(&q.m) != 0) abort();

    q.length--;
    q.start = (q.start + 1) % RLC_DATA_REQ_QUEUE_SIZE;

    if (pthread_cond_signal(&q.c) != 0) abort();
    if (pthread_mutex_unlock(&q.m) != 0) abort();
  }
}

static void init_nr_rlc_data_req_queue(void)
{
  pthread_t t;

  pthread_mutex_init(&q.m, NULL);
  pthread_cond_init(&q.c, NULL);

  if (pthread_create(&t, NULL, rlc_data_req_thread, NULL) != 0) {
    LOG_E(PDCP, "%s:%d:%s: fatal\n", __FILE__, __LINE__, __FUNCTION__);
    exit(1);
  }
}

static void enqueue_rlc_data_req(const protocol_ctxt_t *const ctxt_pP,
                                 const srb_flag_t srb_flagP,
                                 const rb_id_t rb_idP,
                                 const mui_t muiP,
                                 confirm_t confirmP,
                                 sdu_size_t sdu_sizeP,
                                 uint8_t *sdu_pP)
{
  int i;
  int logged = 0;

  if (pthread_mutex_lock(&q.m) != 0) abort();
  while (q.length == RLC_DATA_REQ_QUEUE_SIZE) {
    if (!logged) {
      logged = 1;
      LOG_W(PDCP, "%s: rlc_data_req queue is full\n", __FUNCTION__);
    }
    if (pthread_cond_wait(&q.c, &q.m) != 0) abort();
  }

  i = (q.start + q.length) % RLC_DATA_REQ_QUEUE_SIZE;
  q.length++;

  q.q[i].ctxt_pP    = *ctxt_pP;
  q.q[i].srb_flagP  = srb_flagP;
  q.q[i].rb_idP     = rb_idP;
  q.q[i].muiP       = muiP;
  q.q[i].confirmP   = confirmP;
  q.q[i].sdu_sizeP  = sdu_sizeP;
  q.q[i].sdu_pP     = sdu_pP;

  if (pthread_cond_signal(&q.c) != 0) abort();
  if (pthread_mutex_unlock(&q.m) != 0) abort();
}

/****************************************************************************/
/* rlc_data_req queue - end                                                 */
/****************************************************************************/

/****************************************************************************/
/* pdcp_data_ind thread - begin                                             */
/****************************************************************************/

typedef struct {
  protocol_ctxt_t ctxt_pP;
  srb_flag_t      srb_flagP;
  rb_id_t         rb_id;
  sdu_size_t      sdu_buffer_size;
  uint8_t *sdu_buffer;
} pdcp_data_ind_queue_item;

#define PDCP_DATA_IND_QUEUE_SIZE 10000

typedef struct {
  pdcp_data_ind_queue_item q[PDCP_DATA_IND_QUEUE_SIZE];
  volatile int start;
  volatile int length;
  pthread_mutex_t m;
  pthread_cond_t c;
} pdcp_data_ind_queue;

static pdcp_data_ind_queue pq;

static void do_pdcp_data_ind(const protocol_ctxt_t *const ctxt_pP,
                             const srb_flag_t srb_flagP,
                             const rb_id_t rb_id,
                             const sdu_size_t sdu_buffer_size,
                             uint8_t *const sdu_buffer)
{
  nr_pdcp_ue_t *ue;
  nr_pdcp_entity_t *rb;
  ue_id_t UEid = ctxt_pP->rntiMaybeUEid;

  if (ctxt_pP->module_id != 0 ||
      //ctxt_pP->enb_flag != 1 ||
      ctxt_pP->instance != 0 ||
      ctxt_pP->eNB_index != 0 ||
      ctxt_pP->brOption != 0) {
    LOG_E(PDCP, "%s:%d:%s: fatal\n", __FILE__, __LINE__, __FUNCTION__);
    exit(1);
  }

  if (ctxt_pP->enb_flag)
    T(T_ENB_PDCP_UL, T_INT(ctxt_pP->module_id), T_INT(UEid), T_INT(rb_id), T_INT(sdu_buffer_size));

  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, UEid);
  rb = nr_pdcp_get_rb(ue, rb_id, srb_flagP);

  if (rb != NULL) {
    rb->recv_pdu(rb, (char *)sdu_buffer, sdu_buffer_size);
  } else {
    LOG_E(PDCP, "pdcp_data_ind: no RB found (rb_id %ld, srb_flag %d)\n", rb_id, srb_flagP);
  }

  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);

  free(sdu_buffer);
}

static void *pdcp_data_ind_thread(void *_)
{
  int i;

  pthread_setname_np(pthread_self(), "PDCP data ind");
  while (1) {
    if (pthread_mutex_lock(&pq.m) != 0) abort();
    while (pq.length == 0)
      if (pthread_cond_wait(&pq.c, &pq.m) != 0) abort();
    i = pq.start;
    if (pthread_mutex_unlock(&pq.m) != 0) abort();

    do_pdcp_data_ind(&pq.q[i].ctxt_pP,
                     pq.q[i].srb_flagP,
                     pq.q[i].rb_id,
                     pq.q[i].sdu_buffer_size,
                     pq.q[i].sdu_buffer);

    if (pthread_mutex_lock(&pq.m) != 0) abort();

    pq.length--;
    pq.start = (pq.start + 1) % PDCP_DATA_IND_QUEUE_SIZE;

    if (pthread_cond_signal(&pq.c) != 0) abort();
    if (pthread_mutex_unlock(&pq.m) != 0) abort();
  }
}

static void init_nr_pdcp_data_ind_queue(void)
{
  pthread_t t;

  pthread_mutex_init(&pq.m, NULL);
  pthread_cond_init(&pq.c, NULL);

  if (pthread_create(&t, NULL, pdcp_data_ind_thread, NULL) != 0) {
    LOG_E(PDCP, "%s:%d:%s: fatal\n", __FILE__, __LINE__, __FUNCTION__);
    exit(1);
  }
}

static void enqueue_pdcp_data_ind(const protocol_ctxt_t *const ctxt_pP,
                                  const srb_flag_t srb_flagP,
                                  const rb_id_t rb_id,
                                  const sdu_size_t sdu_buffer_size,
                                  uint8_t *const sdu_buffer)
{
  int i;
  int logged = 0;

  if (pthread_mutex_lock(&pq.m) != 0) abort();
  while (pq.length == PDCP_DATA_IND_QUEUE_SIZE) {
    if (!logged) {
      logged = 1;
      LOG_W(PDCP, "%s: pdcp_data_ind queue is full\n", __FUNCTION__);
    }
    if (pthread_cond_wait(&pq.c, &pq.m) != 0) abort();
  }

  i = (pq.start + pq.length) % PDCP_DATA_IND_QUEUE_SIZE;
  pq.length++;

  pq.q[i].ctxt_pP         = *ctxt_pP;
  pq.q[i].srb_flagP       = srb_flagP;
  pq.q[i].rb_id           = rb_id;
  pq.q[i].sdu_buffer_size = sdu_buffer_size;
  pq.q[i].sdu_buffer      = sdu_buffer;

  if (pthread_cond_signal(&pq.c) != 0) abort();
  if (pthread_mutex_unlock(&pq.m) != 0) abort();
}

bool nr_pdcp_data_ind(const protocol_ctxt_t *const ctxt_pP,
                      const srb_flag_t srb_flagP,
                      const rb_id_t rb_id,
                      const sdu_size_t sdu_buffer_size,
                      uint8_t *const sdu_buffer)
{
  enqueue_pdcp_data_ind(ctxt_pP, srb_flagP, rb_id, sdu_buffer_size, sdu_buffer);
  return true;
}

/****************************************************************************/
/* pdcp_data_ind thread - end                                               */
/****************************************************************************/

int pdcp_fifo_flush_sdus(const protocol_ctxt_t *const ctxt_pP)
{
  return 0;
}

static void set_node_type() {
  node_type = get_node_type();
}

void nr_pdcp_layer_init(void)
{
  /* hack: be sure to initialize only once */
  static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
  static int initialized = 0;
  if (pthread_mutex_lock(&m) != 0) abort();
  if (initialized) {
    if (pthread_mutex_unlock(&m) != 0) abort();
    return;
  }
  initialized = 1;
  if (pthread_mutex_unlock(&m) != 0) abort();

  nr_pdcp_ue_manager = new_nr_pdcp_ue_manager(1);

  set_node_type();

  if ((RC.nrrrc == NULL) || (!NODE_IS_CU(node_type))) {
    init_nr_rlc_data_req_queue();
  }
  nr_pdcp_e1_if_init(node_type == ngran_gNB_CUUP || node_type == ngran_gNB_CUCP);
  init_nr_pdcp_data_ind_queue();
  nr_pdcp_init_timer_thread(nr_pdcp_ue_manager);
}

#include "nfapi/oai_integration/vendor_ext.h"
#include "executables/lte-softmodem.h"
#include "common/utils/tun_if.h"
#include "openair2/SDAP/nr_sdap/nr_sdap.h"

// 여기에 Hook 함수를 작성하면 복호화가 끝난 Header+SDU가 전달됨 따라서 header확인 가능 by inho
// 상위 layer로 SDU 전달하는 콜백 함수 by inho
static void deliver_sdu_drb(void *_ue, nr_pdcp_entity_t *entity,
                            char *buf, int size,
                            const nr_pdcp_integrity_data_t *msg_integrity)
{
  nr_pdcp_ue_t *ue = _ue;
  int rb_id;
  int i;
  uint8_t qfi = 0;  // QFI 기본값 0 (SDAP 헤더 없음)

  // SDAP 헤더가 있으면 QFI 추출
  if (entity->has_sdap_rx && size > 0) {
    // SDAP UL 헤더: R(1bit) DC(1bit) QFI(6bits)
    qfi = ((uint8_t *)buf)[0] & 0x3F;
    LOG_D(PDCP, "Extracted QFI from SDAP header: %u\n", qfi);
  }

#if defined(JBPF_HOOK) && !defined(NR_UE)
  /*
   * JBPF Hook - PDCP Uplink
   * 위치: PDCP 복호화 완료 후
   * 철학: Application은 최소 코드만, 모든 분석은 Codelet에 위임
   */

  if (!jbpf_pdcp_thread_registered) {
    jbpf_register_thread();
    jbpf_pdcp_thread_registered = 1;
    LOG_I(PDCP, "[JBPF] Registered PDCP thread %ld\n", pthread_self());
  }

  hook_pdcp_uplink((uint8_t*)buf, size, entity, ue);

#endif  // JBPF_HOOK && !NR_UE

  if (IS_SOFTMODEM_NOS1 || UE_NAS_USE_TUN) {
    LOG_D(PDCP, "IP packet received with size %d, to be sent to SDAP interface, UE ID/RNTI: %ld\n", size, ue->ue_id);
    // in NoS1 mode: the SDAP should write() packets to an FD (TUN interface),
    // so below, set is_gnb == 0 to do that
    sdap_data_ind(entity->rb_id, 0, entity->has_sdap_rx, qfi, entity->pdusession_id, ue->ue_id, buf, size);
  }
  else{
    for (i = 0; i < MAX_DRBS_PER_UE; i++) {
        if (entity == ue->drb[i]) {
          rb_id = i+1;
          goto rb_found;
        }
      }

      LOG_E(PDCP, "%s:%d:%s: fatal, no RB found for UE ID/RNTI %ld\n", __FILE__, __LINE__, __FUNCTION__, ue->ue_id);
      exit(1);

    rb_found:
    {
      LOG_D(PDCP, "%s() (drb %d) sending message to SDAP size %d\n", __func__, rb_id, size);
      sdap_data_ind(rb_id,   /// Radio Bearer ID
                    ue->drb[rb_id - 1]->is_gnb,  
                    ue->drb[rb_id - 1]->has_sdap_rx,
                    qfi,
                    ue->drb[rb_id - 1]->pdusession_id,
                    ue->ue_id,
                    buf,
                    size);
    }
  }
}

static void deliver_pdu_drb_ue(void *deliver_pdu_data, ue_id_t ue_id, int rb_id,
                               char *buf, int size, int sdu_id)
{
  DevAssert(deliver_pdu_data == NULL);
  protocol_ctxt_t ctxt = { .enb_flag = 0, .rntiMaybeUEid = ue_id };

  uint8_t *memblock = malloc16(size);
  memcpy(memblock, buf, size);
  LOG_D(PDCP, "%s(): (drb %d) calling rlc_data_req size %d UE %ld/%04lx\n", __func__, rb_id, size, ctxt.rntiMaybeUEid, ctxt.rntiMaybeUEid);
  enqueue_rlc_data_req(&ctxt, 0, rb_id, sdu_id, 0, size, memblock);
}

static void deliver_pdu_drb_gnb(void *deliver_pdu_data, ue_id_t ue_id, int rb_id,
                                char *buf, int size, int sdu_id)
{
  DevAssert(deliver_pdu_data == NULL);
  f1_ue_data_t ue_data = cu_get_f1_ue_data(ue_id);
  protocol_ctxt_t ctxt = { .enb_flag = 1, .rntiMaybeUEid = ue_data.secondary_ue };

  if (NODE_IS_CU(node_type)) {
    LOG_D(PDCP, "%s() (drb %d) sending message to gtp size %d\n", __func__, rb_id, size);
    extern instance_t CUuniqInstance;
    gtpv1uSendDirectWithNRUSeqNum(CUuniqInstance, ue_id, rb_id, (uint8_t *)buf, size);
  } else {
    uint8_t *memblock = malloc16(size);
    memcpy(memblock, buf, size);
    LOG_D(PDCP, "%s(): (drb %d) calling rlc_data_req size %d\n", __func__, rb_id, size);
    enqueue_rlc_data_req(&ctxt, 0, rb_id, sdu_id, 0, size, memblock);
  }
}


static void deliver_sdu_srb(void *_ue, nr_pdcp_entity_t *entity,
                            char *buf, int size,
                            const nr_pdcp_integrity_data_t *msg_integrity)
{
  nr_pdcp_ue_t *ue = _ue;
  int srb_id;
  int i;

  for (i = 0; i < sizeofArray(ue->srb) ; i++) {
    if (entity == ue->srb[i]) {
      srb_id = i+1;
      goto srb_found;
    }
  }

  LOG_E(PDCP, "%s:%d:%s: fatal, no SRB found for UE ID/RNTI %ld\n", __FILE__, __LINE__, __FUNCTION__, ue->ue_id);
  exit(1);

srb_found:
  if (entity->is_gnb) {
    MessageDef *message_p = itti_alloc_new_message(TASK_PDCP_GNB, 0, F1AP_UL_RRC_MESSAGE);
    AssertFatal(message_p != NULL, "OUT OF MEMORY\n");
    f1ap_ul_rrc_message_t *ul_rrc = &F1AP_UL_RRC_MESSAGE(message_p);
    ul_rrc->gNB_CU_ue_id = ue->ue_id;
    /* look up the correct secondary UE ID to provide complete information to
     * RRC, the RLC-PDCP interface does not transport this information */
    f1_ue_data_t ue_data = cu_get_f1_ue_data(ue->ue_id);
    ul_rrc->gNB_DU_ue_id = ue_data.secondary_ue;
    ul_rrc->srb_id = srb_id;
    ul_rrc->rrc_container = malloc(size);
    AssertFatal(ul_rrc->rrc_container != NULL, "OUT OF MEMORY\n");
    memcpy(ul_rrc->rrc_container, buf, size);
    ul_rrc->rrc_container_length = size;
    itti_send_msg_to_task(TASK_RRC_GNB, 0, message_p);
  } else {
    uint8_t *rrc_buffer_p = itti_malloc(TASK_PDCP_UE, TASK_RRC_NRUE, size);
    AssertFatal(rrc_buffer_p != NULL, "OUT OF MEMORY\n");
    memcpy(rrc_buffer_p, buf, size);
    MessageDef *message_p = itti_alloc_new_message(TASK_PDCP_UE, 0, NR_RRC_DCCH_DATA_IND);
    AssertFatal(message_p != NULL, "OUT OF MEMORY\n");
    NR_RRC_DCCH_DATA_IND(message_p).dcch_index = srb_id;
    NR_RRC_DCCH_DATA_IND(message_p).sdu_p = rrc_buffer_p;
    NR_RRC_DCCH_DATA_IND(message_p).sdu_size = size;
    memcpy(&NR_RRC_DCCH_DATA_IND(message_p).msg_integrity, msg_integrity, sizeof(*msg_integrity));
    ue_id_t ue_id = ue->ue_id;
    itti_send_msg_to_task(TASK_RRC_NRUE, ue_id, message_p);
  }
}

void deliver_pdu_srb_rlc(void *deliver_pdu_data, ue_id_t ue_id, int srb_id,
                         char *buf, int size, int sdu_id)
{
  protocol_ctxt_t ctxt = { .enb_flag = 1, .rntiMaybeUEid = ue_id };
  uint8_t *memblock = malloc16(size);
  memcpy(memblock, buf, size);
  enqueue_rlc_data_req(&ctxt, 1, srb_id, sdu_id, 0, size, memblock);
}

void add_srb(int is_gnb,
             ue_id_t UEid,
             struct NR_SRB_ToAddMod *s,
             const nr_pdcp_entity_security_keys_and_algos_t *security_parameters)
{
  nr_pdcp_entity_t *pdcp_srb;
  nr_pdcp_ue_t *ue;

  int srb_id = s->srb_Identity;
  int t_Reordering = -1; // infinity as per default SRB configuration in 9.2.1 of 38.331
  if (s->pdcp_Config != NULL && s->pdcp_Config->t_Reordering != NULL)
    t_Reordering = decode_t_reordering(*s->pdcp_Config->t_Reordering);

  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, UEid);
  if (nr_pdcp_get_rb(ue, srb_id, true) != NULL) {
    LOG_E(PDCP, "warning SRB %d already exist for UE ID %ld, do nothing\n", srb_id, UEid);
  } else {
    pdcp_srb = new_nr_pdcp_entity(NR_PDCP_SRB,
                                  is_gnb,
                                  srb_id,
                                  0,      // PDU session ID (not relevant)
                                  false,  // has SDAP RX (not relevant)
                                  false,  // has SDAP TX (not relevant)
                                  deliver_sdu_srb,
                                  ue,
                                  NULL,
                                  ue,
                                  SHORT_SN_SIZE,
                                  t_Reordering,
                                  -1,
                                  security_parameters);
    nr_pdcp_ue_add_srb_pdcp_entity(ue, srb_id, pdcp_srb);

    LOG_D(PDCP, "added srb %d to UE ID %ld\n", srb_id, UEid);
  }
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

void nr_pdcp_add_drb(int is_gnb,
                     const ue_id_t UEid,
                     const NR_PDCP_Config_t *pdcp,
                     const sdap_config_t *sdap,
                     const nr_pdcp_entity_security_keys_and_algos_t *security_parameters)
{
  nr_pdcp_ue_t *ue;

  if (!pdcp->drb) {
    LOG_E(PDCP, "Missing PDCP config. DRB %d not configured.\n", sdap->drb_id);
    return;
  }

  struct NR_PDCP_Config__drb *drb = pdcp->drb;
  int sn_size_ul = decode_sn_size_ul(*drb->pdcp_SN_SizeUL);
  int sn_size_dl = decode_sn_size_dl(*drb->pdcp_SN_SizeDL);
  int discard_timer = decode_discard_timer(*drb->discardTimer);

  /* if pdcp_Config->t_Reordering is not present, it means infinity (-1) */
  int t_reordering = -1;
  if (pdcp->t_Reordering != NULL) {
    t_reordering = decode_t_reordering(*pdcp->t_Reordering);
  }

  int has_integrity = (drb->integrityProtection != NULL) ? 1 : 0;
  int has_ciphering = (pdcp->ext1 != NULL && pdcp->ext1->cipheringDisabled != NULL) ? 0 : 1;

  /* get actual ciphering and integrity algorithm based on pdcp_Config */
  nr_pdcp_entity_security_keys_and_algos_t actual_security_parameters = *security_parameters;
  actual_security_parameters.ciphering_algorithm = has_ciphering ? security_parameters->ciphering_algorithm : 0;
  actual_security_parameters.integrity_algorithm = has_integrity ? security_parameters->integrity_algorithm : 0;

  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, UEid);
  if (nr_pdcp_get_rb(ue, sdap->drb_id, false) != NULL) {
    LOG_W(PDCP, "warning DRB %d already exist for UE ID %ld, do nothing\n", sdap->drb_id, UEid);
  } else {
    // code assumption: same SN size for both DL and UL
    if (sn_size_ul != sn_size_dl) {
      LOG_E(PDCP, "fatal, bad SN sizes, must be same. ul=%d, dl=%d\n", sn_size_ul, sn_size_dl);
      exit(1);
    }

    // add PDCP entity
    nr_pdcp_entity_t *pdcp_drb = new_nr_pdcp_entity(NR_PDCP_DRB_AM,
                                                    is_gnb,
                                                    sdap->drb_id,
                                                    sdap->pdusession_id,
                                                    (sdap->role & (SDAP_UL_RX | SDAP_DL_RX)) != 0,
                                                    (sdap->role & (SDAP_UL_TX | SDAP_DL_TX)) != 0,
                                                    deliver_sdu_drb,
                                                    ue,
                                                    is_gnb ? deliver_pdu_drb_gnb : deliver_pdu_drb_ue,
                                                    ue,
                                                    sn_size_dl,
                                                    t_reordering,
                                                    discard_timer,
                                                    &actual_security_parameters);
    nr_pdcp_ue_add_drb_pdcp_entity(ue, sdap->drb_id, pdcp_drb);

    LOG_I(PDCP, "Added DRB %d to UE ID %ld\n", sdap->drb_id, UEid);
  }
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

void nr_pdcp_add_srbs(eNB_flag_t enb_flag,
                      ue_id_t UEid,
                      NR_SRB_ToAddModList_t *const srb2add_list,
                      const nr_pdcp_entity_security_keys_and_algos_t *security_parameters)
{
  if (srb2add_list != NULL) {
    for (int i = 0; i < srb2add_list->list.count; i++) {
      add_srb(enb_flag, UEid, srb2add_list->list.array[i], security_parameters);
    }
  } else
    LOG_W(PDCP, "nr_pdcp_add_srbs() with void list\n");
}

uint64_t get_pdcp_optmask(void)
{
  return pdcp_optmask;
}

void nr_pdcp_remove_UE(ue_id_t ue_id)
{
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  nr_pdcp_manager_remove_ue(nr_pdcp_ue_manager, ue_id);
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

void nr_pdcp_config_set_security(ue_id_t ue_id,
                                 rb_id_t rb_id,
                                 bool is_srb,
                                 const nr_pdcp_entity_security_keys_and_algos_t *parameters)
{
  nr_pdcp_ue_t *ue;
  nr_pdcp_entity_t *rb;

  nr_pdcp_manager_lock(nr_pdcp_ue_manager);

  ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);

  rb = nr_pdcp_get_rb(ue, rb_id, is_srb);

  if (rb == NULL) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    LOG_E(PDCP, "no %s found (ue_id %ld, rb_id %ld)\n", is_srb ? "SRB" : "DRB", ue_id, rb_id);
    return;
  }

  rb->set_security(rb, parameters);

  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

bool nr_pdcp_check_integrity_srb(ue_id_t ue_id,
                                 int srb_id,
                                 const uint8_t *msg,
                                 int msg_size,
                                 const nr_pdcp_integrity_data_t *msg_integrity)
{
  nr_pdcp_ue_t *ue;
  nr_pdcp_entity_t *rb;

  nr_pdcp_manager_lock(nr_pdcp_ue_manager);

  ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);

  rb = nr_pdcp_get_rb(ue, srb_id, true);

  if (rb == NULL) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    LOG_E(PDCP, "no SRB found (ue_id %ld, rb_id %d)\n", ue_id, srb_id);
    return false;
  }

  bool ret = rb->check_integrity(rb, msg, msg_size, msg_integrity);

  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);

  return ret;
}

bool nr_pdcp_data_req_srb(ue_id_t ue_id,
                          const rb_id_t rb_id,
                          const mui_t muiP,
                          const sdu_size_t sdu_buffer_size,
                          unsigned char *const sdu_buffer,
                          deliver_pdu deliver_pdu_cb,
                          void *data)
{
  LOG_D(PDCP, "%s() called, size %d\n", __func__, sdu_buffer_size);
  nr_pdcp_ue_t *ue;
  nr_pdcp_entity_t *rb;

  nr_pdcp_manager_lock(nr_pdcp_ue_manager);

  ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  rb = nr_pdcp_get_rb(ue, rb_id, true);

  if (rb == NULL) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    LOG_E(PDCP, "no SRB found (ue_id %ld, rb_id %ld)\n", ue_id, rb_id);
    return 0;
  }

  int max_size = nr_max_pdcp_pdu_size(sdu_buffer_size);
  char pdu_buf[max_size];
  int pdu_size = rb->process_sdu(rb, (char *)sdu_buffer, sdu_buffer_size, muiP, pdu_buf, max_size);
  if (pdu_size == -1) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    return 0;
  }
  AssertFatal(rb->deliver_pdu == NULL, "SRB callback should be NULL, to be provided on every invocation\n");

  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);

  deliver_pdu_cb(data, ue_id, rb_id, pdu_buf, pdu_size, muiP);

  return 1;
}

void nr_pdcp_suspend_srb(ue_id_t ue_id, int srb_id)
{
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  nr_pdcp_ue_t *ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  nr_pdcp_entity_t *srb = nr_pdcp_get_rb(ue, srb_id, true);
  if (srb == NULL) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    LOG_E(PDCP, "Trying to suspend SRB with ID %d but it is not established\n", srb_id);
    return;
  }
  srb->suspend_entity(srb);
  LOG_D(PDCP, "SRB %d suspended\n", srb_id);
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

void nr_pdcp_suspend_drb(ue_id_t ue_id, int drb_id)
{
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  nr_pdcp_ue_t *ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  nr_pdcp_entity_t *drb = nr_pdcp_get_rb(ue, drb_id, false);
  if (drb == NULL) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    LOG_E(PDCP, "Trying to suspend DRB with ID %d but it is not established\n", drb_id);
    return;
  }
  drb->suspend_entity(drb);
  LOG_D(PDCP, "DRB %d suspended\n", drb_id);
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

void nr_pdcp_reconfigure_srb(ue_id_t ue_id, int srb_id, long t_Reordering)
{
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  nr_pdcp_ue_t *ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  nr_pdcp_entity_t *srb = nr_pdcp_get_rb(ue, srb_id, true);
  if (srb == NULL) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    LOG_E(PDCP, "Trying to reconfigure SRB with ID %d but it is not established\n", srb_id);
    return;
  }
  int decoded_t_reordering = decode_t_reordering(t_Reordering);
  srb->t_reordering = decoded_t_reordering;
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

void nr_pdcp_reconfigure_drb(ue_id_t ue_id, int drb_id, NR_PDCP_Config_t *pdcp_config)
{
  // The enabling/disabling of ciphering or integrity protection
  // can be changed only by releasing and adding the DRB
  // (so not by reconfiguring).
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  nr_pdcp_ue_t *ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  nr_pdcp_entity_t *drb = nr_pdcp_get_rb(ue, drb_id, false);
  if (drb == NULL) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    LOG_E(PDCP, "Trying to reconfigure DRB with ID %d but it is not established\n", drb_id);
    return;
  }
  if (pdcp_config) {
    if (pdcp_config->t_Reordering)
      drb->t_reordering = decode_t_reordering(*pdcp_config->t_Reordering);
    else
      drb->t_reordering = -1;
    struct NR_PDCP_Config__drb *drb_config = pdcp_config->drb;
    if (drb_config) {
      if (drb_config->discardTimer)
        drb->discard_timer = decode_discard_timer(*drb_config->discardTimer);
      bool size_set = false;
      if (drb_config->pdcp_SN_SizeUL) {
        drb->sn_size = decode_sn_size_ul(*drb_config->pdcp_SN_SizeUL);
        size_set = true;
      }
      if (drb_config->pdcp_SN_SizeDL) {
        int size = decode_sn_size_dl(*drb_config->pdcp_SN_SizeDL);
        AssertFatal(!size_set || (size == drb->sn_size),
                    "SN sizes must be the same. dl=%d, ul=%d",
                    size, drb->sn_size);
        drb->sn_size = size;
      }
    }
  }
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

void nr_pdcp_release_srb(ue_id_t ue_id, int srb_id)
{
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  nr_pdcp_ue_t *ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  if (ue->srb[srb_id - 1] != NULL) {
    ue->srb[srb_id - 1]->delete_entity(ue->srb[srb_id - 1]);
    ue->srb[srb_id - 1] = NULL;
  }
  else
    LOG_E(PDCP, "Attempting to release SRB%d but it is not configured\n", srb_id);
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

void nr_pdcp_release_drb(ue_id_t ue_id, int drb_id)
{
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  nr_pdcp_ue_t *ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  nr_pdcp_entity_t *drb = ue->drb[drb_id - 1];
  if (drb) {
    nr_sdap_release_drb(ue_id, drb_id, drb->pdusession_id);
    drb->release_entity(drb);
    drb->delete_entity(drb);
    ue->drb[drb_id - 1] = NULL;
    LOG_I(PDCP, "release DRB %d of UE %ld\n", drb_id, ue_id);
  }
  else
    LOG_E(PDCP, "Attempting to release DRB%d but it is not configured\n", drb_id);
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

void nr_pdcp_reestablishment(ue_id_t ue_id,
                             int rb_id,
                             bool srb_flag,
                             const nr_pdcp_entity_security_keys_and_algos_t *security_parameters)
{
  nr_pdcp_ue_t     *ue;
  nr_pdcp_entity_t *rb;

  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  rb = nr_pdcp_get_rb(ue, rb_id, srb_flag);

  if (rb != NULL) {
    LOG_D(PDCP, "UE %4.4lx re-establishment of %sRB %d\n", ue_id, srb_flag ? "S" : "D", rb_id);
    rb->reestablish_entity(rb, security_parameters);
    LOG_I(PDCP, "%s %d re-established\n", srb_flag ? "SRB" : "DRB" , rb_id);
  } else {
    LOG_W(PDCP, "UE %4.4lx cannot re-establish %sRB %d, RB not found\n", ue_id, srb_flag ? "S" : "D", rb_id);
  }

  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

bool nr_pdcp_data_req_drb(protocol_ctxt_t *ctxt_pP,
                          const srb_flag_t srb_flagP,
                          const rb_id_t rb_id,
                          const mui_t muiP,
                          const confirm_t confirmP,
                          const sdu_size_t sdu_buffer_size,
                          unsigned char *const sdu_buffer,
                          const pdcp_transmission_mode_t mode,
                          const uint32_t *const sourceL2Id,
                          const uint32_t *const destinationL2Id)
{
  DevAssert(srb_flagP == SRB_FLAG_NO);

  LOG_D(PDCP, "%s() called, size %d\n", __func__, sdu_buffer_size);
  nr_pdcp_ue_t *ue;
  nr_pdcp_entity_t *rb;
  ue_id_t ue_id = ctxt_pP->rntiMaybeUEid;

  if (ctxt_pP->module_id != 0 ||
      //ctxt_pP->enb_flag != 1 ||
      ctxt_pP->instance != 0 ||
      ctxt_pP->eNB_index != 0 /*||
      ctxt_pP->configured != 1 ||
      ctxt_pP->brOption != 0*/) {
    LOG_E(PDCP, "%s:%d:%s: fatal\n", __FILE__, __LINE__, __FUNCTION__);
    exit(1);
  }

  nr_pdcp_manager_lock(nr_pdcp_ue_manager);

  ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  rb = nr_pdcp_get_rb(ue, rb_id, false);

  if (rb == NULL) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    LOG_E(PDCP, "[UE %lx] DRB %ld not found\n", ue_id, rb_id);
    return 0;
  }

  int max_size = nr_max_pdcp_pdu_size(sdu_buffer_size);
  char pdu_buf[max_size];
  int pdu_size = rb->process_sdu(rb, (char *)sdu_buffer, sdu_buffer_size, muiP, pdu_buf, max_size);
  if (pdu_size == -1) {
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    return 0;
  }

  deliver_pdu deliver_pdu_cb = rb->deliver_pdu;

  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);

  deliver_pdu_cb(NULL, ue_id, rb_id, pdu_buf, pdu_size, muiP);

  return 1;
}

bool cu_f1u_data_req(protocol_ctxt_t  *ctxt_pP,
                     const srb_flag_t srb_flagP,
                     const rb_id_t rb_id,
                     const mui_t muiP,
                     const confirm_t confirmP,
                     const sdu_size_t sdu_buffer_size,
                     unsigned char *const sdu_buffer,
                     const pdcp_transmission_mode_t mode,
                     const uint32_t *const sourceL2Id,
                     const uint32_t *const destinationL2Id) {
  //Force instance id to 0, OAI incoherent instance management
  ctxt_pP->instance=0;
  uint8_t *memblock = malloc16(sdu_buffer_size);
  if (memblock == NULL) {
    LOG_E(RLC, "%s:%d:%s: ERROR: malloc16 failed\n", __FILE__, __LINE__, __FUNCTION__);
    exit(1);
  }
  memcpy(memblock, sdu_buffer, sdu_buffer_size);
  int ret = nr_pdcp_data_ind(ctxt_pP, srb_flagP, rb_id, sdu_buffer_size, memblock);
  if (!ret) {
    LOG_E(RLC, "%s:%d:%s: ERROR: pdcp_data_ind failed\n", __FILE__, __LINE__, __FUNCTION__);
    /* what to do in case of failure? for the moment: nothing */
  }
  return ret;
}

/*
 * For the SDAP API
 */
nr_pdcp_ue_manager_t *nr_pdcp_sdap_get_ue_manager() {
  return nr_pdcp_ue_manager;
}

/* returns false in case of error, true if everything ok */
bool nr_pdcp_get_statistics(ue_id_t ue_id, int srb_flag, int rb_id, nr_pdcp_statistics_t *out)
{
  nr_pdcp_ue_t     *ue;
  nr_pdcp_entity_t *rb;
  bool             ret;

  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  rb = nr_pdcp_get_rb(ue, rb_id, srb_flag);

  if (rb != NULL) {
    rb->get_stats(rb, out);
    ret = true;
  } else {
    ret = false;
  }

  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);

  return ret;
}

int nr_pdcp_get_num_ues(ue_id_t *ue_list, int len)
{
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);
  int num_ues = nr_pdcp_manager_get_ue_count(nr_pdcp_ue_manager);
  nr_pdcp_ue_t **nr_pdcp_ue_list = nr_pdcp_manager_get_ue_list(nr_pdcp_ue_manager);
  for (int i = 0; i < num_ues && i < len; i++)
    ue_list[i] = nr_pdcp_ue_list[i]->ue_id;
  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
  
  return num_ues;
}

void nr_pdcp_count_update(ue_id_t ue_id,
                          rb_id_t drb_id,
                          nr_pdcp_count_t dl_count,
                          nr_pdcp_count_t ul_count,
                          int sn_size)
{
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);

  nr_pdcp_ue_t *ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);
  if (ue == NULL) {
    LOG_E(PDCP, "UE %ld not found in PDCP manager\n", ue_id);
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    return;
  }

  nr_pdcp_entity_t *entity = nr_pdcp_get_rb(ue, drb_id, false);
  if (entity == NULL) {
    LOG_E(PDCP, "No PDCP entity found for UE %ld DRB %ld\n", ue_id, drb_id);
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    return;
  }

  entity->set_pdcp_count_dl(entity, dl_count, sn_size);
  entity->set_pdcp_count_ul(entity, ul_count, sn_size);

  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}

/** * @brief Get PDCP COUNT values (PDCP-SN and HFN) for UL and DL from the PDCP entity
 * @param[in]  ue_id          Unique UE ID
 * @param[in]  rb_id          Radio Bearer ID
 * @param[out] ul_count       UL PDCP count (SN, HFN)
 * @param[out] dl_count       DL PDCP count (SN, HFN)
 */
void nr_pdcp_get_drb_count_values(ue_id_t ue_id, rb_id_t rb_id, nr_pdcp_count_t *ul_count, nr_pdcp_count_t *dl_count)
{
  nr_pdcp_manager_lock(nr_pdcp_ue_manager);

  nr_pdcp_ue_t *ue = nr_pdcp_manager_get_ue(nr_pdcp_ue_manager, ue_id);

  nr_pdcp_entity_t *entity = nr_pdcp_get_rb(ue, rb_id, false);

  if (!entity) {
    LOG_E(PDCP, "No entity found (DRB %ld)\n", rb_id);
    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
    return;
  }

  *dl_count = entity->get_pdcp_count_dl(entity);
  *ul_count = entity->get_pdcp_count_ul(entity);

  nr_pdcp_manager_unlock(nr_pdcp_ue_manager);
}
