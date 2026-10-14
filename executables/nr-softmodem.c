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


#define _GNU_SOURCE             /* See feature_test_macros(7) */

#include "common/config/config_userapi.h"
#include "common/utils/load_module_shlib.h"
#ifdef SMBV
#include "PHY/TOOLS/smbv.h"
unsigned short config_frames[4] = {2,9,11,13};
#endif
#include "common/utils/time_manager/time_manager.h"
#ifdef ENABLE_AERIAL
#include "nfapi/oai_integration/aerial/fapi_nvIPC.h"
#endif
#ifdef E2_AGENT
#include "openair2/E2AP/flexric/src/agent/e2_agent_api.h"
#include "openair2/E2AP/RAN_FUNCTION/init_ran_func.h"
#endif
#ifdef JBPF_HOOK
#include "jbpf.h"
#include "jbpf_io_channel.h"
#include "openair2/JBPF/codelets/common.h"  // struct Packet5Tuple 정의

/*
 * QoS weight 시스템 헤더 두 개:
 *   qos_weight_msg.h : 코드릿이 push 한 WeightUpdate wire format
 *   qos_weight.h     : 호스트 측 테이블 API (qos_weight_apply / lookup)
 *
 * 이 두 헤더는 짝으로 다닌다. wire 메시지를 받아서 host 테이블에 반영.
 */
#include "openair2/JBPF/qos_weight_msg.h"
#include "openair2/JBPF/qos_weight.h"

/*
 * f1ap_ids.h 는 du_get_f1_ue_data() / du_exists_f1_ue_data() 를 노출.
 * 이 두 함수가 *MAC RNTI → CU-UE-ID* 매핑 (DU side registry) 을 들고 있어서
 * codelet 에서 받은 CU-UE-ID 로 MAC RNTI 를 역추적할 때 필요하다.
 */
#include "openair2/F1AP/f1ap_ids.h"

/*
 * Codelet 구조체 정의
 * 주의: 이 구조체들은 Codelet 파일의 정의와 정확히 일치해야 합니다!
 *
 * C 메모리 레이아웃 개념:
 * - 구조체 필드는 선언 순서대로 메모리에 배치됨
 * - CPU 효율을 위해 "정렬(Alignment)" 발생
 * - 예: uint64_t는 8바이트 경계에 배치되어야 함
 */

/*
 * UE별 패킷 통계
 * sdap_packet_stats.c 파일의 struct packet_stats와 동일
 */
struct packet_stats {
    uint64_t rx_packets;      // 수신 패킷 수 (8 bytes, offset 0)
    uint64_t rx_bytes;        // 수신 바이트 수 (8 bytes, offset 8)
    uint64_t last_timestamp;  // 마지막 패킷 타임스탬프 (8 bytes, offset 16)
};
// sizeof(struct packet_stats) = 24 bytes

/*
 * QFI별 트래픽 통계
 * sdap_qfi_classifier.c 파일의 struct qfi_stats와 동일
 */
struct qfi_stats {
    uint32_t ue_id;           // UE 식별자 (4 bytes, offset 0)
    uint8_t qfi;              // QoS Flow Identifier (1 byte, offset 4)
    uint8_t padding[3];       // 정렬을 위한 패딩 (3 bytes, offset 5)
    uint64_t packet_count;    // 패킷 수 (8 bytes, offset 8)
    uint64_t byte_count;      // 바이트 수 (8 bytes, offset 16)
};
// sizeof(struct qfi_stats) = 24 bytes

/*
 * 이전 통계 저장용 (Throughput 계산에 사용)
 *
 * static 키워드:
 * - 함수 호출 간에도 값이 유지됨 (전역 변수처럼)
 * - 하지만 이 파일 내에서만 접근 가능 (scope 제한)
 *
 * {0} 초기화:
 * - 모든 필드를 0으로 초기화
 * - prev_bytes = 0, prev_timestamp = 0, initialized = false
 */
static struct {
    uint64_t prev_bytes;      // 이전 바이트 수
    uint64_t prev_timestamp;  // 이전 타임스탬프
    bool initialized;         // 초기화 여부 (첫 샘플은 throughput 계산 불가)
} ue_prev_stats = {0};

/*
 * MAC 스케줄러 Codelet 출력 구조체
 *
 * 각 구조체는 대응하는 codelet 파일의 출력 구조체와 필드 순서/타입/크기가
 * 정확히 일치해야 한다. 불일치 시 잘못된 값을 읽게 된다.
 */

/* mac_dl_prb_stats.c: struct dl_prb_report와 동일 */
struct dl_prb_report {
    uint64_t timestamp;
    uint32_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint16_t rb_start;
    uint16_t rb_size;
    uint8_t  mcs;
    uint32_t tb_size;
    uint8_t  harq_pid;
    uint8_t  is_retx;
    uint32_t total_dl_bytes;
    uint32_t total_slots;
};

/* mac_ul_prb_stats.c: struct ul_prb_report와 동일 */
struct ul_prb_report {
    uint64_t timestamp;
    uint32_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint16_t rb_start;
    uint16_t rb_size;
    uint8_t  mcs;
    uint32_t tb_size;
    int32_t  buffer_bytes;
    uint8_t  harq_pid;
    uint8_t  is_retx;
    uint32_t total_ul_bytes;
    uint32_t total_slots;
    uint8_t  buffer_pressure_pct;
};

/* mac_bsr_monitor.c: struct bsr_report와 동일 */
struct bsr_report {
    uint64_t timestamp;
    uint32_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint8_t  bsr_type;
    uint32_t estimated_bytes;
    uint8_t  lcg_id;
    uint32_t bsr_count;
    uint32_t peak_bytes;
};

/* mac_sr_monitor.c: struct sr_report와 동일 */
struct sr_report {
    uint64_t timestamp;
    uint32_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint8_t  ul_cqi;
    uint32_t sr_count;
    uint32_t avg_ul_cqi;
};

/* mac_sr_packet_dump.c: struct sr_packet_frame와 동일
 *
 * 메모리 레이아웃 (24 bytes, 8-byte 정렬):
 *   [0..7]   ts_cycles    (uint64_t) - CPU rdtsc 타임스탬프
 *   [8..9]   rnti         (uint16_t) - UE 식별자
 *   [10..11] frame        (uint16_t) - 10ms 프레임 번호 (0~1023)
 *   [12]     slot         (uint8_t)  - 슬롯 번호 (SCS=30kHz → 0~19)
 *   [13]     sr_detected  (uint8_t)  - SR 유효 여부 (항상 1)
 *   [14]     ul_cqi       (uint8_t)  - PUCCH 수신 품질 (148=SNR 10dB)
 *   [15..19] _pad[5]      (uint8_t×5)- 정렬 패딩
 *   [20..23] seq_num      (uint32_t) - 전역 이벤트 시퀀스 번호 (0부터)
 */
struct sr_packet_frame {
    uint64_t ts_cycles;
    uint16_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint8_t  sr_detected;
    uint8_t  ul_cqi;
    uint8_t  _pad[5];
    uint32_t seq_num;
};

/* mac_bsr_packet_dump.c: struct bsr_packet_frame와 동일
 *
 * 메모리 레이아웃 (24 bytes, 8-byte 정렬):
 *   [0..7]   ts_cycles        (uint64_t) - CPU rdtsc 타임스탬프
 *   [8..9]   rnti             (uint16_t) - UE 식별자
 *   [10..11] frame            (uint16_t) - 10ms 프레임 번호
 *   [12]     slot             (uint8_t)  - 슬롯 번호
 *   [13]     bsr_type         (uint8_t)  - 0=Short BSR, 1=Long BSR
 *   [14]     lcg_id           (uint8_t)  - LCG ID (Long BSR: 0xFF)
 *   [15]     _pad             (uint8_t)  - 정렬 패딩
 *   [16..19] estimated_bytes  (uint32_t) - 추정 UL 버퍼 크기 (바이트)
 *   [20..23] seq_num          (uint32_t) - 전역 이벤트 시퀀스 번호
 *  * SR / BSR 패킷 덤프 핸들러
 *
 * mac_sr_packet_dump.c / mac_bsr_packet_dump.c 코드렛이
 * jbpf_ringbuf_output()으로 전송한 데이터를 수신하여
 * nr-softmodem 터미널에 ASCII 패킷 덤프 형태로 표시한다.
 *
 * 출력 형식 (Wireshark 스타일):
 *   +---(헤더)---+
 *   | FIELD TABLE |  ← 각 필드: 오프셋, 이름, Hex, Dec, 설명
 *   +---(구분)---+
 *   | HEX DUMP  |  ← 원시 바이트 (16진수 + ASCII)
 *   +-----------+
 *
 * 학습 포인트:
 *   1. 포인터 캐스팅: void* → 구조체 포인터 (안전한 캐스팅 조건 이해)
 *   2. 배열 접근: (uint8_t*)ptr로 구조체를 바이트 단위 접근
 *   3. 비트 연산: SNR 계산, 출력 가능 ASCII 판단
 *   4. 정수 산술: 부동소수 없이 소수점 표현 (×10 or ×100 스케일)
 * ============================================================ */

/*
 * 출력 구조체 정의 (mac_sr_packet_dump.c의 sr_packet_frame과 동일해야 함)
 *
 * 메모리 레이아웃:
 *   [0..7]  ts_cycles    (uint64_t, 8 bytes)
 *   [8..9]  rnti         (uint16_t, 2 bytes)
 *   [10..11] frame       (uint16_t, 2 bytes)
 *   [12]    slot         (uint8_t)
 *   [13]    sr_detected  (uint8_t)
 *   [14]    ul_cqi       (uint8_t)
 *   [15..19] _pad[5]     (uint8_t × 5)
 *   [20..23] seq_num     (uint32_t, 4 bytes)
 *   Total: 24 bytes
 */
struct bsr_packet_frame {
    uint64_t ts_cycles;
    uint16_t rnti;
    uint16_t frame;
    uint8_t  slot;
    uint8_t  bsr_type;
    uint8_t  lcg_id;
    uint8_t  _pad;
    uint32_t estimated_bytes;
    uint32_t seq_num;
};


#endif
#include "nr-softmodem.h"
#include <common/utils/assertions.h>
#include <openair2/GNB_APP/gnb_app.h>
#include <openair3/ocp-gtpu/gtp_itf.h>
#include <pthread.h>
#include <sched.h>
#include <simple_executable.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "LAYER2/nr_pdcp/nr_pdcp_oai_api.h"
#include "NR_PHY_INTERFACE/NR_IF_Module.h"
#include "LAYER2/NR_MAC_gNB/nr_mac_gNB.h"
#include "PHY/INIT/nr_phy_init.h"
#include "PHY/TOOLS/phy_scope_interface.h"
#include "PHY/defs_gNB.h"
#include "PHY/defs_nr_common.h"
#include "PHY/phy_vars.h"
#include "RRC/NR/nr_rrc_defs.h"
#include "RRC/NR/nr_rrc_proto.h"
#include "RRC_nr_paramsvalues.h"
#include "SIMULATION/TOOLS/sim.h"
#include "T.h"
#include "UTIL/OPT/opt.h"
#include "common/config/config_userapi.h"
#include "common/ngran_types.h"
#include "common/oai_version.h"
#include "common/ran_context.h"
#include "common/utils/LOG/log.h"
#include "e1ap_messages_types.h"
#include "executables/softmodem-common.h"
#include "gnb_config.h"
#include "gnb_paramdef.h"
#include "intertask_interface.h"
#include "nfapi/oai_integration/vendor_ext.h"
#include "nfapi_interface.h"
#include "nfapi_nr_interface_scf.h"
#include "ngap_gNB.h"
#include "nr-softmodem-common.h"
#include "openair2/E1AP/e1ap_common.h"
#include "pdcp.h"
#include "radio/COMMON/common_lib.h"
#include "s1ap_eNB.h"
#include "sctp_eNB_task.h"
#include "system.h"
#include "time_meas.h"
#include "utils.h"
#include "x2ap_eNB.h"
#include "openair1/SCHED_NR/sched_nr.h"
#include "openair2/SDAP/nr_sdap/nr_sdap.h"
pthread_cond_t nfapi_sync_cond;
pthread_mutex_t nfapi_sync_mutex;
int nfapi_sync_var=-1; //!< protected by mutex \ref nfapi_sync_mutex
THREAD_STRUCT thread_struct;
pthread_cond_t sync_cond;
pthread_mutex_t sync_mutex;
int sync_var=-1; //!< protected by mutex \ref sync_mutex.
int config_sync_var=-1;
int oai_exit = 0;

unsigned int mmapped_dma=0;

uint64_t downlink_frequency[MAX_NUM_CCs][4];
int32_t uplink_frequency_offset[MAX_NUM_CCs][4];
char *uecap_file;

runmode_t mode = normal_txrx;

#if MAX_NUM_CCs == 1
double tx_gain[MAX_NUM_CCs][4] = {{20,0,0,0}};
double rx_gain[MAX_NUM_CCs][4] = {{110,0,0,0}};
#else
double tx_gain[MAX_NUM_CCs][4] = {{20,0,0,0},{20,0,0,0}};
double rx_gain[MAX_NUM_CCs][4] = {{110,0,0,0},{20,0,0,0}};
#endif

double rx_gain_off = 0.0;

static int tx_max_power[MAX_NUM_CCs]; /* =  {0,0}*/;
int chain_offset = 0;
int numerology = 0;
double cpuf;

/* hack: pdcp_run() is required by 4G scheduler which is compiled into
 * nr-softmodem because of linker issues */
void pdcp_run(const protocol_ctxt_t *const ctxt_pP)
{
  abort();
}

/*------------------------------------------------------------------------*/

unsigned int build_rflocal(int txi, int txq, int rxi, int rxq) {
  return (txi + (txq<<6) + (rxi<<12) + (rxq<<18));
}
unsigned int build_rfdc(int dcoff_i_rxfe, int dcoff_q_rxfe) {
  return (dcoff_i_rxfe + (dcoff_q_rxfe<<8));
}


#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KBLU  "\x1B[34m"
#define RESET "\033[0m"

void exit_function(const char *file, const char *function, const int line, const char *s, const int assert)
{
  int ru_id;

  if (s != NULL) {
    printf("%s:%d %s() Exiting OAI softmodem: %s\n",file,line, function, s);
  }

  oai_exit = 1;

  if (RC.ru == NULL)
    exit(-1); // likely init not completed, prevent crash or hang, exit now...

  for (ru_id=0; ru_id<RC.nb_RU; ru_id++) {
    if (RC.ru[ru_id] && RC.ru[ru_id]->rfdevice.trx_end_func) {
      if (RC.ru[ru_id]->rfdevice.trx_get_stats_func) {
        RC.ru[ru_id]->rfdevice.trx_get_stats_func(&RC.ru[ru_id]->rfdevice);
        RC.ru[ru_id]->rfdevice.trx_get_stats_func = NULL;
      }
      RC.ru[ru_id]->rfdevice.trx_end_func(&RC.ru[ru_id]->rfdevice);
      RC.ru[ru_id]->rfdevice.trx_end_func = NULL;
    }

    if (RC.ru[ru_id] && RC.ru[ru_id]->ifdevice.trx_end_func) {
      if (RC.ru[ru_id]->ifdevice.trx_get_stats_func) {
        RC.ru[ru_id]->ifdevice.trx_get_stats_func(&RC.ru[ru_id]->ifdevice);
        RC.ru[ru_id]->ifdevice.trx_get_stats_func = NULL;
      }
      RC.ru[ru_id]->ifdevice.trx_end_func(&RC.ru[ru_id]->ifdevice);
      RC.ru[ru_id]->ifdevice.trx_end_func = NULL;
    }
  }

  if (assert) {
    abort();
  } else {
    sleep(1); // allow nr-softmodem threads to exit first
    exit(EXIT_SUCCESS);
  }
}

static int create_gNB_tasks(ngran_node_t node_type, configmodule_interface_t *cfg)
{
  uint32_t                        gnb_nb = RC.nb_nr_inst; 
  uint32_t                        gnb_id_start = 0;
  uint32_t                        gnb_id_end = gnb_id_start + gnb_nb;
  LOG_D(GNB_APP, "%s(gnb_nb:%d)\n", __FUNCTION__, gnb_nb);
  itti_wait_ready(1);
  LOG_D(PHY, "%s() Task ready initialize structures\n", __FUNCTION__);

#ifdef ENABLE_AERIAL
  AssertFatal(NFAPI_MODE == NFAPI_MODE_AERIAL,"Can only be run with '--nfapi AERIAL' when compiled with AERIAL support, if you want to run other (n)FAPI modes, please run ./build_oai without -w AERIAL");
#endif

  RCconfig_verify(cfg, node_type);

  if (RC.nb_nr_macrlc_inst > 0)
    RCconfig_nr_macrlc(cfg);

  if (RC.nb_nr_L1_inst>0) AssertFatal(l1_north_init_gNB()==0,"could not initialize L1 north interface\n");

  AssertFatal (gnb_nb <= RC.nb_nr_inst,
               "Number of gNB is greater than gNB defined in configuration file (%d/%d)!",
               gnb_nb, RC.nb_nr_inst);

  LOG_D(GNB_APP, "Allocating gNB_RRC_INST\n");
  RC.nrrrc = calloc(1, sizeof(*RC.nrrrc));
  RC.nrrrc[0] = RCconfig_NRRRC();

  if (node_type != ngran_gNB_DU) {
    // we start pdcp in both cuup (for drb) and cucp (for srb)
    nr_pdcp_layer_init();
  }

  if (get_softmodem_params()->nsa) { //&& !NODE_IS_DU(node_type)
	  LOG_I(X2AP, "X2AP enabled \n");
	  __attribute__((unused)) uint32_t x2_register_gnb_pending = gNB_app_register_x2 (gnb_id_start, gnb_id_end);
  }

  /* For the CU case the gNB registration with the AMF might have to take place after the F1 setup, as the PLMN info
     * can originate from the DU. Add check on whether x2ap is enabled to account for ENDC NSA scenario.*/
  if (IS_SA_MODE(get_softmodem_params()) && !NODE_IS_DU(node_type)) {
    /* Try to register each gNB */
    //registered_gnb = 0;
    __attribute__((unused)) uint32_t register_gnb_pending = gNB_app_register (gnb_id_start, gnb_id_end);
  }

  if (gnb_nb > 0) {
    if(itti_create_task(TASK_SCTP, sctp_eNB_task, NULL) < 0) {
      LOG_E(SCTP, "Create task for SCTP failed\n");
      return -1;
    }

    if (get_softmodem_params()->nsa) {
      if(itti_create_task(TASK_X2AP, x2ap_task, NULL) < 0) {
        LOG_E(X2AP, "Create task for X2AP failed\n");
      }
    } else {
      LOG_I(X2AP, "X2AP is disabled.\n");
    }
  }

  if (IS_SA_MODE(get_softmodem_params()) && !NODE_IS_DU(node_type)) {

    char*             gnb_ipv4_address_for_NGU      = NULL;
    uint32_t          gnb_port_for_NGU              = 0;
    char*             gnb_ipv4_address_for_S1U      = NULL;
    uint32_t          gnb_port_for_S1U              = 0;
    paramdef_t NETParams[]  =  GNBNETPARAMS_DESC;
    char aprefix[MAX_OPTNAME_SIZE*2 + 8];
    sprintf(aprefix,"%s.[%i].%s",GNB_CONFIG_STRING_GNB_LIST,0,GNB_CONFIG_STRING_NETWORK_INTERFACES_CONFIG);
    config_get(cfg, NETParams, sizeofArray(NETParams), aprefix);

    if (gnb_nb > 0) {
      if (itti_create_task (TASK_NGAP, ngap_gNB_task, NULL) < 0) {
        LOG_E(NGAP, "Create task for NGAP failed\n");
        return -1;
      }
    }
  }

  if (gnb_nb > 0) {
    if (!NODE_IS_DU(node_type)) {
      if (itti_create_task (TASK_RRC_GNB, rrc_gnb_task, NULL) < 0) {
        LOG_E(NR_RRC, "Create task for NR RRC gNB failed\n");
        return -1;
      }
    }

    // E1AP initialisation, whether the node is a CU or has integrated CU
    if (node_type == ngran_gNB_CU || node_type == ngran_gNB) {
      MessageDef *msg = RCconfig_NR_CU_E1(NULL);
      instance_t inst = 0;
      createE1inst(UPtype, inst, E1AP_REGISTER_REQ(msg).gnb_id, &E1AP_REGISTER_REQ(msg).net_config, NULL);
      cuup_init_n3(inst);
      RC.nrrrc[gnb_id_start]->e1_inst = inst; // stupid instance !!!*/

      /* send E1 Setup Request to RRC */
      MessageDef *new_msg = itti_alloc_new_message(TASK_GNB_APP, 0, E1AP_SETUP_REQ);
      E1AP_SETUP_REQ(new_msg) = E1AP_REGISTER_REQ(msg).setup_req;
      new_msg->ittiMsgHeader.originInstance = -1; /* meaning, it is local */
      itti_send_msg_to_task(TASK_RRC_GNB, 0 /*unused by callee*/, new_msg);
      itti_free(TASK_UNKNOWN, msg);
    }

    if (itti_create_task (TASK_GNB_APP, gNB_app_task, NULL) < 0) {
      LOG_E(GNB_APP, "Create task for gNB APP failed\n");
      return -1;
    }

    //Use check on x2ap to consider the NSA scenario 
    if((is_x2ap_enabled() || IS_SA_MODE(get_softmodem_params())) && (node_type != ngran_gNB_CUCP)) {
      if (itti_create_task (TASK_GTPV1_U, &gtpv1uTask, NULL) < 0) {
        LOG_E(GTPU, "Create task for GTPV1U failed\n");
        return -1;
      }
    }
  }

  return 0;
}

static void get_options(configmodule_interface_t *cfg)
{
  paramdef_t cmdline_params[] = CMDLINE_PARAMS_DESC_GNB ;
  CONFIG_SETRTFLAG(CONFIG_NOEXITONHELP);
  IS_SOFTMODEM_GNB = true;
  get_common_options(cfg);
  config_process_cmdline(cfg, cmdline_params, sizeofArray(cmdline_params), NULL);
  CONFIG_CLEARRTFLAG(CONFIG_NOEXITONHELP);
}

void wait_RUs(void) {
  LOG_D(PHY, "Waiting for RUs to be configured ... RC.ru_mask:%02lx\n", RC.ru_mask);
  // wait for all RUs to be configured over fronthaul
  pthread_mutex_lock(&RC.ru_mutex);

  while (RC.ru_mask>0) {
    pthread_cond_wait(&RC.ru_cond,&RC.ru_mutex);
  }

  pthread_mutex_unlock(&RC.ru_mutex);
  LOG_D(PHY, "RUs configured\n");
}

void wait_gNBs(void) {
  int i;
  int waiting=1;

  while (waiting==1) {
    LOG_D(GNB_APP, "Waiting for gNB L1 instances to all get configured ... sleeping 50ms (nb_nr_sL1_inst %d)\n", RC.nb_nr_L1_inst);
    usleep(50*1000);
    waiting=0;

    for (i=0; i<RC.nb_nr_L1_inst; i++) {
      if (RC.gNB[i]->configured==0) {
        waiting=1;
        break;
      }
    }
  }

  LOG_D(GNB_APP, "gNB L1 are configured\n");
}

/*
 * helper function to terminate a certain ITTI task
 */
void terminate_task(task_id_t task_id, module_id_t mod_id) {
  LOG_I(GNB_APP, "sending TERMINATE_MESSAGE to task %s (%d)\n", itti_get_task_name(task_id), task_id);
  MessageDef *msg;
  msg = itti_alloc_new_message (TASK_ENB_APP, 0, TERMINATE_MESSAGE);
  itti_send_msg_to_task (task_id, ENB_MODULE_ID_TO_INSTANCE(mod_id), msg);
}

int stop_L1(module_id_t gnb_id)
{
  RU_t *ru = RC.ru[gnb_id];
  if (!ru) {
    LOG_W(GNB_APP, "no RU configured\n");
    return -1;
  }

  if (!RC.gNB[gnb_id]->configured) {
    LOG_W(GNB_APP, "L1 already stopped\n");
    return -1;
  }

  LOG_I(GNB_APP, "stopping nr-softmodem\n");
  oai_exit = 1;

  /* these tasks/layers need to pick up new configuration */
  if (RC.nb_nr_L1_inst > 0)
    stop_gNB(RC.nb_nr_L1_inst);

  if (RC.nb_RU > 0)
    stop_RU(RC.nb_RU);

  /* stop trx devices, multiple carrier currently not supported by RU */
  if (ru->rfdevice.trx_get_stats_func) {
    ru->rfdevice.trx_get_stats_func(&ru->rfdevice);
  }
  if (ru->rfdevice.trx_stop_func) {
    ru->rfdevice.trx_stop_func(&ru->rfdevice);
    LOG_I(GNB_APP, "turned off RU rfdevice\n");
  }

  if (ru->ifdevice.trx_get_stats_func) {
    ru->ifdevice.trx_get_stats_func(&ru->rfdevice);
  }
  if (ru->ifdevice.trx_stop_func) {
    ru->ifdevice.trx_stop_func(&ru->ifdevice);
    LOG_I(GNB_APP, "turned off RU ifdevice\n");
  }

  /* release memory used by the RU/gNB threads (incomplete), after all
   * threads have been stopped (they partially use the same memory) */
  for (int inst = 0; inst < RC.nb_RU; inst++) {
    nr_phy_free_RU(RC.ru[inst]);
  }

  for (int inst = 0; inst < RC.nb_nr_L1_inst; inst++) {
    phy_free_nr_gNB(RC.gNB[inst]);
  }

  RC.gNB[gnb_id]->configured = 0;
  return 0;
}

/*
 * Restart the nr-softmodem after it has been soft-stopped with stop_L1L2()
 */
#include "openair2/LAYER2/NR_MAC_gNB/mac_proto.h"
int start_L1L2(module_id_t gnb_id)
{
  LOG_I(GNB_APP, "starting nr-softmodem\n");
  /* block threads */
  oai_exit = 0;
  sync_var = -1;

  /* update config */
  gNB_MAC_INST *mac = RC.nrmac[0];
  NR_ServingCellConfigCommon_t *scc = mac->common_channels[0].ServingCellConfigCommon;
  nr_mac_config_scc(mac, scc, &mac->radio_config);

  NR_BCCH_BCH_Message_t *mib = mac->common_channels[0].mib;
  const NR_BCCH_DL_SCH_Message_t *sib1 = mac->common_channels[0].sib1;
  f1ap_setup_req_t *sr = mac->f1_config.setup_req;
  DevAssert(sr->num_cells_available == 1);
  f1ap_served_cell_info_t *info = &sr->cell[0].info;
  DevAssert(info->mode == F1AP_MODE_TDD);
  /* update existing config in F1 Setup request structures */
  DevAssert(scc->tdd_UL_DL_ConfigurationCommon != NULL);
  info->tdd = read_tdd_config(scc); /* updates radio config */
  prepare_du_configuration_update(mac, info, mib, sib1);

  init_NR_RU(config_get_if(), NULL);

  start_NR_RU();
  wait_RUs();
  init_eNB_afterRU();
  LOG_I(GNB_APP, "Sending sync to all threads\n");
  pthread_mutex_lock(&sync_mutex);
  sync_var=0;
  pthread_cond_broadcast(&sync_cond);
  pthread_mutex_unlock(&sync_mutex);
  return 0;
}

static  void wait_nfapi_init(char *thread_name)
{
  pthread_mutex_lock( &nfapi_sync_mutex );

  while (nfapi_sync_var<0)
    pthread_cond_wait( &nfapi_sync_cond, &nfapi_sync_mutex );

  pthread_mutex_unlock(&nfapi_sync_mutex);
}

#ifdef E2_AGENT
static void initialize_agent(ngran_node_t node_type, e2_agent_args_t oai_args)
{
  AssertFatal(oai_args.sm_dir != NULL , "Please, specify the directory where the SMs are located in the config file, i.e., add in config file the next line: e2_agent = {near_ric_ip_addr = \"127.0.0.1\"; sm_dir = \"/usr/local/lib/flexric/\");} ");
  AssertFatal(oai_args.ip != NULL , "Please, specify the IP address of the nearRT-RIC in the config file, i.e., e2_agent = {near_ric_ip_addr = \"127.0.0.1\"; sm_dir = \"/usr/local/lib/flexric/\"");

  printf("After RCconfig_NR_E2agent %s %s \n",oai_args.sm_dir, oai_args.ip  );

  fr_args_t args = {0};
  args.ip = oai_args.ip;
  memcpy(args.libs_dir, oai_args.sm_dir, FR_CONF_FILE_LEN);

  sleep(1);
  const gNB_RRC_INST* rrc = RC.nrrrc[0];
  assert(rrc != NULL && "rrc cannot be NULL");

  const int mcc = rrc->configuration.plmn[0].mcc;
  const int mnc = rrc->configuration.plmn[0].mnc;
  const int mnc_digit_len = rrc->configuration.plmn[0].mnc_digit_length;
  // const ngran_node_t node_type = rrc->node_type;
  int nb_id = 0;
  int cu_du_id = 0;
  if (node_type == ngran_gNB) {
    nb_id = rrc->node_id;
  } else if (node_type == ngran_gNB_DU) {
    const gNB_MAC_INST* mac = RC.nrmac[0];
    AssertFatal(mac, "MAC not initialized\n");
    cu_du_id = mac->f1_config.gnb_id;
    nb_id = mac->f1_config.setup_req->gNB_DU_id;
  } else if (node_type == ngran_gNB_CU || node_type == ngran_gNB_CUCP) {
    // agent buggy: the CU has no second ID, it is the CU-UP ID
    // however, that is not a problem her for us, so put the same ID twice
    nb_id = rrc->node_id;
    cu_du_id = rrc->node_id;
  } else {
    LOG_E(NR_RRC, "not supported ran type detect\n");
  }

  printf("[E2 NODE]: mcc = %d mnc = %d mnc_digit = %d nb_id = %d \n", mcc, mnc, mnc_digit_len, nb_id);

  printf("[E2 NODE]: Args %s %s \n", args.ip, args.libs_dir);

  sm_io_ag_ran_t io = init_ran_func_ag();
  init_agent_api(mcc, mnc, mnc_digit_len, nb_id, cu_du_id, node_type, io, &args);
}
#endif

#ifdef JBPF_HOOK

/*
 * Stream ID 비교 함수
 *
 * 개념 설명:
 * - Stream ID는 16바이트 UUID (예: 00112233445566778899AABBCCDDEE01)
 * - 마지막 바이트로 어느 Codelet에서 왔는지 구분
 * - inline 함수: 함수 호출 오버헤드 제거 (컴파일러가 코드를 직접 삽입)
 * - const 포인터: 함수 내에서 stream_id 수정 불가 (안전성)
 *
 * YAML 설정 (oai_gnb_monitoring.yaml):
 * - stats_output:  ...CCDDEE01  (마지막 바이트 = 0x01)
 * - qfi_output:    ...CCDDEE02  (마지막 바이트 = 0x02)
 */

/*
 * Stream ID 구분 전략:
 *
 * SDAP/PDCP 스트림:  "00112233445566778899AABBCCDDEE0X" → id[0] = 0x00
 * MAC 스케줄러 스트림: "AABB0011223344556677889900000X0X" → id[0] = 0xAA
 *
 * id[15] (마지막 바이트)만 확인하면 두 그룹 간 충돌 발생.
 * id[0]로 스트림 그룹을 먼저 구분한 후 id[15]로 codelet을 식별한다.
 */

/* SDAP/PDCP 스트림 확인 함수 (id[0] == 0x00) */
static inline bool is_packet_stats_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0x00 && stream_id->id[15] == 0x01;
}

static inline bool is_qfi_stats_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0x00 && stream_id->id[15] == 0x02;
}

static inline bool is_header_parser_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0x00 && stream_id->id[15] == 0x03;
}

/* MAC 스케줄러 스트림 확인 함수 (id[0] == 0xAA) */
static inline bool is_mac_dl_prb_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0xAA && stream_id->id[15] == 0x01;
}

static inline bool is_mac_ul_prb_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0xAA && stream_id->id[15] == 0x02;
}

static inline bool is_mac_bsr_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0xAA && stream_id->id[15] == 0x03;
}

static inline bool is_mac_sr_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0xAA && stream_id->id[15] == 0x04;
}

/* MAC 패킷 덤프 스트림 확인 (id[0]==0xAA, id[15]==0x05/0x06)
 * mac_sr_packet_dump.c / mac_bsr_packet_dump.c 코드렛과 대응 */
static inline bool is_mac_sr_dump_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0xAA && stream_id->id[15] == 0x05;
}

static inline bool is_mac_bsr_dump_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0xAA && stream_id->id[15] == 0x06;
}

/*
 * Intent 그룹 스트림: id[0] = 0xBB
 * intent_monitoring_dev.yaml의 stream_id 'BB112233...EE01'과 매핑
 */
static inline bool is_intent_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0xBB && stream_id->id[15] == 0x01;
}

/*
 * 정책 그룹 스트림: id[0] = 0xCC
 *
 * 0xCC...01 = QoS weight 즉시 적용 채널
 *   - 코드릿 intent_parser.c 의 weight_output ringbuf 에서 발사
 *   - 페이로드: struct WeightUpdate (8 바이트)
 *   - 호스트 측 dispatch: qos_weight_apply() 호출
 *
 * YAML 매니페스트 (intent_monitoring_dev.yaml) 의
 *   stream_id: 'CC112233445566778899AABBCCDDEE01'
 * 과 정확히 매핑되어야 한다.
 */
static inline bool is_weight_stream(const jbpf_io_stream_id_t* stream_id) {
    return stream_id->id[0] == 0xCC && stream_id->id[15] == 0x01;
}

/*
 * Packet Stats 처리 함수
 *
 * 학습 개념:
 * 1. 포인터 NULL 체크: 포인터 사용 전 항상 유효성 검사 필수
 * 2. 타입 캐스팅: void*를 struct packet_stats*로 변환
 * 3. 단위 변환:
 *    - bits = bytes × 8
 *    - Mbps = (bits per second) / 1,000,000
 *    - KB = bytes / 1024
 *    - ms = ns / 1,000,000
 * 4. CPU 사이클 → 시간 변환:
 *    - rdtsc_oai()는 CPU 사이클 수 반환
 *    - JBPF calibration: 약 3.187 GHz = 3.187 cycles/ns
 *    - 1 cycle ≈ 0.314 ns
 */
static void handle_packet_stats(struct packet_stats* stats) {
    if (!stats) {
        LOG_E(GNB_APP, "[JBPF] NULL packet_stats pointer\n");
        return;
    }

    /* 기본 통계 출력 */
    LOG_I(GNB_APP, "[JBPF Stats] Packets: %lu, Bytes: %lu\n",
          stats->rx_packets, stats->rx_bytes);

    /* Throughput 계산 (이전 통계가 있는 경우만) */
    if (ue_prev_stats.initialized) {
        /*
         * 차분 계산: 현재 - 이전
         * Codelet은 누적 값을 저장하므로 차이를 구해야 구간별 throughput 계산 가능
         */
        uint64_t bytes_diff = stats->rx_bytes - ue_prev_stats.prev_bytes;
        uint64_t time_diff_cycles = stats->last_timestamp - ue_prev_stats.prev_timestamp;

        /*
         * CPU 사이클을 시간(ns)으로 변환
         * JBPF가 calibration 시 측정한 CPU 주파수 사용
         * 예: 3.187 GHz = 3.187 cycles/ns
         * 따라서 time_ns = cycles / 3.187
         */
        double time_diff_ns = time_diff_cycles / 3.187;

        /*
         * Throughput 계산 (Mbps):
         * - bits = bytes_diff × 8
         * - time_s = time_diff_ns / 1,000,000,000
         * - bps = bits / time_s
         * - Mbps = bps / 1,000,000
         *
         * 단순화: (bytes_diff × 8 × 1e9) / (time_diff_ns × 1e6)
         */
        double throughput_mbps = (bytes_diff * 8.0 * 1000000000.0) / (time_diff_ns * 1000000.0);

        LOG_I(GNB_APP, "[JBPF Stats] Throughput: %.2f Mbps (%.2f KB in %.2f ms)\n",
              throughput_mbps,
              bytes_diff / 1024.0,           // KB
              time_diff_ns / 1000000.0);     // ms
    }

    /*
     * 현재 통계를 "이전 통계"로 저장
     * 다음 호출 시 throughput 계산에 사용
     */
    ue_prev_stats.prev_bytes = stats->rx_bytes;
    ue_prev_stats.prev_timestamp = stats->last_timestamp;
    ue_prev_stats.initialized = true;
}

/*
 * QFI Stats 처리 함수
 *
 * 학습 개념:
 * 1. switch 문: 여러 조건 분기 (if-else보다 효율적)
 * 2. const char*: 읽기 전용 문자열 포인터
 * 3. 5G QFI (QoS Flow Identifier) 의미:
 *    - QFI 5: IMS (IP Multimedia Subsystem) Signaling
 *      → VoIP 통화 시그널링, 높은 우선순위
 *    - QFI 9: Default Bearer
 *      → 일반 인터넷 트래픽, Best-effort
 *    - QFI 32: Custom (우리가 추가한 slice)
 *      → 실험용 또는 특수 서비스
 */
static void handle_qfi_stats(struct qfi_stats* stats) {
    if (!stats) {
        LOG_E(GNB_APP, "[JBPF] NULL qfi_stats pointer\n");
        return;
    }

    /*
     * QFI별 통계 출력
     * %u: unsigned int (uint32_t, uint8_t)
     * %lu: unsigned long (uint64_t)
     * %.2f: floating point with 2 decimal places
     */
    LOG_I(GNB_APP, "[JBPF QFI] UE %u, QFI %u: Packets=%lu, Bytes=%lu (%.2f KB)\n",
          stats->ue_id, stats->qfi,
          stats->packet_count, stats->byte_count,
          stats->byte_count / 1024.0);

    /*
     * QFI 값에 따른 트래픽 타입 추정
     * 3GPP TS 23.501 표준 참고
     */
    const char* traffic_type = "Unknown";
    switch (stats->qfi) {
        case 1:
            traffic_type = "Conversational Video (GBR)";
            break;
        case 5:
            traffic_type = "IMS Signaling";
            break;
        case 9:
            traffic_type = "Default Bearer (Best Effort)";
            break;
        case 32:
            traffic_type = "Custom Slice (ffffff)";
            break;
        default:
            traffic_type = "Operator-specific QFI";
            break;
    }

    LOG_D(GNB_APP, "[JBPF QFI] Traffic type: %s\n", traffic_type);

    /*
     * QFI별 특별 처리 예시
     * - 실제 환경에서는 QFI에 따라 다른 정책 적용 가능:
     *   1. QFI 1 (Video): 지연시간 모니터링
     *   2. QFI 5 (IMS): 패킷 손실률 추적
     *   3. QFI 9 (Default): 대역폭 사용량 제한
     */
    if (stats->qfi == 5 && stats->packet_count > 0) {
        LOG_D(GNB_APP, "[JBPF QFI] High-priority IMS traffic detected\n");
    }
}

/*
 * ============================================================
 * Header Parser 처리 함수 (NEW!)
 * ============================================================
 *
 * header_parser Codelet이 전송한 L3/L4 5-Tuple 데이터 처리
 *
 * 학습 개념:
 * 1. 5-Tuple: 네트워크 플로우를 고유하게 식별하는 5가지 정보
 *    - Source IP
 *    - Destination IP
 *    - Source Port
 *    - Destination Port
 *    - Protocol (TCP=6, UDP=17)
 *
 * 2. IP 주소 표현:
 *    - 네트워크: 32bit Big-Endian (0xC0A80101)
 *    - 사람: Dotted decimal (192.168.1.1)
 *    - 변환: (ip >> 24).((ip >> 16) & 0xFF).((ip >> 8) & 0xFF).(ip & 0xFF)
 *
 * 3. 프로토콜 번호:
 *    - 6: TCP (Transmission Control Protocol) - 연결 지향, 신뢰성
 *    - 17: UDP (User Datagram Protocol) - 비연결, 빠름
 *    - 1: ICMP (Internet Control Message Protocol) - Ping 등
 *
 * 데이터 흐름:
 * PDCP → hook_pdcp_uplink → Codelet jbpf_main() → jbpf_ringbuf_output
 * → jbpf_io_output_handler → handle_header_parser (여기!)
 */
static void handle_header_parser(struct Packet5Tuple* packet) {
    if (!packet) {
        return;
    }

    /* Latency 계산: (현재시간 - 보낸시간) / CPU주파수 */
    uint64_t current_time = rdtsc_oai();
    double latency_us = (double)(current_time - packet->timestamp) / cpuf / 1000.0;

    /* IP 주소 변환 (Host Byte Order -> Dotted Decimal) */
    uint8_t *s = (uint8_t *)&packet->src_ip;
    uint8_t *d = (uint8_t *)&packet->dst_ip;

    const char *proto_str = (packet->protocol == IPPROTO_TCP) ? "TCP" :
                            (packet->protocol == IPPROTO_UDP) ? "UDP" : "Other";

    /* Codelet 대신 여기서 로그 출력 (Latency + pkt_count 정보 추가) */
    LOG_I(GNB_APP, "[5-TUPLE] %s %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u"
          " (UE=%u QFI=%u) pkts_5s=%llu latency=%.2fus\n",
          proto_str,
          s[0], s[1], s[2], s[3], packet->src_port,
          d[0], d[1], d[2], d[3], packet->dst_port,
          packet->ue_id, packet->qfi,
          (unsigned long long)packet->pkt_count, latency_us);
}

/* ============================================================
 * 6G Demand Codelet 핸들러
 * ============================================================
 *
 * intent_parser.c codelet에서 5초마다 전송하는 IntentReport를 수신.
 *
 * 출력 예시:
 *   [DEMAND] UE=1 app=LLM src_port=54321
 *            intents=4350/5s sum=6.0MB last=1400B deadline=50ms
 *
 * IntentReport 필드 해석:
 *   intent_count:      이 5초 윈도우 동안 UE가 보낸 demand 패킷 수
 *   sum_payload_bytes: UE가 이 5초 동안 보내겠다고 선언한 총 바이트 합계
 *                      스케줄러에서 UL 그랜트 결정 시 참고 가능
 *   app_type:          0=UNKNOWN, 1=LLM, 2=VLA, 3=VIDEO, 4=BULK
 *   src_port:          flow 식별자 (UE 소켓의 source port)
 *   deadline_ms:       soft deadline in milliseconds (0=없음)
 */

/*
 * IntentReport 구조체: intent_parser.c의 struct IntentReport와 100% 동일해야 함.
 * 레이아웃 (40 bytes, 8-byte 정렬):
 *   [ 0] timestamp_ns       (8B)
 *   [ 8] sum_payload_bytes  (8B)
 *   [16] ue_id              (4B)
 *   [20] intent_count       (4B)
 *   [24] payload_bytes_last (4B)
 *   [28] src_port           (2B)
 *   [30] deadline_ms        (2B)
 *   [32] app_type           (1B)
 *   [33] _pad               (7B)
 */
struct IntentReport {
    uint64_t timestamp_ns;
    uint64_t sum_payload_bytes;
    uint32_t ue_id;
    uint32_t intent_count;
    uint32_t payload_bytes_last;
    uint16_t src_port;
    uint16_t deadline_ms;
    uint8_t  app_type;
    uint8_t  _pad[7];
};

static void handle_intent(struct IntentReport *r)
{
    if (!r)
        return;

    const char *app_str = (r->app_type == 1) ? "LLM"   :
                          (r->app_type == 2) ? "VLA"   :
                          (r->app_type == 3) ? "VIDEO" :
                          (r->app_type == 4) ? "BULK"  : "UNKNOWN";

  //  LOG_I(GNB_APP,
  //        "[DEMAND] UE=%u app=%s\n src_port=%u"
  //        " intents=%u/5s sum=%.1fKB last=%uB deadline=%ums\n",
  //        r->ue_id, app_str, r->src_port,
  //        r->intent_count,
  //        r->sum_payload_bytes / 1024.0f,
  //        r->payload_bytes_last,
  //        r->deadline_ms);
    LOG_I(GNB_APP,
          "[6G_REQUIREMENT] UE=%u\n", r->ue_id);
    LOG_I(GNB_APP,
          "[6G_REQUIREMENT] application=%s\n", app_str);
    LOG_I(GNB_APP,
          "[6G_REQUIREMENT] deadline=%ums\n", r->deadline_ms);
      
}

/* ============================================================
 * MAC 스케줄러 Codelet 핸들러 함수들
 * ============================================================ */

static void handle_mac_dl_prb(struct dl_prb_report *r)
{
    if (!r)
        return;
    LOG_I(GNB_APP,
          "[MAC DL] RNTI=0x%04x frame=%u slot=%u RB=[%u+%u] MCS=%u TB=%uB"
          " retx=%u total_dl=%.1fKB slots=%u\n",
          r->rnti, r->frame, r->slot,
          r->rb_start, r->rb_size, r->mcs, r->tb_size,
          r->is_retx,
          r->total_dl_bytes / 1024.0f, r->total_slots);
}

static void handle_mac_ul_prb(struct ul_prb_report *r)
{
    if (!r)
        return;
    LOG_I(GNB_APP,
          "[MAC UL] RNTI=0x%04x frame=%u slot=%u RB=[%u+%u] MCS=%u TB=%uB"
          " buf=%dB pressure=%u%% retx=%u total_ul=%.1fKB slots=%u\n",
          r->rnti, r->frame, r->slot,
          r->rb_start, r->rb_size, r->mcs, r->tb_size,
          r->buffer_bytes, r->buffer_pressure_pct,
          r->is_retx,
          r->total_ul_bytes / 1024.0f, r->total_slots);
}

static void handle_mac_bsr(struct bsr_report *r)
{
    if (!r)
        return;
    const char *bsr_type_str = (r->bsr_type == 0) ? "Short" : "Long";
    LOG_I(GNB_APP,
          "[MAC BSR] RNTI=0x%04x frame=%u slot=%u type=%s LCG=%u"
          " est=%uB count=%u peak=%.1fKB\n",
          r->rnti, r->frame, r->slot,
          bsr_type_str, r->lcg_id,
          r->estimated_bytes, r->bsr_count,
          r->peak_bytes / 1024.0f);
}

static void handle_mac_sr(struct sr_report *r)
{
    if (!r)
        return;
    LOG_I(GNB_APP,
          "[MAC SR] RNTI=0x%04x frame=%u slot=%u UL_CQI=%u"
          " sr_count=%u avg_cqi=%.2f\n",
          r->rnti, r->frame, r->slot,
          r->ul_cqi, r->sr_count,
          r->avg_ul_cqi / 100.0f);
}

/* ============================================================
 * SR / BSR 패킷 덤프 핸들러
 *
 * mac_sr_packet_dump.c / mac_bsr_packet_dump.c 코드렛이
 * jbpf_ringbuf_output()으로 전송한 데이터를 수신하여
 * nr-softmodem 터미널에 ASCII 패킷 덤프 형태로 표시한다.
 *
 * 출력 전략 (로그 폭주 방지):
 *   - 매 이벤트: compact 1줄 요약 (LOG_I)
 *   - N번에 1번: 전체 ASCII 테이블 + Hex Dump (LOG_I)
 *
 * 인터벌 조정:
 *   SR_DUMP_FULL_INTERVAL  : SR full dump 주기
 *   BSR_DUMP_FULL_INTERVAL : BSR full dump 주기
 *   값을 1로 설정하면 매 이벤트마다 전체 덤프 출력됨 (트래픽 적을 때)
 *
 * 출력 구조체(sr_packet_frame, bsr_packet_frame)는 파일 상단
 * "MAC 스케줄러 Codelet 출력 구조체" 블록에 정의되어 있다.
 * ============================================================ */

/* 전체 ASCII 패킷 덤프를 출력하는 이벤트 주기 */
#define SR_DUMP_FULL_INTERVAL   50    /* SR 50번에 1번 전체 덤프 */
#define BSR_DUMP_FULL_INTERVAL  100   /* BSR 100번에 1번 전체 덤프 */

/*
 * 헥스 덤프 한 줄 출력 헬퍼
 *
 * @param bytes  출력할 데이터의 시작 포인터
 * @param offset 전체 구조체 내 현재 오프셋 (출력에만 사용)
 * @param len    이 줄에서 출력할 바이트 수 (1~8)
 * @param tag    LOG_I 태그 구분용 접두사 ("SR" or "BSR")
 *
 * 학습: hex/ascii 문자를 로컬 배열에 먼저 조합 후 LOG_I 1번으로 출력.
 *       → 여러 LOG_I 호출 간 다른 스레드 로그가 끼어드는 현상 방지.
 */

static void print_hex_line(const uint8_t *bytes, size_t offset, int len, const char *tag)
{
    char hex[25];   /* 최대 8×3 = 24자 + null */
    char asc[9];    /* 최대 8자 + null */
    int  hpos = 0;

    for (int i = 0; i < len; i++) {
        uint8_t b = bytes[offset + i];
        hex[hpos]     = "0123456789ABCDEF"[b >> 4];
        hex[hpos + 1] = "0123456789ABCDEF"[b & 0xF];
        hex[hpos + 2] = ' ';
        hpos += 3;
        asc[i] = (b >= 0x20 && b <= 0x7E) ? (char)b : '.';
    }
    hex[hpos] = '\0';
    asc[len]  = '\0';

    /* 출력이 주석 처리되어 있어서 이 함수가 문자열만 조립하고 버리고 있었다
     * (gcc 의 'hex/asc set but not used' 경고가 그 흔적). 호출 자체가
     * SR 50회 / BSR 100회에 1번으로 throttle 되어 있고, 위쪽 주석이
     * "전체 ASCII 테이블 + hex dump" 를 출력한다고 명시하므로 출력을
     * 되살렸다. 다시 끄려면 호출부(print_hex_line)를 지우는 쪽이 맞다. */
    LOG_I(GNB_APP, "[MAC %s DUMP] | %04zx: %-24s %s\n",
          tag, offset, hex, asc);
}

/*
 * SR 패킷 덤프 출력 핸들러
 *
 * 출력 구조:
 *   [매 이벤트] compact 1줄:
 *     [MAC SR ] #N RNTI=0x???? F???.S?? CQI=???(SNR~??dB)
 *
 *   [SR_DUMP_FULL_INTERVAL번에 1번] 전체 ASCII 테이블 + hex dump
 *
 * UL CQI → SNR 변환 (정수 연산, float 불필요):
 *   snr_x10 = (ul_cqi - 128) × 5  [단위: 0.1 dB]
 *   snr_int  = snr_x10 / 10
 *   snr_frac = |snr_x10 % 10|
 *   → "17.0 dB" 형태 표현
 */
static void handle_mac_sr_packet_dump(struct sr_packet_frame *r)
{
    if (!r)
        return;

    int snr_x10  = ((int)r->ul_cqi - 128) * 5;
    int snr_int  = snr_x10 / 10;
    int snr_frac = snr_x10 < 0 ? -(snr_x10 % 10) : (snr_x10 % 10);

    /* ── compact 요약 (매 이벤트) ── */
    //LOG_I(GNB_APP,
    //      "[MAC SR ] #%-5u RNTI=0x%04x F%4u.S%02u  CQI=%3u(SNR~%d.%ddB)\n",
    //      r->seq_num, r->rnti, r->frame, r->slot,
    //      r->ul_cqi, snr_int, snr_frac);

    /* ── 전체 덤프 (N번에 1번, 또는 첫 이벤트) ── */
    if (r->seq_num % SR_DUMP_FULL_INTERVAL != 0)
        return;

    const uint8_t *raw = (const uint8_t *)r;
    size_t sz = sizeof(struct sr_packet_frame);  /* = 24 */

    LOG_I(GNB_APP, "[MAC SR DUMP] +------------------------------------------------------------------+\n");
    LOG_I(GNB_APP, "[MAC SR DUMP] |  5G NR MAC UL Control: SR (Scheduling Request)  #%u\n",
          r->seq_num);
    LOG_I(GNB_APP, "[MAC SR DUMP] |  Hook: mac_sr_detect | PUCCH Fmt0/1 | UL Grant 요청 시그널\n");
    LOG_I(GNB_APP, "[MAC SR DUMP] +------+----------------+----------+-------+--------------------+\n");
    LOG_I(GNB_APP, "[MAC SR DUMP] | OFF  | FIELD          | HEX      | DEC   | NOTE               |\n");
    LOG_I(GNB_APP, "[MAC SR DUMP] +------+----------------+----------+-------+--------------------+\n");
    LOG_I(GNB_APP, "[MAC SR DUMP] |  0   | Timestamp      | %016llx | -     | CPU rdtsc cycles   |\n",
          (unsigned long long)r->ts_cycles);
    LOG_I(GNB_APP, "[MAC SR DUMP] |  8   | RNTI           | 0x%04x   | %5u | UE Radio Temp ID   |\n",
          r->rnti, r->rnti);
    LOG_I(GNB_APP, "[MAC SR DUMP] | 10   | Frame          | 0x%04x   | %5u | 10ms 프레임 (0~1023)|\n",
          r->frame, r->frame);
    LOG_I(GNB_APP, "[MAC SR DUMP] | 12   | Slot           | 0x%02x     | %5u | 슬롯 (SCS=30kHz)   |\n",
          r->slot, r->slot);
    LOG_I(GNB_APP, "[MAC SR DUMP] | 13   | SR Detected    | 0x%02x     | %5u | 1=VALID SR         |\n",
          r->sr_detected, r->sr_detected);
    LOG_I(GNB_APP, "[MAC SR DUMP] | 14   | UL CQI         | 0x%02x     | %5u | SNR~%d.%ddB(148=10dB)|\n",
          r->ul_cqi, r->ul_cqi, snr_int, snr_frac);
    LOG_I(GNB_APP, "[MAC SR DUMP] | 15   | _pad[5]        | -         | -     | 정렬 패딩 5바이트  |\n");
    LOG_I(GNB_APP, "[MAC SR DUMP] | 20   | Seq#           | 0x%08x | %5u | 이벤트 번호        |\n",
          r->seq_num, r->seq_num);
    LOG_I(GNB_APP, "[MAC SR DUMP] +------+----------------+----------+-------+--------------------+\n");
    LOG_I(GNB_APP, "[MAC SR DUMP] |  Hex Dump  (%zu bytes)                                        |\n", sz);

    for (size_t off = 0; off < sz; off += 8) {
        int chunk = (int)(sz - off);
        if (chunk > 8) chunk = 8;
        print_hex_line(raw, off, chunk, "SR");
    }

    LOG_I(GNB_APP, "[MAC SR DUMP] +------------------------------------------------------------------+\n");
}

/*
 * BSR 패킷 덤프 출력 핸들러
 *
 * 출력 구조:
 *   [매 이벤트] compact 1줄:
 *     [MAC BSR] #N RNTI=0x???? F???.S?? Short/Long LCG=? est=????B(~?KB)
 *
 *   [BSR_DUMP_FULL_INTERVAL번에 1번] 전체 ASCII 테이블 + hex dump
 *
 * LCG ID 해석:
 *   0~7: Short BSR에서 보고한 특정 논리채널그룹
 *   0xFF: Long BSR (여러 LCG 포함, lcg_id를 ALL로 표시)
 */
static void handle_mac_bsr_packet_dump(struct bsr_packet_frame *r)
{
    if (!r)
        return;

    const char *bsr_type_str = (r->bsr_type == 0) ? "Short" : "Long";
    uint32_t kb_int  = r->estimated_bytes / 1024;
    uint32_t kb_frac = (r->estimated_bytes % 1024) * 10 / 1024;

    /* LCG ID 문자열 */
    char lcg_str[16];
    if (r->lcg_id == 0xFF)
        __builtin_memcpy(lcg_str, "ALL", 4);
    else {
        lcg_str[0] = '0' + (r->lcg_id & 0xF);
        lcg_str[1] = '\0';
    }

    /* ── compact 요약 (매 이벤트) ── */
    //LOG_I(GNB_APP,
    //      "[MAC BSR] #%-5u RNTI=0x%04x F%4u.S%02u  %5s LCG=%-3s est=%5uB(~%u.%uKB)\n",
    //      r->seq_num, r->rnti, r->frame, r->slot,
    //      bsr_type_str, lcg_str,
    //      r->estimated_bytes, kb_int, kb_frac);

    /* ── 전체 덤프 (N번에 1번, 또는 첫 이벤트) ── */
    if (r->seq_num % BSR_DUMP_FULL_INTERVAL != 0)
        return;

    const uint8_t *raw = (const uint8_t *)r;
    size_t sz = sizeof(struct bsr_packet_frame);  /* = 24 */

    LOG_I(GNB_APP, "[MAC BSR DUMP] +------------------------------------------------------------------+\n");
    LOG_I(GNB_APP, "[MAC BSR DUMP] |  5G NR MAC UL Control: BSR (Buffer Status Report)  #%u\n",
          r->seq_num);
    LOG_I(GNB_APP, "[MAC BSR DUMP] |  Hook: mac_bsr_event | %s BSR MAC CE | PUSCH 내 포함\n",
          bsr_type_str);
    LOG_I(GNB_APP, "[MAC BSR DUMP] +------+------------------+----------+-------+------------------+\n");
    LOG_I(GNB_APP, "[MAC BSR DUMP] | OFF  | FIELD            | HEX      | DEC   | NOTE             |\n");
    LOG_I(GNB_APP, "[MAC BSR DUMP] +------+------------------+----------+-------+------------------+\n");
    LOG_I(GNB_APP, "[MAC BSR DUMP] |  0   | Timestamp        | %016llx | -     | CPU rdtsc cycles |\n",
          (unsigned long long)r->ts_cycles);
    LOG_I(GNB_APP, "[MAC BSR DUMP] |  8   | RNTI             | 0x%04x   | %5u | UE Radio Temp ID |\n",
          r->rnti, r->rnti);
    LOG_I(GNB_APP, "[MAC BSR DUMP] | 10   | Frame            | 0x%04x   | %5u | 10ms 프레임      |\n",
          r->frame, r->frame);
    LOG_I(GNB_APP, "[MAC BSR DUMP] | 12   | Slot             | 0x%02x     | %5u | 슬롯 (0~19)      |\n",
          r->slot, r->slot);
    LOG_I(GNB_APP, "[MAC BSR DUMP] | 13   | BSR Type         | 0x%02x     | %5s | Short/Long       |\n",
          r->bsr_type, bsr_type_str);
    LOG_I(GNB_APP, "[MAC BSR DUMP] | 14   | LCG ID           | 0x%02x     | %5s | 논리채널그룹     |\n",
          r->lcg_id, lcg_str);
    LOG_I(GNB_APP, "[MAC BSR DUMP] | 15   | _pad             | 0x%02x     | -     | 정렬 패딩 1바이트|\n",
          r->_pad);
    LOG_I(GNB_APP, "[MAC BSR DUMP] | 16   | Estimated Bytes  | 0x%08x | %5u | ~%u.%uKB UL 버퍼 |\n",
          r->estimated_bytes, r->estimated_bytes, kb_int, kb_frac);
    LOG_I(GNB_APP, "[MAC BSR DUMP] | 20   | Seq#             | 0x%08x | %5u | 이벤트 번호      |\n",
          r->seq_num, r->seq_num);
    LOG_I(GNB_APP, "[MAC BSR DUMP] +------+------------------+----------+-------+------------------+\n");
    LOG_I(GNB_APP, "[MAC BSR DUMP] |  Hex Dump  (%zu bytes)                                        |\n", sz);

    for (size_t off = 0; off < sz; off += 8) {
        int chunk = (int)(sz - off);
        if (chunk > 8) chunk = 8;
        print_hex_line(raw, off, chunk, "BSR");
    }

    LOG_I(GNB_APP, "[MAC BSR DUMP] +------------------------------------------------------------------+\n");
}

/**
 * JBPF I/O 출력 콜백 핸들러
 *
 * eBPF Codelet이 ringbuf로 전송한 데이터를 수신하는 핸들러 함수
 * jbpf_register_io_output_cb()로 등록되어 codelet이 jbpf_ringbuf_output() 호출 시 자동 실행
 *
 * @param stream_id  출력 스트림 ID (YAML의 out_io_channel.stream_id와 매칭)
 * @param bufs       데이터 버퍼 배열 (각 버퍼는 codelet이 전송한 구조체 포인터)
 * @param num_bufs   버퍼 개수
 * @param ctx        사용자 정의 컨텍스트 (등록 시 전달, 현재 미사용)
 */
static void jbpf_io_output_handler(jbpf_io_stream_id_t* stream_id, void** bufs, int num_bufs, void* ctx)
{
    if (!stream_id || num_bufs <= 0) {
        return;
    }

    /* 디버그: 수신된 데이터 정보 로깅 */
    //LOG_I(GNB_APP, "Received %d buffers from codelet (stream_id: %02x%02x...)\n",
    //      num_bufs, stream_id->id[0], stream_id->id[1]);

    /*
     * 추후 확장 가능 영역:
     *
     * 1. Stream ID로 codelet 구분:
     *    - stream_id: 00112233445566778899AABBCCDDEE01 → sdap_packet_stats
     *    - stream_id: 00112233445566778899AABBCCDDEE02 → sdap_qfi_classifier
     *
     * 2. 구조체 파싱:
     *    struct packet_stats* stats = (struct packet_stats*)bufs[i];
     *    LOG_I(JBPF, "UE %u: %lu packets, %lu bytes\n",
     *          stats->ue_id, stats->rx_packets, stats->rx_bytes);
     *
     * 3. 외부 시스템 연동:
     *    - Prometheus exporter (HTTP 메트릭 엔드포인트)
     *    - InfluxDB (시계열 DB)
     *    - Kafka (실시간 스트리밍)
     *    - FlexRIC E2 Metrics (xApp으로 전송)
     */
    for (int i = 0; i < num_bufs; i++) {
        if (!bufs[i]) {
            LOG_W(GNB_APP, "[JBPF] NULL buffer at index %d\n", i);
            continue;
        }

        if (is_packet_stats_stream(stream_id)) {
            /*
             * Stream ID 0x01: packet_stats Codelet
             * - SDAP 계층 기본 통계 (패킷 수, 바이트 수)
             */
            struct packet_stats* stats = (struct packet_stats*)bufs[i];
            handle_packet_stats(stats);

        } else if (is_qfi_stats_stream(stream_id)) {
            /*
             * Stream ID 0x02: qfi_stats Codelet
             * - QFI별 트래픽 분류 통계
             */
            struct qfi_stats* stats = (struct qfi_stats*)bufs[i];
            handle_qfi_stats(stats);

        } else if (is_header_parser_stream(stream_id)) {
            /*
             * Stream ID 0x03: header_parser Codelet (NEW!)
             * - PDCP 계층 L3/L4 헤더 파싱
             * - 5-Tuple 추출 (src_ip, dst_ip, src_port, dst_port, protocol)
             *
             * 데이터 흐름:
             * 1. PDCP deliver_sdu_drb() → hook_pdcp_uplink()
             * 2. Codelet jbpf_main() → IP/TCP/UDP 헤더 파싱
             * 3. jbpf_ringbuf_output() → 여기로 전송
             */
            struct Packet5Tuple* packet = (struct Packet5Tuple*)bufs[i];
            handle_header_parser(packet);

        } else if (is_mac_dl_prb_stream(stream_id)) {
            handle_mac_dl_prb((struct dl_prb_report *)bufs[i]);

        } else if (is_mac_ul_prb_stream(stream_id)) {
            handle_mac_ul_prb((struct ul_prb_report *)bufs[i]);

        } else if (is_mac_bsr_stream(stream_id)) {
            handle_mac_bsr((struct bsr_report *)bufs[i]);

        } else if (is_mac_sr_stream(stream_id)) {
            handle_mac_sr((struct sr_report *)bufs[i]);

        } else if (is_mac_sr_dump_stream(stream_id)) {
            /*
             * Stream ID 0xAA...05: mac_sr_packet_dump 코드렛
             * 매 SR 이벤트를 Wireshark 스타일 ASCII 패킷 덤프로 출력
             */
            handle_mac_sr_packet_dump((struct sr_packet_frame *)bufs[i]);

        } else if (is_mac_bsr_dump_stream(stream_id)) {
            /*
             * Stream ID 0xAA...06: mac_bsr_packet_dump 코드렛
             * 매 BSR 이벤트를 Wireshark 스타일 ASCII 패킷 덤프로 출력
             */
            handle_mac_bsr_packet_dump((struct bsr_packet_frame *)bufs[i]);

        } else if (is_intent_stream(stream_id)) {
            /*
             * Stream ID 0xBB...01: intent_parser 코드렛
             * UE의 6G Intent 패킷을 5초마다 요약 출력
             * intent_monitoring_dev.yaml로 로드
             */
            handle_intent((struct IntentReport *)bufs[i]);

        } else if (is_weight_stream(stream_id)) {
            /*
             * ─── Stream ID 0xCC…01: QoS weight 정책 채널 ───────────
             *
             * 이 분기가 jbpf 출력 중 *유일하게 gNB 동작을 바꾸는* 경로다.
             * 나머지 스트림은 전부 로그로만 나간다.
             *
             *   1. duration_ms 센티널이면 전체 해제 후 종료
             *   2. CU-UE-ID → MAC RNTI 역조회
             *   3. Q16.16 → float 변환 (이 경계에서만 일어난다)
             *   4. qos_weight_apply() 로 테이블 반영
             */
            struct WeightUpdate *wu = (struct WeightUpdate *)bufs[i];

            /* ── (1) 전체 해제 요청 ────────────────────────────────
             * rnti / weight_q16 필드는 의미가 없으므로 RNTI 역조회를
             * 하기 전에 처리한다. 코드렛의 APP_TYPE_RESET 경로가 발사. */
            if (wu->duration_ms == QOS_WEIGHT_TTL_CLEAR_ALL) {
                qos_weight_clear_all();
                LOG_I(GNB_APP, "[QoS] clear_all — 모든 UE 가중치 해제\n");
                continue;
            }

            /* ── (2) CU-UE-ID → MAC RNTI 역방향 조회 ───────────────
             *
             * 코드렛이 보낸 wu->rnti 는 PDCP 의 내부 UE ID (= CU-UE-ID)
             * 이고 MAC RNTI 가 아니다. 스케줄러는 UE->rnti (0x59a2 같은
             * 실제 RNTI) 로 lookup 하므로 여기서 변환해야 한다.
             *
             * connected_ue_list[CU-UE-ID - 1] 인덱싱은 쓸 수 없다 —
             * CU-UE-ID 가 재사용되지 않아서 (UE 가 끊기면 다음 UE 는 더
             * 큰 값을 받는다) 인덱스가 어긋난다. 그래서 리스트를 돌며
             * du_get_f1_ue_data(rnti).secondary_ue == CU-UE-ID 인 UE 를
             * 찾는 역조회를 한다.
             *
             * du_*_f1_ue_data 는 DU(= MAC) 가 들고 있는 F1AP UE ID 매핑
             * 테이블이다. monolithic gNB 에서는 CU-UE-ID 가 곧 PDCP/RRC
             * 의 ue_id 이고, 이걸 MAC RNTI 와 묶어두는 자리가 여기다. */
            uint32_t cu_ue_id = wu->rnti;
            uint16_t mac_rnti = 0;

            /* 생존 RNTI 목록. 같은 순회에서 공짜로 모을 수 있으므로
             * 아래 qos_weight_retain() 으로 유령 엔트리를 정리한다.
             * (정책은 영구이고 OAI 는 RNTI 를 재사용하므로, 정리하지
             *  않으면 신규 UE 가 남의 정책을 상속한다.) */
            uint16_t live_rnti[MAX_MOBILES_PER_GNB];
            int      live_n = 0;

            gNB_MAC_INST *nrmac = RC.nrmac[0];
            if (nrmac) {
                NR_SCHED_LOCK(&nrmac->sched_lock);
                UE_iterator(nrmac->UE_info.connected_ue_list, ue_it) {
                    if (live_n < MAX_MOBILES_PER_GNB)
                        live_rnti[live_n++] = ue_it->rnti;
                    if (mac_rnti == 0 && du_exists_f1_ue_data(ue_it->rnti)) {
                        f1_ue_data_t ued = du_get_f1_ue_data(ue_it->rnti);
                        if (ued.secondary_ue == cu_ue_id)
                            mac_rnti = ue_it->rnti;
                    }
                }
                NR_SCHED_UNLOCK(&nrmac->sched_lock);
            }

            /* 락을 놓은 뒤 정리한다 — qos_weight 의 rwlock 과
             * 스케줄러 락을 중첩해서 잡지 않기 위해서다. */
            qos_weight_retain(live_rnti, live_n);

            if (mac_rnti == 0) {
                /* UE 가 disconnect 됐거나 아직 RRC connected 전.
                 * 코드렛이 WEIGHT_REASSERT_NS(2초) 주기로 재확인하므로
                 * 이 메시지를 버려도 정책은 자동 복구된다. */
                LOG_D(GNB_APP, "[QoS] CU-UE-ID %u 에 해당하는 MAC RNTI 없음 "
                               "(2초 내 재확인으로 복구)\n", cu_ue_id);
                continue;
            }

            /* ── (3)(4) 적용 ───────────────────────────────────────
             *
             * 로그를 throttle 하지 않는다. 변화 감지는 코드렛의
             * last_weight_q16 비교 한 곳에만 있고 (intent_parser.c),
             * 여기 도착하는 메시지는 이미 "정책이 실제로 바뀐 순간"
             * 뿐이다. 양쪽에 같은 판정을 두면 둘이 어긋날 때 디버깅이
             * 어려워진다. */
            float w = QOS_WEIGHT_FROM_Q16(wu->weight_q16);
            qos_weight_apply(mac_rnti, w, wu->duration_ms);

            if (w == 1.0f) {
                LOG_I(GNB_APP, "[QoS] rnti=%04x (cu_ue_id=%u) 정책 해제 → PF 기본값\n",
                      mac_rnti, cu_ue_id);
            } else if (wu->duration_ms == 0) {
                LOG_I(GNB_APP, "[QoS] rnti=%04x (cu_ue_id=%u) weight=%.2f PERMANENT\n",
                      mac_rnti, cu_ue_id, w);
            } else {
                LOG_I(GNB_APP, "[QoS] rnti=%04x (cu_ue_id=%u) weight=%.2f ttl=%ums\n",
                      mac_rnti, cu_ue_id, w, wu->duration_ms);
            }

        } else {
            LOG_W(GNB_APP, "[JBPF] Unknown stream ID: %02x...%02x\n",
                  stream_id->id[0], stream_id->id[15]);
        }
    }
}
#endif // JBPF_HOOK

void init_eNB_afterRU(void);
configmodule_interface_t *uniqCfg = NULL;
int main( int argc, char **argv ) {
  int ru_id, CC_id = 0;
  start_background_system();

  ///static configuration for NR at the moment
  if ((uniqCfg = load_configmodule(argc, argv, CONFIG_ENABLECMDLINEONLY)) == NULL) {
    exit_fun("[SOFTMODEM] Error, configuration module init failed\n");
  }

  set_softmodem_sighandler();
#ifdef DEBUG_CONSOLE
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
#endif
  mode = normal_txrx;
  memset(tx_max_power,0,sizeof(int)*MAX_NUM_CCs);
  logInit();
  lock_memory_to_ram();
  get_options(uniqCfg);

  if (CONFIG_ISFLAGSET(CONFIG_ABORT) ) {
    fprintf(stderr,"Getting configuration failed\n");
    exit(-1);
  }

  if (!has_cap_sys_nice())
    LOG_W(UTIL,
          "no SYS_NICE capability: cannot set thread priority and affinity, consider running with sudo for optimum performance\n");

  softmodem_verify_mode(get_softmodem_params());

#if T_TRACER
  T_Config_Init();
#endif
  set_taus_seed (0);

  cpuf=get_cpu_freq_GHz();
  itti_init(TASK_MAX, tasks_info);
  // initialize mscgen log after ITTI
  init_opt();

  // strdup to put the sring in the core file for post mortem identification
  char *pckg = strdup(OAI_PACKAGE_VERSION);
  LOG_I(HW, "Version: %s\n", pckg);

  // Init RAN context
  if (!(CONFIG_ISFLAGSET(CONFIG_ABORT)))
    NRRCConfig();

  if (RC.nb_nr_L1_inst > 0) {
    // Initialize gNB structure in RAN context
    init_gNB();
    // Initialize L1
    RCconfig_NR_L1();
    // Initialize Positioning Reference Signal configuration
    if(NFAPI_MODE != NFAPI_MODE_PNF && NFAPI_MODE != NFAPI_MODE_AERIAL)
      RCconfig_nr_prs();
  }

  // don't create if node doesn't connect to RRC/S1/GTP
  const ngran_node_t node_type = get_node_type();

  if (NFAPI_MODE != NFAPI_MODE_PNF) {
    int ret = create_gNB_tasks(node_type, uniqCfg);
    AssertFatal(ret == 0, "cannot create ITTI tasks\n");
  }

  pthread_cond_init(&sync_cond,NULL);
  pthread_mutex_init(&sync_mutex, NULL);
  usleep(1000);

  if (NFAPI_MODE && NFAPI_MODE != NFAPI_MODE_AERIAL) {
    pthread_cond_init(&sync_cond,NULL);
    pthread_mutex_init(&sync_mutex, NULL);
  }

  // start time manager with some reasonable default for the running mode
  // (may be overwritten in configuration file or command line)
  void nr_pdcp_ms_tick(void);
  void x2ap_ms_tick();
  void nr_rlc_ms_tick(void);
  time_manager_tick_function_t tick_functions[3];
  int tick_functions_count = 0;
  if (NODE_IS_MONOLITHIC(node_type)) {
    /* monolithic */
    tick_functions[tick_functions_count++] = nr_pdcp_ms_tick;
    tick_functions[tick_functions_count++] = nr_rlc_ms_tick;
    /* x2ap is enabled when in NSA mode */
    if (get_softmodem_params()->nsa)
      tick_functions[tick_functions_count++] = x2ap_ms_tick;
  } else if (NODE_IS_CU(node_type)) {
     /* CU */
    tick_functions[tick_functions_count++] = nr_pdcp_ms_tick;
    /* x2ap is enabled when in NSA mode */
    if (get_softmodem_params()->nsa)
      tick_functions[tick_functions_count++] = x2ap_ms_tick;
  } else {
     /* DU */
    tick_functions[tick_functions_count++] = nr_rlc_ms_tick;
  }
  time_manager_start(tick_functions, tick_functions_count,
                     // iq_samples time source for monolithic/du with rfsim,
                     // realtime time source for other cases
                     IS_SOFTMODEM_RFSIM
                     && (NODE_IS_MONOLITHIC(node_type) || NODE_IS_DU(node_type))
                         ? TIME_SOURCE_IQ_SAMPLES
                         : TIME_SOURCE_REALTIME);

  // start the main threads
  number_of_cards = 1;

  wait_gNBs();
  int sl_ahead = NFAPI_MODE == NFAPI_MODE_AERIAL ? 0 : 6;
  if (RC.nb_RU >0) {
    init_NR_RU(uniqCfg, get_softmodem_params()->rf_config_file);

    for (ru_id=0; ru_id<RC.nb_RU; ru_id++) {
      RC.ru[ru_id]->rf_map.card=0;
      RC.ru[ru_id]->rf_map.chain=CC_id+chain_offset;
      if (ru_id==0) sl_ahead = RC.ru[ru_id]->sl_ahead;	
      else AssertFatal(RC.ru[ru_id]->sl_ahead != RC.ru[0]->sl_ahead,"RU %d has different sl_ahead %d than RU 0 %d\n",ru_id,RC.ru[ru_id]->sl_ahead,RC.ru[0]->sl_ahead);
    }
    
  }

  config_sync_var=0;


#ifdef E2_AGENT

//////////////////////////////////
//////////////////////////////////
//// Init the E2 Agent

  // OAI Wrapper 
  e2_agent_args_t oai_args = RCconfig_NR_E2agent();

  if (oai_args.enabled) {
    initialize_agent(node_type, oai_args);
  }

#endif // E2_AGENT

#ifdef JBPF_HOOK
  /*
   * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   * JANUS (jbpf) eBPF 프레임워크 초기화
   * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   *
   * JBPF는 userspace eBPF 프레임워크로, gNB의 프로토콜 계층(SDAP/PDCP/RLC)에
   * Hook을 삽입하여 런타임에 로드 가능한 eBPF Codelet으로 패킷 모니터링/분류 수행
   *
   * 주요 기능:
   * - 런타임 Codelet 로딩 (LCM IPC를 통해 YAML 기반 배포)
   * - 패킷 통계 수집 (UE별 throughput, latency)
   * - QFI별 트래픽 분류 (QoS Flow 분석)
   * - 커스텀 패킷 필터링/수정 (향후 확장 가능)
   */
  LOG_I(GNB_APP, "Initializing JANUS (jbpf) framework...\n");

  /* 1. JBPF 설정 구조체 초기화 */
  struct jbpf_config jbpf_config = {0};
  jbpf_set_default_config_options(&jbpf_config);

  /*
   * 2. LCM (Life-Cycle Management) IPC 설정
   *
   * Unix Domain Socket을 통해 외부 도구(jbpf_lcm_cli)에서
   * 런타임에 codeletset을 로드/언로드 가능
   *
   * 사용 예시:
   *   jbpf_lcm_cli load -s /tmp/jbpf_oai_gnb.sock -c oai_gnb_monitoring.yaml
   */
  jbpf_config.lcm_ipc_config.has_lcm_ipc_thread = true;
  snprintf(
      jbpf_config.lcm_ipc_config.lcm_ipc_name,
      sizeof(jbpf_config.lcm_ipc_config.lcm_ipc_name) - 1,
      "%s",
      "jbpf_oai_gnb"
  );

  /*
   * 3. I/O 채널 모드 설정
   *
   * JBPF_IO_THREAD_CONFIG: Standalone 모드 (콜백 기반)
   *   - Codelet의 ringbuf 출력 → 콜백 핸들러로 전달
   *   - 별도 IPC 프로세스 불필요
   *
   * 참고: JBPF_IO_IPC_CONFIG는 별도 프로세스와 공유 메모리 통신 시 사용
   */
  jbpf_config.io_config.io_type = JBPF_IO_THREAD_CONFIG;

  /* 4. JBPF 라이브러리 초기화 */
  if (jbpf_init(&jbpf_config) < 0) {
    LOG_E(GNB_APP, "Failed to initialize JBPF framework\n");
    return -1;
  }

  /*
   * 5. 현재 스레드를 JBPF에 등록
   *
   * jbpf는 스레드별로 eBPF VM 컨텍스트를 관리하므로,
   * hook을 호출하는 모든 스레드는 등록 필요
   *
   * 주의: nr-softmodem의 워커 스레드(RU/L1/L2 thread)에서도
   *       hook 호출 시 해당 스레드에서 jbpf_register_thread() 필요
   */
  jbpf_register_thread();

  /*
   * 6. I/O 출력 콜백 핸들러 등록
   *
   * Codelet이 jbpf_ringbuf_output()로 데이터 전송 시
   * jbpf_io_output_handler() 함수가 자동 호출됨
   * Callback 등록은 jbpf_register_io_output_cb()로 수행
   * 
   */
  jbpf_register_io_output_cb(jbpf_io_output_handler);

  LOG_I(GNB_APP, "JANUS (jbpf) framework initialized successfully\n");
  LOG_I(GNB_APP, "  - LCM IPC socket: /tmp/jbpf/jbpf_oai_gnb\n");
  LOG_I(GNB_APP, "  - I/O mode: Local (callback-based)\n");
  LOG_I(GNB_APP, "Load codelets with: jbpf_lcm_cli load -s /tmp/jbpf/jbpf_oai_gnb -c <yaml>\n");
#endif // JBPF_HOOK

  // wait for F1 Setup Response before starting L1 for real
  if (NFAPI_MODE != NFAPI_MODE_PNF && (NODE_IS_DU(node_type) || NODE_IS_MONOLITHIC(node_type)))
    wait_f1_setup_response();

  if (RC.nb_RU > 0)
    start_NR_RU();

#ifdef ENABLE_AERIAL
  gNB_MAC_INST *nrmac = RC.nrmac[0];
  nvIPC_Init(nrmac->nvipc_params_s);
#endif

  for (int idx = 0; idx < RC.nb_nr_L1_inst; idx++)
    RC.gNB[idx]->if_inst->sl_ahead = sl_ahead;

  if (NFAPI_MODE==NFAPI_MODE_PNF) {
    wait_nfapi_init("main?");
  }

  if (RC.nb_nr_L1_inst > 0) {
    wait_RUs();
    // once all RUs are ready initialize the rest of the gNBs ((dependence on final RU parameters after configuration)

    if (IS_SOFTMODEM_DOSCOPE || IS_SOFTMODEM_IMSCOPE_ENABLED || IS_SOFTMODEM_IMSCOPE_RECORD_ENABLED) {
      sleep(1);
      scopeParms_t p;
      p.argc = &argc;
      p.argv = argv;
      p.gNB = RC.gNB[0];
      p.ru = RC.ru[0];
      if (IS_SOFTMODEM_DOSCOPE) {
        load_softscope("nr", &p);
      }
      if (IS_SOFTMODEM_IMSCOPE_ENABLED) {
        load_softscope("im", &p);
      }
      AssertFatal(!(IS_SOFTMODEM_IMSCOPE_ENABLED && IS_SOFTMODEM_IMSCOPE_RECORD_ENABLED),
                  "Data recoding and ImScope cannot be enabled at the same time\n");
      if (IS_SOFTMODEM_IMSCOPE_RECORD_ENABLED) {
        load_module_shlib("imscope_record", NULL, 0, &p);
      }
    }

    if (NFAPI_MODE != NFAPI_MODE_PNF && NFAPI_MODE != NFAPI_MODE_VNF && NFAPI_MODE != NFAPI_MODE_AERIAL) {
      init_eNB_afterRU();
    }

    // connect the TX/RX buffers
    pthread_mutex_lock(&sync_mutex);
    sync_var=0;
    pthread_cond_broadcast(&sync_cond);
    pthread_mutex_unlock(&sync_mutex);
  }

  // wait for end of program
  printf("TYPE <CTRL-C> TO TERMINATE\n");
  // Sleep a while before checking all parameters have been used
  // Some are used directly in external threads, asynchronously
  sleep(2);
  config_check_unknown_cmdlineopt(uniqCfg, CONFIG_CHECKALLSECTIONS);

  itti_wait_tasks_end(NULL);
  printf("Returned from ITTI signal handler\n");

  nfapi_stop_l1();

  if (RC.nb_nr_L1_inst > 0 || RC.nb_RU > 0)
    stop_L1(0);

  if (RC.nb_nr_macrlc_inst > 0) {
    DevAssert(RC.nb_nr_macrlc_inst == 1);
    mac_top_destroy_gNB(RC.nrmac[0]);
  }

  pthread_cond_destroy(&sync_cond);
  pthread_mutex_destroy(&sync_mutex);
  pthread_cond_destroy(&nfapi_sync_cond);
  pthread_mutex_destroy(&nfapi_sync_mutex);

  time_manager_finish();

  free(pckg);
  logClean();
  printf("Bye.\n");
  return 0;
}
