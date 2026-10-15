# qos_weight 멀티-UE 로직 회귀 테스트
#
#   make      빌드 + 실행
#   make run  실행만
#
# gNB 를 띄우지 않고 호스트 측 가중치 테이블만 단독 검증한다.
# stub/ 의 로그 스텁을 include 경로 앞에 두어 OAI 로그 서브시스템을
# 링크하지 않는다 (qos_weight.c 는 LOG_W/LOG_I 만 쓴다).
#
# /dev/shm 에 빌드하는 이유: 일부 환경에서 /tmp 가 noexec 로 마운트된다.

CC     := gcc
ROOT   := ../../..
BIN    := /dev/shm/test_qos_weight
CFLAGS := -O1 -Wall -Wextra -I stub -I .. -I $(ROOT)/common -I $(ROOT)
LDLIBS := -lpthread

.PHONY: all run clean

all: run

$(BIN): test_qos_weight.c ../qos_weight.c ../qos_weight.h
	$(CC) $(CFLAGS) test_qos_weight.c ../qos_weight.c -o $@ $(LDLIBS)

run: $(BIN)
	@$(BIN)

clean:
	rm -f $(BIN)
