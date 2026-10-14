#!/bin/bash
#
# ─────────────────────────────────────────────────────────────────────
# 로컬 수정 (OAI-gNB fork) — Apache-2.0 / MIT 의 "변경 사실 표시" 조항용 고지
#
# 이 트리는 OAI-gNB 저장소에 *vendoring* 되어 있다. 3p/ 아래 의존성들은
# 더 이상 git submodule 이 아니라 저장소가 직접 추적하는 일반 파일이고,
# 아래 패치들이 *이미 적용된* 상태로 커밋되어 있다.
#
# 이 스크립트는 첫 동작이 `rm -rf 3p/{ebpf-verifier,mimalloc,ck,ubpf}` 다.
# vendoring 된 트리에서 실행하면 그 디렉터리들을 삭제하고,
# `git submodule update` 는 등록된 submodule 이 없어 아무것도 복원하지 못한다.
# → 복구 불가. 그래서 vendoring 상태(.git 없음)를 감지하면 rm 전에 빠진다.
#
# exit 0 (실패가 아니라 "할 일 없음") 인 이유:
#   이 스크립트는 사람이 직접 부르는 것만이 아니라 CMakeLists.txt:46 의
#   execute_process() 가 configure 중에 호출하고, 0 이 아니면
#   FATAL_ERROR 로 빌드를 중단시킨다. vendoring 상태는 "이미 초기화되고
#   패치된 상태"이므로 성공으로 보고하는 것이 맞다.
#   (-DINITIALIZE_SUBMODULES=OFF 로 우회할 수도 있지만, 빌드할 때마다
#    플래그를 기억해야 한다면 vendoring 의 목적이 사라진다.)
#
# 자세한 내용: third_party/jbpf/UPSTREAM.md
# ─────────────────────────────────────────────────────────────────────
if [ ! -e "$(dirname "$0")/.git" ]; then
    cat <<'MSG'
[jbpf] vendoring 된 트리이므로 submodule 초기화/패치를 건너뛴다.
       3p/ 의존성들은 패치가 적용된 채로 이미 저장소에 들어 있다.
       (자세한 내용: third_party/jbpf/UPSTREAM.md)
MSG
    exit 0
fi

rm -rf 3p/ebpf-verifier 3p/mimalloc 3p/ck 3p/ubpf
git submodule update --init --recursive

cp patches/ck.patch 3p/ck
cp patches/mimalloc.patch 3p/mimalloc
cp patches/ebpf_verifier.patch 3p/ebpf-verifier/

cd 3p/ck
git apply ck.patch

cd ../mimalloc
git apply mimalloc.patch

cd ../ebpf-verifier/
git apply ebpf_verifier.patch
