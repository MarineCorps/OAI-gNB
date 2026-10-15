# jbpf — vendored snapshot

이 디렉터리는 **git submodule 이 아니다.** `microsoft/jbpf` 의 특정 커밋을
*패치가 적용된 상태로* OAI-gNB 저장소에 직접 포함(vendoring)한 것이다.

| | |
|---|---|
| upstream | https://github.com/microsoft/jbpf |
| commit | `b15dd0306b8be9ce1217f9de84411c36699de2d3` (`heads/main`) |
| vendored | 2026-10-14 |
| license | MIT — `LICENSE`, 하위 의존성 attribution 은 `NOTICE` |

## 왜 vendoring 했나

submodule 로 두면 **클론만으로는 빌드되지 않는다.**

1. 이 트리 안에 중첩 submodule 이 **23개** 있다 (최대 5단계 깊이).
   `3p/ck`, `3p/mimalloc`, `3p/ubpf`, `3p/ebpf-verifier` 와 그들의 하위 의존성.
2. 빌드 전에 `init_and_patch_submodules.sh` 가 `git apply` 로 **패치 3개**를
   입혀야 한다 — `patches/ck.patch`, `patches/mimalloc.patch`,
   `patches/ebpf_verifier.patch`.

즉 `git clone --recursive` 로도 "빌드되는 상태"에 도달하지 못하고, 패치 단계를
사람이 기억해서 실행해야 했다. 다른 머신에서 재현이 깨지던 원인이 이것이다.

지금 이 트리는 **그 패치들이 이미 적용된 상태**로 커밋되어 있다. 클론 한 번으로
빌드 가능한 상태가 된다.

## 클론 후 빌드

```bash
cd third_party/jbpf
source ./setup_jbpf_env.sh
mkdir -p build && cd build
cmake .. && make -j$(nproc)
sudo make install        # → out/lib/libjbpf.so, out/bin/jbpf_lcm_cli
```

`init_and_patch_submodules.sh` 는 신경 쓰지 않아도 된다. vendoring 상태를
감지하면 아무 일도 하지 않고 성공으로 빠지도록 가드를 넣어 두었다
(이 파일이 그 변경 사실에 대한 고지다).

가드가 필요한 이유는 그 스크립트의 첫 동작이
`rm -rf 3p/{ebpf-verifier,mimalloc,ck,ubpf}` 이기 때문이다. vendoring
상태에서는 `git submodule update` 가 등록된 submodule 이 없어 아무것도
복원하지 못하므로, 한 번 실행하면 트리가 복구 불가하게 깨진다.

가드가 `exit 1` 이 아니라 `exit 0` 인 것도 중요하다. 이 스크립트는 사람이
직접 부르는 것만이 아니라 jbpf 의 `CMakeLists.txt:46` 이 configure 중에
`execute_process()` 로 호출하고, 0 이 아니면 `FATAL_ERROR` 로 빌드를
중단시킨다. vendoring 상태는 "이미 초기화·패치 완료"이므로 성공이 맞다.

빌드가 끝나면 OAI 쪽은 자동으로 이 경로를 찾는다
(`CMakeLists.txt` 의 `JBPF_SUBMODULE_OUT` 우선 탐색).

## 저장소에 포함되지 않는 것

`.gitignore` 로 제외했다 — 재생성 가능한 산출물이다.

| 경로 | 크기 | 비고 |
|---|---|---|
| `build/` | 94 M | CMake 빌드 디렉터리. 절대 경로가 박힌 캐시 포함 |
| `out/` | 25 M | `make install` 결과 (`libjbpf.so`, `jbpf_lcm_cli`, `inc/`) |

소스는 **119 M**이다. 대부분이 `3p/ubpf/external/`(65 M, ubpf 의 테스트
의존성)과 `3p/ebpf-verifier/`(34 M)다. `3p/ubpf/external/` 은 jbpf 의
`3p/ebpf-verifier` 와 내용이 겹치지만, 제외하면 ubpf 의 CMake 가 깨질 수 있어
"클론하면 빌드된다"는 보장을 지키기 위해 그대로 포함했다.

## 라이선스

전부 permissive 이고, 각 디렉터리의 `LICENSE` 파일과 jbpf 의 `NOTICE`(34 KB,
하위 의존성 attribution 집계)를 **삭제하지 않는 것**이 유지 조건이다.

| 구성요소 | 라이선스 | 저작권자 |
|---|---|---|
| jbpf | MIT | Microsoft Corporation |
| `3p/ck` | BSD-2-Clause | Samy Al Bahra · AppNexus |
| `3p/mimalloc` | MIT | Microsoft · Daan Leijen |
| `3p/ubpf` | Apache-2.0 | IO Visor Project |
| `3p/ebpf-verifier` | MIT (+ Apache-2.0 동봉) | vbpf project |

OAI 본체는 OAI Public License V1.1 (Apache-2.0 파생)이고, 위 라이선스들과
모두 호환된다. OAI 자신도 `nfapi/open-nFAPI/` 를 같은 방식으로 포함하고 있다.

Apache-2.0(`3p/ubpf`)의 "변경 사실 표시" 조항 대상이 되는 로컬 수정:

- `init_and_patch_submodules.sh` — vendoring 감지 가드 추가 (jbpf 본체, MIT)
- `3p/ck`, `3p/mimalloc`, `3p/ebpf-verifier` — `patches/` 의 패치 적용 상태
- `3p/ubpf` 자체에는 패치를 적용하지 않았다

## 업스트림 업데이트 방법

submodule 추적을 포기했으므로 `git submodule update` 로는 갱신되지 않는다.
수동 절차:

```bash
# 1. 업스트림을 별도 위치에 클론하고 패치까지 적용
git clone https://github.com/microsoft/jbpf /tmp/jbpf-new
cd /tmp/jbpf-new && ./init_and_patch_submodules.sh

# 2. 현재 트리와 비교 (build/, out/, .git 제외)
diff -r --exclude=.git --exclude=build --exclude=out \
     /tmp/jbpf-new ~/OAI-gNB/third_party/jbpf

# 3. 교체하려면 — 중첩 .git 을 반드시 먼저 제거할 것
find /tmp/jbpf-new -name .git -exec rm -rf {} +
rsync -a --delete --exclude=build --exclude=out --exclude=UPSTREAM.md \
      /tmp/jbpf-new/ ~/OAI-gNB/third_party/jbpf/

# 4. 이 파일의 commit 해시를 갱신하고 커밋
```

교체 후에는 OAI 쪽 hook context 구조체
(`openair2/JBPF/pdcp_hook_ctx.h`, `mac_scheduler_hooks.h`)와
`jbpf_helper.h` 의 helper 시그니처가 여전히 맞는지 확인해야 한다.
