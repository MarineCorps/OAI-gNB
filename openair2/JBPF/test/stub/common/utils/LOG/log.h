/* 테스트용 로그 스텁 — OAI 로그 서브시스템을 링크하지 않기 위해 */
#ifndef LOG_STUB_H
#define LOG_STUB_H
#define GNB_APP 0
#define LOG_W(c, x...) ((void)0)
#define LOG_I(c, x...) ((void)0)
#define LOG_D(c, x...) ((void)0)
#define LOG_E(c, x...) ((void)0)
#endif
