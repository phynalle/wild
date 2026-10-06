__declspec(dllimport) int puts(const char *);
__declspec(dllimport) void *CreateThread(void *, unsigned long long, unsigned long (*)(void *),
                                         void *, unsigned long, unsigned long *);
__declspec(dllimport) unsigned long WaitForSingleObject(void *, unsigned long);
__declspec(dllimport) int GetExitCodeThread(void *, unsigned long *);
__declspec(dllimport) int CloseHandle(void *);
__declspec(thread) int tls_value = 13;
static int initialized;
static void initialize(void) { initialized = 29; }
#pragma section(".CRT$XCU", read)
__declspec(allocate(".CRT$XCU")) static void (*constructor)(void) = initialize;
static unsigned long worker(void *unused) {
  (void)unused;
  if (tls_value != 13) return 1;
  tls_value = 99;
  return tls_value;
}
int main(void) {
  if (initialized != 29 || tls_value != 13) return 1;
  tls_value += initialized;
  for (int i = 0; i < 8; i++) {
    void *thread = CreateThread(0, 0, worker, 0, 0, 0);
    unsigned long result = 0;
    if (!thread || WaitForSingleObject(thread, 0xffffffff) != 0 ||
        !GetExitCodeThread(thread, &result) || result != 99)
      return 3;
    CloseHandle(thread);
  }
  puts("native CRT/TLS OK");
  return tls_value == 42 ? 0 : 2;
}
