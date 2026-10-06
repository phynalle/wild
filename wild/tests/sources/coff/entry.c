__declspec(dllimport) void ExitProcess(unsigned long code);
static int data = 17;
void entry(void) { ExitProcess(data + 25); }
