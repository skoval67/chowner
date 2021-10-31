// chowner.cpp : Defines the entry point for the console application.
//

#include <windows.h>
#include "aclapi.h"
#include "locale.h"
#include <shlwapi.h>
#include "targetver.h"
#include <stdio.h>
#include <tchar.h>

#define MAX_DOMAIN_NAME_LEN 255
#define ERR_MESSAGE_LEN 512
#define MAXPATHLEN 1024
#define MAXNAMELEN 256

struct node {
  LPTSTR buf;
  struct node *next;
};

node *root = NULL, *current;
TCHAR error_message[ERR_MESSAGE_LEN];
PSID psidOwner = NULL;
TCHAR PathAndFiles[MAXPATHLEN];
BOOLEAN bRecurseSubdirs = false;
TCHAR Files[MAXPATHLEN] = L"";
TCHAR Path[MAXPATHLEN] = L"";

void Usage(const wchar_t *cmdname)
{
  wprintf(L"Usage: %s [-r] [-f files] owner\n", cmdname);
  wprintf(L"       change the owner of selected files\n"
          L"       -r (recursive)  recurse subdirectories\n"
          L"       -f files        files to be modified (may contain wildcards * and ?)\n"
          L"       owner           new owner of files\n"
		  L"Examples:\n");
  wprintf(L"       %s -f *.txt domain\\user\n", cmdname);
  wprintf(L"       dir /b . | %s domain\\user\n", cmdname);
  exit(EXIT_FAILURE); 
}

void GetErrorMessage(LPTSTR s)
{
  LPVOID lpMsgBuf;

  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    GetLastError(),
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPTSTR) &lpMsgBuf, 0, NULL );
  wcscpy_s(s, ERR_MESSAGE_LEN, (LPTSTR) lpMsgBuf);
  LocalFree(lpMsgBuf);
}

void PrintErrorMessage()
{
  TCHAR error_str[ERR_MESSAGE_LEN];
  
  GetErrorMessage(error_str);
  fwprintf_s(stderr, error_str);
}

node *node_add(node **p, LPTSTR s)
{
  if (p == NULL)           /*checks to see if the pointer points somewhere in space*/
    return NULL;
 
  node *n = (node*) LocalAlloc(LMEM_FIXED, sizeof(node));   /* creates a new node of the correct data size */
  if (n == NULL) {
	PrintErrorMessage();
    return NULL;
  };
 
  size_t buflen = wcslen(s) * sizeof(TCHAR);
  n->buf = new TCHAR[buflen];
  if ( n->buf == NULL ) {
    PrintErrorMessage();
	LocalFree(n);
	return NULL;
  };
  wcscpy_s(n->buf, buflen, s); 
  
  n->next = *p; /* the previous element (*p) now becomes the "next" element */
  *p = n;       /* add new empty element to the front (head) of the list */
 
  return *p;
}
 
void node_remove(node **p) /* remove head */
{
  if (p != NULL && *p != NULL)
  {
    node *n = *p;
	delete[] (*p)->buf;
    *p = (*p)->next;
    LocalFree(n);
  }
}

/*
void list_print(node *n)
{
  if (n == NULL) printf("list is empty\n");
  while (n != NULL) {
    wprintf(L"print %p %p %s\n", n, n->next, n->buf);
    n = n->next;
  }
}
*/

node *reverse (node *p)
{
   node *pr = NULL;
   while (p != NULL)
   {
      node *tmp = p->next;
      p->next = pr;
      pr = p;
      p = tmp;
   }
   return pr;
}

bool need_help(wchar_t *arg)
{
  wchar_t *p = arg;

  if (*p == '/' || *p == '-') {
    switch (tolower(*++p)) {
      case '?':;
      case 'h': return true;
    };
  };
  
  return false;
}

BOOLEAN ProcessCmdLine(int argcount, _TCHAR* argvalues[])
{
  DWORD dwsid = 0;
  DWORD dwdomain = 0;
  SID_NAME_USE eUse = SidTypeUnknown;
  TCHAR DomainName[MAX_DOMAIN_NAME_LEN];
  TCHAR Owner[MAXNAMELEN];
  TCHAR c, *p;

  if ((argcount == 1) || (argcount == 2) && need_help(argvalues[1]))
    Usage(PathFindFileName(argvalues[0]));

  wcscpy_s(Owner, MAXNAMELEN, argvalues[--argcount]);			// last arg: owner
  psidOwner = LocalAlloc(LMEM_FIXED, SECURITY_MAX_SID_SIZE);
  LookupAccountName(NULL, Owner, NULL, &dwsid, NULL, &dwdomain, &eUse);
  if (dwdomain >= MAX_DOMAIN_NAME_LEN) {
    SetLastError(1212);						// ERROR_INVALID_DOMAINNAME
    return false;
  };
  if (!LookupAccountName(NULL, Owner, psidOwner, &dwsid, DomainName, &dwdomain, &eUse))
    return false;

  if ( argcount > 1 ) { 
    // other args: options
    while (--argcount > 0 ) { 
      p = *++argvalues; 
      if ( *p == '/' || *p == '-' ) { 
        c = *++p;
        switch (tolower(c)) { 
          case 'r': 
            bRecurseSubdirs = true; 
            break; 
          case 'f':
            p = *++argvalues; 
	      		node_add(&root, (LPTSTR)p);
            argcount--;
            break;
          default: 
            Usage(PathFindFileName(argvalues[0]));
            break; 
        }; 
      }
    } 
  }; 
  
  return true;
}

BOOLEAN SetPrivilege(LPCTSTR Privilege, BOOLEAN bEnablePrivilege)
{
  TOKEN_PRIVILEGES tp;
  LUID luid;
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES tpPrevious;
  DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
  
  if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) ) {
    PrintErrorMessage();
	return false;
  };
  if ( !LookupPrivilegeValue( 
        NULL,				        // lookup privilege on local system
        Privilege,      			// privilege to lookup 
        &luid ) )			        // receives LUID of privilege
    return false; 

  // first pass.  get current privilege setting
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = 0;

  AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);
  if (GetLastError() != ERROR_SUCCESS)
    return false;

  // second pass.  set privilege based on previous setting
  tpPrevious.PrivilegeCount = 1;
  tpPrevious.Privileges[0].Luid = luid;

  if(bEnablePrivilege)
    tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
  else
    tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);

  AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL);
  if (GetLastError() != ERROR_SUCCESS)
    return false;

  if (hToken) CloseHandle(hToken);
  
  return true;
}

BOOLEAN ModifyFiles(const TCHAR *szPath, const TCHAR *szFiles)
{
  WIN32_FIND_DATA FindFileData; 
  HANDLE hFind;
  TCHAR szFullPath[MAXPATHLEN];
  TCHAR szCurrentFile[MAXPATHLEN];

  wcscpy_s(szFullPath, MAXPATHLEN, szPath);
  wcscat_s(szFullPath, MAXPATHLEN, szFiles);

  hFind = FindFirstFile(szFullPath, &FindFileData);
  if (hFind == INVALID_HANDLE_VALUE)
    return GetLastError() == 2 && bRecurseSubdirs;
  
  do {
    if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY ||
         wcscmp(FindFileData.cFileName, L".") == 0 || wcscmp(FindFileData.cFileName, L"..") == 0)
      continue;

    wcscpy_s(szCurrentFile, MAXPATHLEN, szPath);
    wcscat_s(szCurrentFile, MAXPATHLEN, FindFileData.cFileName);

	wprintf(L"Processing %s ...\n", szCurrentFile);

    if (SetNamedSecurityInfo(szCurrentFile,
                      SE_FILE_OBJECT,
                      OWNER_SECURITY_INFORMATION,
                      psidOwner,
                      NULL,
                      NULL,
                      NULL) != ERROR_SUCCESS)
      PrintErrorMessage();
  }
  while (FindNextFile(hFind, &FindFileData));
  
  if ( GetLastError() != ERROR_NO_MORE_FILES ) {
    PrintErrorMessage();
    return false;
  };

  FindClose(hFind);
  return true;
}

BOOLEAN RecurseDirectories(const LPTSTR szPath, const LPTSTR szFiles)
{
  HANDLE hFiles;
  WIN32_FIND_DATA FindData;
  TCHAR szFullPath[MAXPATHLEN];
  TCHAR szCurrentDir[MAXPATHLEN];

  if ( !ModifyFiles(szPath,szFiles) )
    PrintErrorMessage();
  wcscpy_s(szFullPath, MAXPATHLEN, szPath);
  wcscat_s(szFullPath, MAXPATHLEN, L"*");
  hFiles=FindFirstFileEx(szFullPath,
                         FindExInfoStandard,
                         &FindData,
                         FindExSearchLimitToDirectories,
                         NULL,
                         0);
  if (hFiles == INVALID_HANDLE_VALUE) {
    if (GetLastError() == 2)            // No subdirectories found
      return true;
    PrintErrorMessage();
    return false;
  };
  do {
    wcscpy_s(szCurrentDir, MAXPATHLEN, szPath);
    wcscat_s(szCurrentDir, MAXPATHLEN, FindData.cFileName);
    if ( (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY &&
          wcscmp(FindData.cFileName, L".") != 0 && wcscmp(FindData.cFileName, L"..") != 0 ) {
      if ( szCurrentDir[wcslen(szCurrentDir)-1] != '\\' ) wcscat_s(szCurrentDir, MAXPATHLEN, L"\\");
      RecurseDirectories(szCurrentDir, szFiles);
    };
  } while (FindNextFile(hFiles, &FindData));
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    PrintErrorMessage();
    return false;
  };
  FindClose(hFiles);
  return true;
}

void FreeBuff() {
  if (psidOwner) LocalFree(psidOwner);
  while (root) {
    node_remove(&root);
  };
}

void ChangeOwner(const LPTSTR szPathAndFiles)
{
  LPTSTR pFileName;

  if (GetFullPathName(szPathAndFiles,
                      MAXPATHLEN,
                      Path,
                      &pFileName) == 0) {
    PrintErrorMessage();
    return;
  };
  if (!PathIsDirectory(szPathAndFiles)) {
    if (pFileName != NULL) wcscpy_s(Files, MAXPATHLEN, pFileName);
    Path[wcslen(Path)-wcslen(Files)] = 0;
  }; 
  if (Path[wcslen(Path)-1] != L'\\') wcscat_s(Path, MAXPATHLEN, L"\\");
  
  if (wcscspn(Files, L"*?") == wcslen(Files)) bRecurseSubdirs = false;	// Files не содержит подстановочных символов

  if (bRecurseSubdirs)
    RecurseDirectories(Path, Files);
  else
    if ( !ModifyFiles(Path, Files) )
	  PrintErrorMessage();
  return;
}

int _tmain(int argc, _TCHAR* argv[])
{
  _wsetlocale(LC_ALL, L"Russian");

  fseek(stdin, 0, SEEK_END);
  if (ftell(stdin)) {
    fseek(stdin, 0, SEEK_SET);
    while (_getws_s(PathAndFiles, MAXPATHLEN) && node_add(&root, PathAndFiles)) {};
  };

  if (!ProcessCmdLine(argc, argv)) {
	  PrintErrorMessage();
	  FreeBuff();
    return 1;
  };
  
  root = reverse(root);
  
  if (!SetPrivilege(SE_RESTORE_NAME, true)) {
    PrintErrorMessage();
    FreeBuff();
    return 1;
  };

  current = root;
  while (current) {
	  ChangeOwner(current->buf);
	  current = current->next;
  };

  FreeBuff();
  SetPrivilege(SE_RESTORE_NAME, false);

  return 0;
}

