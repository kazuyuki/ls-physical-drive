//
//ntdll.h
//
#include <windef.h>

//typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	MySystemPowerInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation=1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation = 9,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileCopyOnWriteInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileObjectIdInformation,
	FileTrackingInformation,
	FileOleDirectoryInformation,
	FileContentIndexInformation,
	FileInheritContentIndexInformation,
	FileOleInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _FILE_NAME_INFORMATION {
	ULONG  FileNameLength;
	WCHAR  FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO { 
	USHORT UniqueProcessId; 
	USHORT CreatorBackTraceIndex; 
	UCHAR ObjectTypeIndex; 
	UCHAR HandleAttributes; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT USHORT HandleValue; 
	PVOID Object; 
	ACCESS_MASK GrantedAccess; 
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO; 

typedef struct _SYSTEM_HANDLE_INFORMATION { 
	ULONG NumberOfHandles; 
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles; 
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION; 

/* ntdll内部関数 */
typedef NTSYSAPI NTSTATUS (NTAPI *PNtQueryInformationFile ) 
	 ( HANDLE FileHandle, 
            PIO_STATUS_BLOCK IoStatusBlock,
	   PVOID FileInformation,
	   ULONG Length,
	   FILE_INFORMATION_CLASS FileInformationClass );

typedef NTSYSAPI NTSTATUS (NTAPI *PNtQuerySystemInformation )
	( SYSTEM_INFORMATION_CLASS SystemInformationClass,
	  PVOID SystemInformation,
	  ULONG SystemInformationLength,
	  PULONG ReturnLength );

typedef NTSTATUS (NTAPI *PNtQueryObject )
	( HANDLE ObjectHandle,
	  DWORD ObjectInformationClass,
	  PVOID ObjectInformation,
	  ULONG Length,
	  PULONG ResultLength );

//
//unlock.cpp
//

#include <stdio.h>
#include <windows.h>
#include <wchar.h>
#include <process.h>
#include <ntsecapi.h>
#include "ntdll.h"

// DLLロード用のハンドル
HMODULE hLoadDll = NULL;

//DLLロード用関数(LoadLibraryで動的に呼び出す。)
PNtQueryInformationFile NtQueryInformationFile;
PNtQuerySystemInformation NtQuerySystemInformation;
PNtQueryObject NtQueryObject;

bool InitNativeFunctions()
{
	hLoadDll = LoadLibraryA( "C:/WINDOWS/SYSTEM32/ntdll.dll" );
	NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(hLoadDll,(LPCSTR)"NtQuerySystemInformation" );

	NtQueryObject = (PNtQueryObject)GetProcAddress(hLoadDll,(LPCSTR)"NtQueryObject");

	NtQueryInformationFile = (PNtQueryInformationFile)GetProcAddress(hLoadDll,(LPCSTR)"NtQueryInformationFile" );

	FreeLibrary( hLoadDll );
	return NtQuerySystemInformation && NtQueryObject && NtQueryInformationFile;
}

// 自プロセスに関連付けられたファイルで解放せずに残ったハンドルのロック解除する関数
long FileUnLock( const char *pucUnlockFileName )
{
	// 自プロセスに関連したハンドルとそのパス名をもれなく列挙する方法
	DWORD iMaxHandleNum = 10000;
	UCHAR *ucFileBuffer[MAX_PATH*2];
	UCHAR* pucQueryBuffer = NULL;
	wchar_t *pwcUnlockFileName = NULL;
	wchar_t pName[MAX_PATH*2];
	DWORD dwRet = 0;
	DWORD dwPathLen = 0;
	BOOL bRet = TRUE;
	int i;
	int iStrLen = 0;
	int iwStrLen = 0;

	HANDLE SelfProcessHandle;
	DWORD dwQueryObjSize = 0;
	PFILE_NAME_INFORMATION pFNI = NULL; 
	IO_STATUS_BLOCK iob;
	iStrLen = strlen( pucUnlockFileName )+1;
	for( i=0 ; i<(int)iMaxHandleNum; i++ )
	{
		dwQueryObjSize = 0;
		SelfProcessHandle = (HANDLE)i;
		// Query の情報サイズを取得( windows非公開関数使用 )
		NtQueryObject( SelfProcessHandle, ObjectTypeInformation, NULL, 0, &dwQueryObjSize );
		// サイズ0の場合は次のハンドルへ
		if( dwQueryObjSize == 0 ) continue;
		pucQueryBuffer = new UCHAR[dwQueryObjSize];
		if( pucQueryBuffer == NULL )
		{
			return -2;
		}
		// Queryの情報取得( type = 2 = ObjectTypeInformation) ( windows非公開関数使用 )
		if( NtQueryObject( SelfProcessHandle, 
			ObjectTypeInformation, 
			pucQueryBuffer, dwQueryObjSize, NULL ) == 0 )
		{
			// 取得したハンドルがファイルハンドルかどうかチェック
			if( _wcsicmp(L"File", (wchar_t*)(pucQueryBuffer+0x60)) != 0 )
			{
				if( pucQueryBuffer != NULL )
				{
					delete[] pucQueryBuffer;
					pucQueryBuffer = NULL;
				}
				continue;
			}
			// ファイルハンドルからハンドルに関連付けられたパス名を取得( windows非公開関数使用 )
			dwRet = NtQueryInformationFile( SelfProcessHandle, 
			                              &iob, 
			                              ucFileBuffer, 
			                              MAX_PATH*2, FileNameInformation );
			pFNI = (PFILE_NAME_INFORMATION)ucFileBuffer;
			if( dwRet == 0 )
			{
				dwPathLen = pFNI->FileNameLength/2;
				if ( dwPathLen > MAX_PATH ) dwPathLen = MAX_PATH-1;
				wcsncpy( pName, pFNI->FileName, dwPathLen );
				iwStrLen = mbstowcs( NULL, pucUnlockFileName, iStrLen );
				if( iwStrLen == -1 )
				{
				   return -1;
				}
				pwcUnlockFileName = new wchar_t[iwStrLen];
				if( pwcUnlockFileName == NULL )
				{
				   return -3;
				}
				iwStrLen = mbstowcs( pwcUnlockFileName, pucUnlockFileName, iStrLen );
				if( iwStrLen == -1 )
				{
					return -1;
				}
				// ロック解除するパス名の場合、ハンドル解放。
				if( wcscmp( pwcUnlockFileName, pName ) == 0 )
				{
					bRet = CloseHandle( SelfProcessHandle );
					if( bRet == FALSE )
					{
						return -4;
					}
				}
				memset( pName, 0, sizeof(pName) );
			}
			pFNI = NULL;
		}
		if( pucQueryBuffer != NULL )
		{
			delete [] pucQueryBuffer;
			pucQueryBuffer = NULL;
		}
	}
	return 0;
}


int main( int argc, char* argv[])
{
	long lRet = 0L;
	if( argc <= 0 )
	{
		printf("invalid argument.\n");
		return -1;
	}
	InitNativeFunctions();
	// forcible close handle for specified file
	lRet = FileUnLock( (const char*)argv[1] );
	if( lRet != 0 )
	{
		printf("failed to forcible unlock file.\n");
		return lRet;
	}
	return 0;
}
