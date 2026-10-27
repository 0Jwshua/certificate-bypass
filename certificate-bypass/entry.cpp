#include <windows.h>
#include <iostream>
#include <string>

#include "minhook/minhook.h"

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef NTSTATUS(NTAPI* NtCreateFilePtr)(
	PHANDLE                     FileHandle,
	ACCESS_MASK                 DesiredAccess,
	POBJECT_ATTRIBUTES			ObjectAttributes,
	PIO_STATUS_BLOCK            IoStatusBlock,
	PLARGE_INTEGER              AllocationSize,
	ULONG						FileAttributes,
	ULONG						ShareAccess,
	ULONG						CreateDisposition,
	ULONG						CreateOptions,
	PVOID						EaBuffer,
	ULONG						EaLength
);
NtCreateFilePtr originalNtCreateFile;

NTSTATUS NTAPI HookedNtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
) 
{
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		auto wstr = std::wstring(ObjectAttributes->ObjectName->Buffer);

		if (wstr.find(L"BEClient_x64.dll") != std::wstring::npos)
		{
			typedef VOID(__stdcall* _RtlInitUnicodeString)(
				PUNICODE_STRING DestinationString,
				PCWSTR SourceString
				);
			_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

			UNICODE_STRING fakePath;
			RtlInitUnicodeString(&fakePath, L"\\??\\C:\\Windows\\System32\\ntdll.dll");

			auto backupPath = ObjectAttributes->ObjectName;
			ObjectAttributes->ObjectName = &fakePath;
		}
	}
	
	return originalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
};

BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
	{
		auto addy = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");

		MH_Initialize();

		MH_CreateHook((LPVOID)addy, (LPVOID)HookedNtCreateFile, (LPVOID*)&originalNtCreateFile);

		MH_EnableHook(MH_ALL_HOOKS);

		break;
	}
	}

	return true;
}