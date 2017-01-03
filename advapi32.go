// Copyright 2010 The win Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package win

import (
	"syscall"
	"unsafe"
)

const KEY_READ REGSAM = 0x20019
const KEY_WRITE REGSAM = 0x20006

const (
	HKEY_CLASSES_ROOT     HKEY = 0x80000000
	HKEY_CURRENT_USER     HKEY = 0x80000001
	HKEY_LOCAL_MACHINE    HKEY = 0x80000002
	HKEY_USERS            HKEY = 0x80000003
	HKEY_PERFORMANCE_DATA HKEY = 0x80000004
	HKEY_CURRENT_CONFIG   HKEY = 0x80000005
	HKEY_DYN_DATA         HKEY = 0x80000006
)

const (
	ERROR_NO_MORE_ITEMS = 259
)

// #define READ_CONTROL (__MSABI_LONG(0x00020000)) __MSABI_LONG常量
const (
	READ_CONTROL         = 0x00020000
	STANDARD_RIGHTS_READ = READ_CONTROL
)

// winnt.h OpenProcessToken DesiredAccess
const (
	TOKEN_ASSIGN_PRIMARY    = 0x0001
	TOKEN_DUPLICATE         = 0x0002
	TOKEN_IMPERSONATE       = 0x0004
	TOKEN_QUERY             = 0x0008
	TOKEN_QUERY_SOURCE      = 0x0010
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_ADJUST_GROUPS     = 0x0040
	TOKEN_ADJUST_DEFAULT    = 0x0080
	TOKEN_ADJUST_SESSIONID  = 0x0100

	TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY
)

type (
	ACCESS_MASK uint32
	HKEY        HANDLE
	REGSAM      ACCESS_MASK
)

const (
	REG_NONE      uint64 = 0 // No value type
	REG_SZ               = 1 // Unicode nul terminated string
	REG_EXPAND_SZ        = 2 // Unicode nul terminated string
	// (with environment variable references)
	REG_BINARY                     = 3 // Free form binary
	REG_DWORD                      = 4 // 32-bit number
	REG_DWORD_LITTLE_ENDIAN        = 4 // 32-bit number (same as REG_DWORD)
	REG_DWORD_BIG_ENDIAN           = 5 // 32-bit number
	REG_LINK                       = 6 // Symbolic Link (unicode)
	REG_MULTI_SZ                   = 7 // Multiple Unicode strings
	REG_RESOURCE_LIST              = 8 // Resource list in the resource map
	REG_FULL_RESOURCE_DESCRIPTOR   = 9 // Resource list in the hardware description
	REG_RESOURCE_REQUIREMENTS_LIST = 10
	REG_QWORD                      = 11 // 64-bit number
	REG_QWORD_LITTLE_ENDIAN        = 11 // 64-bit number (same as REG_QWORD)

)

const (
	SE_CREATE_TOKEN_NAME           = "SeCreateTokenPrivilege"
	SE_ASSIGNPRIMARYTOKEN_NAME     = "SeAssignPrimaryTokenPrivilege"
	SE_LOCK_MEMORY_NAME            = "SeLockMemoryPrivilege"
	SE_INCREASE_QUOTA_NAME         = "SeIncreaseQuotaPrivilege"
	SE_UNSOLICITED_INPUT_NAME      = "SeUnsolicitedInputPrivilege"
	SE_MACHINE_ACCOUNT_NAME        = "SeMachineAccountPrivilege"
	SE_TCB_NAME                    = "SeTcbPrivilege"
	SE_SECURITY_NAME               = "SeSecurityPrivilege"
	SE_TAKE_OWNERSHIP_NAME         = "SeTakeOwnershipPrivilege"
	SE_LOAD_DRIVER_NAME            = "SeLoadDriverPrivilege"
	SE_SYSTEM_PROFILE_NAME         = "SeSystemProfilePrivilege"
	SE_SYSTEMTIME_NAME             = "SeSystemtimePrivilege"
	SE_PROF_SINGLE_PROCESS_NAME    = "SeProfileSingleProcessPrivilege"
	SE_INC_BASE_PRIORITY_NAME      = "SeIncreaseBasePriorityPrivilege"
	SE_CREATE_PAGEFILE_NAME        = "SeCreatePagefilePrivilege"
	SE_CREATE_PERMANENT_NAME       = "SeCreatePermanentPrivilege"
	SE_BACKUP_NAME                 = "SeBackupPrivilege"
	SE_RESTORE_NAME                = "SeRestorePrivilege"
	SE_SHUTDOWN_NAME               = "SeShutdownPrivilege"
	SE_DEBUG_NAME                  = "SeDebugPrivilege"
	SE_AUDIT_NAME                  = "SeAuditPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME     = "SeSystemEnvironmentPrivilege"
	SE_CHANGE_NOTIFY_NAME          = "SeChangeNotifyPrivilege"
	SE_REMOTE_SHUTDOWN_NAME        = "SeRemoteShutdownPrivilege"
	SE_UNDOCK_NAME                 = "SeUndockPrivilege"
	SE_SYNC_AGENT_NAME             = "SeSyncAgentPrivilege"
	SE_ENABLE_DELEGATION_NAME      = "SeEnableDelegationPrivilege"
	SE_MANAGE_VOLUME_NAME          = "SeManageVolumePrivilege"
	SE_IMPERSONATE_NAME            = "SeImpersonatePrivilege"
	SE_CREATE_GLOBAL_NAME          = "SeCreateGlobalPrivilege"
	SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege"
	SE_RELABEL_NAME                = "SeRelabelPrivilege"
	SE_INC_WORKING_SET_NAME        = "SeIncreaseWorkingSetPrivilege"
	SE_TIME_ZONE_NAME              = "SeTimeZonePrivilege"
	SE_CREATE_SYMBOLIC_LINK_NAME   = "SeCreateSymbolicLinkPrivilege"
)

const (
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = uint32(0x00000001)
	SE_PRIVILEGE_ENABLED            = uint32(0x00000002)
	SE_PRIVILEGE_REMOVED            = 0X00000004
	SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

	SE_PRIVILEGE_VALID_ATTRIBUTES = (SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_REMOVED | SE_PRIVILEGE_USED_FOR_ACCESS)
)

const (
	ANYSIZE_ARRAY = 1
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [ANYSIZE_ARRAY]LUID_AND_ATTRIBUTES
}

var (
	// Library
	libadvapi32 uintptr

	// Functions
	regCloseKey     uintptr
	regOpenKeyEx    uintptr
	regQueryValueEx uintptr
	regEnumValue    uintptr
	regSetValueEx   uintptr

	openProcessToken      uintptr
	lookupPrivilegeValueA uintptr
	lookupPrivilegeValueW uintptr
	adjustTokenPrivileges uintptr
)

func init() {
	// Library
	libadvapi32 = MustLoadLibrary("advapi32.dll")

	// Functions
	regCloseKey = MustGetProcAddress(libadvapi32, "RegCloseKey")
	regOpenKeyEx = MustGetProcAddress(libadvapi32, "RegOpenKeyExW")
	regQueryValueEx = MustGetProcAddress(libadvapi32, "RegQueryValueExW")
	regEnumValue = MustGetProcAddress(libadvapi32, "RegEnumValueW")
	regSetValueEx = MustGetProcAddress(libadvapi32, "RegSetValueExW")

	openProcessToken = MustGetProcAddress(libadvapi32, "OpenProcessToken")
	// LookupPrivilegeValueW (Unicode) and LookupPrivilegeValueA (ANSI)
	lookupPrivilegeValueW = MustGetProcAddress(libadvapi32, "LookupPrivilegeValueW")
	lookupPrivilegeValueA = MustGetProcAddress(libadvapi32, "LookupPrivilegeValueA")
	adjustTokenPrivileges = MustGetProcAddress(libadvapi32, "AdjustTokenPrivileges")
}

func RegCloseKey(hKey HKEY) int32 {
	ret, _, _ := syscall.Syscall(regCloseKey, 1,
		uintptr(hKey),
		0,
		0)

	return int32(ret)
}

func RegOpenKeyEx(hKey HKEY, lpSubKey *uint16, ulOptions uint32, samDesired REGSAM, phkResult *HKEY) int32 {
	ret, _, _ := syscall.Syscall6(regOpenKeyEx, 5,
		uintptr(hKey),
		uintptr(unsafe.Pointer(lpSubKey)),
		uintptr(ulOptions),
		uintptr(samDesired),
		uintptr(unsafe.Pointer(phkResult)),
		0)

	return int32(ret)
}

func RegQueryValueEx(hKey HKEY, lpValueName *uint16, lpReserved, lpType *uint32, lpData *byte, lpcbData *uint32) int32 {
	ret, _, _ := syscall.Syscall6(regQueryValueEx, 6,
		uintptr(hKey),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(unsafe.Pointer(lpReserved)),
		uintptr(unsafe.Pointer(lpType)),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(unsafe.Pointer(lpcbData)))

	return int32(ret)
}

func RegEnumValue(hKey HKEY, index uint32, lpValueName *uint16, lpcchValueName *uint32, lpReserved, lpType *uint32, lpData *byte, lpcbData *uint32) int32 {
	ret, _, _ := syscall.Syscall9(regEnumValue, 8,
		uintptr(hKey),
		uintptr(index),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(unsafe.Pointer(lpcchValueName)),
		uintptr(unsafe.Pointer(lpReserved)),
		uintptr(unsafe.Pointer(lpType)),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(unsafe.Pointer(lpcbData)),
		0)
	return int32(ret)
}

func RegSetValueEx(hKey HKEY, lpValueName *uint16, lpReserved, lpDataType uint64, lpData *byte, cbData uint32) int32 {
	ret, _, _ := syscall.Syscall6(regSetValueEx, 6,
		uintptr(hKey),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(lpReserved),
		uintptr(lpDataType),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(cbData))
	return int32(ret)
}

func OpenProcessToken(ProcessHandle HANDLE, DesiredAccess uint32, TokenHandle *HANDLE) bool {
	ret, _, _ := syscall.Syscall(openProcessToken, 3,
		uintptr(ProcessHandle),
		uintptr(DesiredAccess),
		uintptr(unsafe.Pointer(TokenHandle)))

	return ret != 0
}

func LookupPrivilegeValueA(lpSystemName, lpName *byte, lpLuid *LUID) bool {
	ret, _, _ := syscall.Syscall(lookupPrivilegeValueA, 3,
		uintptr(unsafe.Pointer(lpSystemName)),
		uintptr(unsafe.Pointer(lpName)),
		uintptr(unsafe.Pointer(lpLuid)))

	return ret != 0
}

func LookupPrivilegeValueW(lpSystemName, lpName *byte, lpLuid *LUID) bool {
	ret, _, _ := syscall.Syscall(lookupPrivilegeValueW, 3,
		uintptr(unsafe.Pointer(lpSystemName)),
		uintptr(unsafe.Pointer(lpName)),
		uintptr(unsafe.Pointer(lpLuid)))

	return ret != 0
}

func AdjustTokenPrivileges(TokenHandle HANDLE, DisableAllPrivileges bool, NewState *TOKEN_PRIVILEGES, BufferLength uint32, PreviousState *TOKEN_PRIVILEGES, ReturnLength *uint16) bool {
	ret, _, _ := syscall.Syscall6(adjustTokenPrivileges, 6,
		uintptr(TokenHandle),
		uintptr(BoolToBOOL(DisableAllPrivileges)),
		uintptr(unsafe.Pointer(NewState)),
		uintptr(BufferLength),
		uintptr(unsafe.Pointer(PreviousState)),
		uintptr(unsafe.Pointer(ReturnLength)))

	return ret != 0
}
