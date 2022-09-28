/*
 * ntoskrnl.exe implementation
 *
 * Copyright (C) 2007 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_NTOSKRNL_PRIVATE_H
#define __WINE_NTOSKRNL_PRIVATE_H

#include <stdarg.h>
#include <stdbool.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winioctl.h"
#include "winbase.h"
#include "winsvc.h"
#include "winternl.h"
#include "ddk/ntifs.h"
#include "ddk/wdm.h"

#include "wine/asm.h"
#include "wine/debug.h"
#include "wine/list.h"
#include "wine/rbtree.h"

static inline LPCSTR debugstr_us( const UNICODE_STRING *us )
{
    if (!us) return "<null>";
    return debugstr_wn( us->Buffer, us->Length / sizeof(WCHAR) );
}

struct _OBJECT_TYPE
{
    const WCHAR *name;            /* object type name used for type validation */
    void *(*constructor)(HANDLE); /* used for creating an object from server handle */
    void (*release)(void*);       /* called when the last reference is released */
};

struct _EPROCESS
{
    DISPATCHER_HEADER header;
    PROCESS_BASIC_INFORMATION info;
    BOOL wow64;
};

struct _KTHREAD
{
    DISPATCHER_HEADER header;
    PEPROCESS process;
    CLIENT_ID id;
    unsigned int critical_region;
    KAFFINITY user_affinity;
};

struct _ETHREAD
{
    struct _KTHREAD kthread;
};

void *alloc_kernel_object( POBJECT_TYPE type, HANDLE handle, SIZE_T size, LONG ref ) DECLSPEC_HIDDEN;
NTSTATUS kernel_object_from_handle( HANDLE handle, POBJECT_TYPE type, void **ret ) DECLSPEC_HIDDEN;

extern POBJECT_TYPE ExEventObjectType;
extern POBJECT_TYPE ExSemaphoreObjectType;
extern POBJECT_TYPE IoDeviceObjectType;
extern POBJECT_TYPE IoDriverObjectType;
extern POBJECT_TYPE IoFileObjectType;
extern POBJECT_TYPE PsProcessType;
extern POBJECT_TYPE PsThreadType;
extern POBJECT_TYPE SeTokenObjectType;

#define DECLARE_CRITICAL_SECTION(cs) \
    static CRITICAL_SECTION cs; \
    static CRITICAL_SECTION_DEBUG cs##_debug = \
    { 0, 0, &cs, { &cs##_debug.ProcessLocksList, &cs##_debug.ProcessLocksList }, \
      0, 0, { (DWORD_PTR)(__FILE__ ": " # cs) }}; \
    static CRITICAL_SECTION cs = { &cs##_debug, -1, 0, 0, 0, 0 };

struct wine_driver
{
    DRIVER_OBJECT driver_obj;
    DRIVER_EXTENSION driver_extension;
    SERVICE_STATUS_HANDLE service_handle;
    struct wine_rb_entry entry;
    struct list root_pnp_devices;
};

void ObReferenceObject( void *obj ) DECLSPEC_HIDDEN;

void pnp_manager_start(void) DECLSPEC_HIDDEN;
void pnp_manager_stop_driver( struct wine_driver *driver ) DECLSPEC_HIDDEN;
void pnp_manager_stop(void) DECLSPEC_HIDDEN;

void CDECL wine_enumerate_root_devices( const WCHAR *driver_name );

struct wine_driver *get_driver( const WCHAR *name ) DECLSPEC_HIDDEN;

static const WCHAR servicesW[] = {'\\','R','e','g','i','s','t','r','y',
                                  '\\','M','a','c','h','i','n','e',
                                  '\\','S','y','s','t','e','m',
                                  '\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t',
                                  '\\','S','e','r','v','i','c','e','s',
                                  '\\',0};

struct wine_device
{
    DEVICE_OBJECT device_obj;
    DEVICE_RELATIONS *children;
};

static const LUID SeCreateTokenPrivilege          = {  2, 0 };
static const LUID SeAssignPrimaryTokenPrivilege   = {  3, 0 };
static const LUID SeLockMemoryPrivilege           = {  4, 0 };
static const LUID SeIncreaseQuotaPrivilege        = {  5, 0 };
static const LUID SeUnsolicitedInputPrivilege     = {  6, 0 };
static const LUID SeTcbPrivilege                  = {  7, 0 };
static const LUID SeSecurityPrivilege             = {  8, 0 };
static const LUID SeTakeOwnershipPrivilege        = {  9, 0 };
static const LUID SeLoadDriverPrivilege           = { 10, 0 };
static const LUID SeSystemProfilePrivilege        = { 11, 0 };
static const LUID SeSystemtimePrivilege           = { 12, 0 };
static const LUID SeProfileSingleProcessPrivilege = { 13, 0 };
static const LUID SeIncreaseBasePriorityPrivilege = { 14, 0 };
static const LUID SeCreatePagefilePrivilege       = { 15, 0 };
static const LUID SeCreatePermanentPrivilege      = { 16, 0 };
static const LUID SeBackupPrivilege               = { 17, 0 };
static const LUID SeRestorePrivilege              = { 18, 0 };
static const LUID SeShutdownPrivilege             = { 19, 0 };
static const LUID SeDebugPrivilege                = { 20, 0 };
static const LUID SeAuditPrivilege                = { 21, 0 };
static const LUID SeSystemEnvironmentPrivilege    = { 22, 0 };
static const LUID SeChangeNotifyPrivilege         = { 23, 0 };
static const LUID SeRemoteShutdownPrivilege       = { 24, 0 };
static const LUID SeUndockPrivilege               = { 25, 0 };
static const LUID SeSyncAgentPrivilege            = { 26, 0 };
static const LUID SeEnableDelegationPrivilege     = { 27, 0 };
static const LUID SeManageVolumePrivilege         = { 28, 0 };
static const LUID SeImpersonatePrivilege          = { 29, 0 };
static const LUID SeCreateGlobalPrivilege         = { 30, 0 };

static const SID well_known_sids[] =
{
    { SID_REVISION, 1, { SECURITY_NULL_SID_AUTHORITY }, { SECURITY_NULL_RID } },
    { SID_REVISION, 1, { SECURITY_WORLD_SID_AUTHORITY }, { SECURITY_WORLD_RID } },
    { SID_REVISION, 1, { SECURITY_LOCAL_SID_AUTHORITY }, { SECURITY_LOCAL_RID } },
    { SID_REVISION, 1, { SECURITY_CREATOR_SID_AUTHORITY }, { SECURITY_CREATOR_OWNER_RID } },
    { SID_REVISION, 1, { SECURITY_CREATOR_SID_AUTHORITY }, { SECURITY_CREATOR_GROUP_RID } },
    { SID_REVISION, 1, { SECURITY_CREATOR_SID_AUTHORITY }, { SECURITY_CREATOR_OWNER_RIGHTS_RID } },
    { SID_REVISION, 1, { SECURITY_CREATOR_SID_AUTHORITY }, { SECURITY_CREATOR_OWNER_SERVER_RID } },
    { SID_REVISION, 1, { SECURITY_CREATOR_SID_AUTHORITY }, { SECURITY_CREATOR_GROUP_SERVER_RID } },
    { SID_REVISION, 0, { SECURITY_NT_AUTHORITY }, { SECURITY_NULL_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_DIALUP_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_NETWORK_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_BATCH_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_INTERACTIVE_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_SERVICE_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_ANONYMOUS_LOGON_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_PROXY_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_ENTERPRISE_CONTROLLERS_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_PRINCIPAL_SELF_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_AUTHENTICATED_USER_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_RESTRICTED_CODE_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_TERMINAL_SERVER_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_REMOTE_LOGON_RID } },
    { SID_REVISION, SECURITY_LOGON_IDS_RID_COUNT, { SECURITY_NT_AUTHORITY }, { SECURITY_LOGON_IDS_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_LOCAL_SYSTEM_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_LOCAL_SERVICE_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_NETWORK_SERVICE_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_GUESTS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_POWER_USERS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ACCOUNT_OPS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_SYSTEM_OPS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_PRINT_OPS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_BACKUP_OPS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_REPLICATOR } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_PREW2KCOMPACCESS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_PACKAGE_BASE_RID, SECURITY_PACKAGE_NTLM_RID } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_PACKAGE_BASE_RID, SECURITY_PACKAGE_DIGEST_RID } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_PACKAGE_BASE_RID, SECURITY_PACKAGE_SCHANNEL_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_THIS_ORGANIZATION_RID } },
    { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_OTHER_ORGANIZATION_RID } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS  } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_MONITORING_USERS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_LOGGING_USERS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS } },
    { SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_DCOM_USERS } },
    { SID_REVISION, 1, { SECURITY_MANDATORY_LABEL_AUTHORITY}, { SECURITY_MANDATORY_LOW_RID} },
    { SID_REVISION, 1, { SECURITY_MANDATORY_LABEL_AUTHORITY}, { SECURITY_MANDATORY_MEDIUM_RID } },
    { SID_REVISION, 1, { SECURITY_MANDATORY_LABEL_AUTHORITY}, { SECURITY_MANDATORY_HIGH_RID } },
    { SID_REVISION, 1, { SECURITY_MANDATORY_LABEL_AUTHORITY}, { SECURITY_MANDATORY_SYSTEM_RID } },
    { SID_REVISION, 2, { SECURITY_APP_PACKAGE_AUTHORITY }, { SECURITY_APP_PACKAGE_BASE_RID, SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE } },
};


#endif
