// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
//
// Minimal PKCS#11 type definitions for HSM key management via dlopen/dlsym.
// This header provides only the types, constants, and function signatures
// needed for key deletion (C_FindObjects + C_DestroyObject) without requiring
// the full p11-kit or vendor PKCS#11 headers as a build dependency.
//
// Based on the OASIS PKCS#11 v2.40 / v3.0 specification.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Basic types
typedef unsigned long int CK_ULONG;
typedef unsigned char CK_BYTE;
typedef unsigned char CK_BBOOL;
typedef unsigned char CK_UTF8CHAR;
typedef CK_BYTE CK_CHAR;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_USER_TYPE;
typedef void* CK_VOID_PTR;
typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE session, CK_ULONG event, CK_VOID_PTR pApplication);

// Version structure
typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

// Token information structure (for C_GetTokenInfo)
typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_UTF8CHAR serialNumber[16];
    CK_FLAGS    flags;
    CK_ULONG    ulMaxSessionCount;
    CK_ULONG    ulSessionCount;
    CK_ULONG    ulMaxRwSessionCount;
    CK_ULONG    ulRwSessionCount;
    CK_ULONG    ulMaxPinLen;
    CK_ULONG    ulMinPinLen;
    CK_ULONG    ulTotalPublicMemory;
    CK_ULONG    ulFreePublicMemory;
    CK_ULONG    ulTotalPrivateMemory;
    CK_ULONG    ulFreePrivateMemory;
    CK_VERSION  hardwareVersion;
    CK_VERSION  firmwareVersion;
    CK_CHAR     utcTime[16];
} CK_TOKEN_INFO;

// Attribute structure
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

// Return values
#define CKR_OK 0UL
#define CKR_USER_ALREADY_LOGGED_IN 0x00000100UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL

// Session flags
#define CKF_RW_SESSION (1UL << 1)
#define CKF_SERIAL_SESSION (1UL << 2)

// User types
#define CKU_SO   0UL
#define CKU_USER 1UL

// Token flags
#define CKF_TOKEN_INITIALIZED    0x00000400UL
#define CKF_USER_PIN_INITIALIZED 0x00000008UL

// Object classes
#define CKO_PUBLIC_KEY 2UL
#define CKO_PRIVATE_KEY 3UL

// Attribute types
#define CKA_CLASS 0UL
#define CKA_LABEL 3UL

// Boolean constants
#define CK_TRUE 1
#define CK_FALSE 0

// Function signatures for the PKCS#11 functions we need (for dlsym)
typedef CK_RV (*PFN_C_Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*PFN_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (*PFN_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                                   CK_SESSION_HANDLE* phSession);
typedef CK_RV (*PFN_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*PFN_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR* pPin, CK_ULONG ulPinLen);
typedef CK_RV (*PFN_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*PFN_C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount);
typedef CK_RV (*PFN_C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE* phObject,
                                   CK_ULONG ulMaxObjectCount, CK_ULONG* pulObjectCount);
typedef CK_RV (*PFN_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*PFN_C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                         CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount);
typedef CK_RV (*PFN_C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV (*PFN_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID* pSlotList, CK_ULONG* pulCount);
typedef CK_RV (*PFN_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO* pInfo);
typedef CK_RV (*PFN_C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR* pPin, CK_ULONG ulPinLen, CK_UTF8CHAR* pLabel);
typedef CK_RV (*PFN_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR* pPin, CK_ULONG ulPinLen);

#ifdef __cplusplus
}
#endif
