/****************************************************************************** 
  Header: WinLicenseSDK.h
  Description: SDK header definition for the C/C++ language

  Author/s: Oreans Technologies  
  (c) 2010 Oreans Technologies
*****************************************************************************/ 

#pragma once


// ***********************************************
// Cross Compiler definitions
// ***********************************************

#ifdef __GNUC__
 #define DLL_IMPORT             extern
 #define STDCALL_CONVENTION     __stdcall
#else
 #define DLL_IMPORT             __declspec(dllimport)
 #define STDCALL_CONVENTION     __stdcall
#endif


// ***********************************************
// Specify platform
// ***********************************************

#ifdef __GNUC__

  #ifdef __x86_64__
  #define PLATFORM_X64
  #else
  #define PLATFORM_X32
  #endif

#else

  #ifdef _WIN64
  #define PLATFORM_X64
  #else
  #define PLATFORM_X32
  #endif

#endif


// ***********************************************
// Defines
// ***********************************************

#ifdef __GNUC__

#define X32_INSERT_VIA_INLINE
#define X64_INSERT_VIA_INLINE

#else

#define X32_INSERT_VIA_INLINE
//#define X64_INSERT_VIA_INLINE

#endif


// ***********************************************
// Link with correct platform library
// ***********************************************

#ifdef _WIN64
 #pragma comment(lib, "WinLicenseSDK64.lib")
#else
 #pragma comment(lib, "WinLicenseSDK32.lib")
#endif

#include "SecureEngineSDK.h"
#include "windows.h"

// ***********************************************
// WinLicense constants definition
// ***********************************************

// Trial extension constants 
const int wlNoTrialExt                          = 0;
const int wlAppExtended                         = 1;
const int wlInvalidTrialExt                     = 2;
const int wlNoMoreExt                           = 3;

const int WL_TRIAL_EXTENSION_NOT_PRESENT        = 0;
const int WL_TRIAL_EXTENSION_APPLIED            = 1;
const int WL_TRIAL_EXTENSION_INVALID            = 2;
const int WL_TRIAL_EXTENSION_NO_MORE_EXTENSIONS = 3;

// Trial status constants
const int wlTrialOk                             = 0;
const int wlTrialDaysExpired                    = 1;
const int wlTrialExecExpired                    = 2;
const int wlTrialDateExpired                    = 3;
const int wlTrialRuntimExpired                  = 4;
const int wlTrialGlobalExpired                  = 5;
const int wlTrialInvalidCountry                 = 6;
const int wlTrialManipulated                    = 7;

const int WL_TRIAL_STATUS_OK                    = 0;
const int WL_TRIAL_STATUS_EXPIRED_DAYS          = 1;
const int WL_TRIAL_STATUS_EXPIRED_EXECUTIONS    = 2;
const int WL_TRIAL_STATUS_EXPIRED_DATE          = 3;
const int WL_TRIAL_STATUS_EXPIRED_RUNTIME       = 4;
const int WL_TRIAL_STATUS_EXPIRED_GLOBAL_TIME   = 5;
const int WL_TRIAL_STATUS_INVALID_COUNTRY       = 6;
const int WL_TRIAL_STATUS_MANIPULATED           = 7;

// Registration status constants
const int wlIsTrial                             = 0;
const int wlIsRegistered                        = 1;
const int wlInvalidLicense                      = 2;
const int wlInvalidHardwareLicense              = 3;
const int wlNoMoreHwdChanges                    = 4;
const int wlLicenseExpired                      = 5;
const int wlInvalidCountryLicense               = 6;
const int wlLicenseStolen                       = 7;
const int wlWrongLicenseExp                     = 8;
const int wlWrongLicenseHardware                = 9;
const int wlIsRegisteredNotActivated            = 10;
const int wlIsRegisteredAndActivated            = 1;  // Internally same as "wlIsRegistered"
const int wlNoMoreInstancesAllowed              = 12;
const int wlNetworkNoServerRunning              = 13;
const int wlInstallLicenseDateExpired           = 14;
const int wlLicenseDisabledInstance             = 15;
const int wlTrialModeNotSupported               = 16;
const int wlNetworkCannotStartServer            = 17;

const int WL_REG_STATUS_TRIAL                                   = 0;
const int WL_REG_STATUS_REGISTERED                              = 1;
const int WL_REG_STATUS_LICENSE_INVALID                         = 2;
const int WL_REG_STATUS_LICENSE_HARDWARE_ID_INVALID             = 3;
const int WL_REG_STATUS_LICENSE_HARDWARE_ID_NO_MORE_CHANGES     = 4;
const int WL_REG_STATUS_LICENSE_EXPIRED                         = 5;
const int WL_REG_STATUS_LICENSE_COUNTRY_INVALID                 = 6;
const int WL_REG_STATUS_LICENSE_STOLEN                          = 7;
const int WL_REG_STATUS_LICENSE_EXPIRATION_REQUIRED             = 8;
const int WL_REG_STATUS_LICENSE_HARDWARE_ID_REQUIRED            = 9;
const int WL_REG_STATUS_NETWORK_INSTANCES_NO_MORE_ALLOWED       = 12;
const int WL_REG_STATUS_NETWORK_INSTANCES_NO_SERVER_RUNNING     = 13;
const int WL_REG_STATUS_INSTALL_BEFORE_DATE_EXPIRED             = 14;
const int WL_REG_STATUS_LICENSE_DISABLED                        = 15;
const int WL_REG_STATUS_TRIAL_NOT_SUPPORTED                     = 16;
const int WL_REG_STATUS_NETWORT_INSTANCES_CANNOT_START_SERVER   = 17;

// Registration status (extended) constants
const int wlLicenseDaysExpired                  = 1;
const int wlLicenseExecExpired                  = 2;
const int wlLicenseDateExpired                  = 3;
const int wlLicenseGlobalExpired                = 4;
const int wlLicenseRuntimeExpired               = 5;
const int wlLicenseActivationExpired            = 6;

const int WL_REG_EXPIRED_DAYS                   = 1;
const int WL_REG_EXTENDED_EXPIRED_EXECUTIONS    = 2;
const int WL_REG_EXTENDED_EXPIRED_DATE          = 3;
const int WL_REG_EXTENDED_EXPIRED_GLOBAL_TIME   = 4;
const int WL_REG_EXTENDED_EXPIRED_RUNTIME       = 5;

// Invalid key constants
const int wlMarkStolenKey                       = 0;
const int wlMarkInvalidKey                      = 1;

const int WL_MARK_KEY_STOLEN                    = 0;
const int WL_MARK_KEY_INVALID                   = 1;

// License restrictions constants
const int wlRegRestrictionDays                      = 1 << 0;
const int wlRegRestrictionExec                      = 1 << 1;
const int wlRegRestrictionDate                      = 1 << 2;
const int wlRegRestrictionRuntime                   = 1 << 3;
const int wlRegRestrictionGlobalTime                = 1 << 4;
const int wlRegRestrictionCountry                   = 1 << 5;
const int wlRegRestrictionHardwareId                = 1 << 6;
const int wlRegRestrictionNetwork                   = 1 << 7;
const int wlRegRestrictionInstallDate               = 1 << 8;
const int wlRegRestrictionCreationDate              = 1 << 9;
const int wlRegRestrictionEmbedUserInfo             = 1 << 10;

const int WL_REG_RESTRICTION_DAYS                   = 1 << 0;
const int WL_REG_RESTRICTION_EXECUTIONS             = 1 << 1;
const int WL_REG_RESTRICTION_DATE                   = 1 << 2;
const int WL_REG_RESTRICTION_RUNTIME                = 1 << 3;
const int WL_REG_RESTRICTION_GLOBAL_TIME            = 1 << 4;
const int WL_REG_RESTRICTION_COUNTRY                = 1 << 5;
const int WL_REG_RESTRICTION_HARDWARE_ID            = 1 << 6;
const int WL_REG_RESTRICTION_NETWORK_INSTANCES      = 1 << 7;
const int WL_REG_RESTRICTION_INSTALL_BEFORE_DATE    = 1 << 8;
const int WL_REG_RESTRICTION_CREATION_DATE          = 1 << 9;
const int WL_REG_RESTRICTION_EMBED_USER_INFO        = 1 << 10;

// Trial restrictions constants
const int wlTrialRestrictionUnlimited               = 0;
const int wlTrialRestrictionDays                    = 1 << 0;
const int wlTrialRestrictionExec                    = 1 << 1;
const int wlTrialRestrictionDate                    = 1 << 2;
const int wlTrialRestrictionRuntime                 = 1 << 3;
const int wlTrialRestrictionGlobalTime              = 1 << 4;
const int wlTrialRestrictionCountry                 = 1 << 5;

const int WL_TRIAL_RESTRICTION_UNLIMITED            = 0;
const int WL_TRIAL_RESTRICTION_DAYS                 = 1 << 0;
const int WL_TRIAL_RESTRICTION_EXECUTIONS           = 1 << 1;
const int WL_TRIAL_RESTRICTION_DATE                 = 1 << 2;
const int WL_TRIAL_RESTRICTION_RUNTIME              = 1 << 3;
const int WL_TRIAL_RESTRICTION_GLOBAL_TIME          = 1 << 4;
const int WL_TRIAL_RESTRICTION_COUNTRY              = 1 << 5;

// Miscellaneous constants 
const int wlPermKey                     = -1;
const int wlNoKey                       = -2;
const int wlNoTrialDate                 = -1;
const int wlInvalidCounter              = -1;

const int WL_INFO_PERMANENT_KEY         = -1;
const int WL_INFO_NO_LICENSE_PRESENT    = -2;
const int WL_INFO_NO_TRIAL_DATE         = -1;
const int WL_INFO_INVALID_COUNTER       = -1;

// Hardware Machine types
const int wlHardwareTypePC              = 0;
const int wlHardwareTypeU3              = 1;
const int wlHardwareTypeCustom          = 2;

const int WL_HARDWARE_TYPE_PC           = 0;
const int WL_HARDWARE_TYPE_USB          = 1;
const int WL_HARDWARE_TYPE_CUSTOM       = 2;

// Activation
const int wlActivationOk                              = 0;
const int wlActivationErrorKeyNotFound                = 1;
const int wlActivationErrorDeviceRevoked              = 2;
const int wlActivationErrorMaxDevicesReached          = 3;
const int wlActivationErrorDeviceReactivationExcedeed = 4;
const int wlActivationErrorNoMoreRevokeAllowed        = 5;
const int wlActivationErrorDeviceNotFound             = 6;
const int wlActivationErrorWrongServerDataReceived    = 7;
const int wlActivationErrorKeyDisabledBySeller        = 8;
const int wlActivationErrorKeyExpired                 = 9;
const int wlActivationErrorCannotInstallLicense       = 50;
const int wlActivationErrorWinsockError               = 100;

// Return values for WLGetLastError
const int WL_ERROR_SUCCESS                            = 0;
const int WL_ERROR_NOT_MATCHING_HARDWARE_ID           = 1;
const int WL_ERROR_NOT_MATCHING_USER_INFO             = 2;
const int WL_ERROR_INVALID_KEY                        = 3;
const int WL_ERROR_REQUIRED_HARDWARE_ID               = 4;
const int WL_ERROR_REQUIRED_EXPIRATION                = 5;
const int WL_ERROR_WRONG_KEY_SIZE                     = 6;

// ***********************************************
// WinLicense typedef definitions
// ***********************************************

typedef struct _sLicenseFeatures 
{ 
    unsigned    cb;                     // size of struct
    unsigned    NumDays;                // expiration days
    unsigned    NumExec;                // expiration executions
    SYSTEMTIME  ExpDate;                // expiration date 
    unsigned    CountryId;              // country ID
    unsigned    Runtime;                // expiration runtime
    unsigned    GlobalMinutes;          // global time expiration
    SYSTEMTIME  InstallDate;            // Date to install the license since it was created
    unsigned    NetInstances;           // Network instances 
    unsigned    EmbedLicenseInfoInKey;  // for Dynamic SmartKeys, it embeds Name+Company+Custom inside generated SmartKey
    unsigned    EmbedCreationDate;      // Embed the date that the key was created
} sLicenseFeatures;

typedef struct 
{
    unsigned char i1;
    unsigned char i2;
    unsigned char i3;
    unsigned char i4;
    unsigned char i5;
    unsigned char i6;
    unsigned char i7;
    unsigned char i8;
    unsigned char i9;
    unsigned char i10;
    unsigned char i11;
    unsigned char i12;
    unsigned char i13;
    unsigned char i14;
    unsigned char i15;
    unsigned char i16;
    unsigned char is_v6;
} WL_IP_ADDRESS;

// ***********************************************
// WinLicense functions prototype
// ***********************************************

#ifdef __cplusplus
extern "C" {
#endif

int STDCALL_CONVENTION GenerateTrialExtensionKey(char* TrialHash, int Level, int NumDays, int NumExec,\
                                        SYSTEMTIME* NewDate, int NumMinutes, int TimeRuntime,\
                                        char* BufferOut);

int STDCALL_CONVENTION WLGenTrialExtensionFileKey(char* TrialHash, int Level,\
                                         int NumDays, int NumExec, SYSTEMTIME* NewDate, int NumMinutes,\
                                         int TimeRuntime, char* BufferOut);

int STDCALL_CONVENTION WLGenTrialExtensionRegistryKey(char* TrialHash, int Level,\
                                             int NumDays, int NumExec, SYSTEMTIME* NewDate, int NumMinutes,\
                                             int TimeRuntime, char* pKeyName, char* pKeyValueName, char* BufferOut);

int STDCALL_CONVENTION WLGenPassword(char* TrialHash, char* Name, char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseFileKey(char* LicenseHash, char* UserName, char* Organization,\
                                  char* CustomData, char* MachineID, int NumDays, int NumExec, SYSTEMTIME* NewDate, \
                                  int CountryId, int Runtime, int GlobalMinutes, char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseFileKeyW(const wchar_t* LicenseHash, const wchar_t* UserName, const wchar_t* Organization,\
                                   const wchar_t* CustomData, const wchar_t* MachineID, int NumDays, int NumExec,\
                                   SYSTEMTIME* NewDate, int CountryId, int Runtime, int GlobalMinutes, char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseFileKeyEx(const char* LicenseHash, const char* UserName, const char* Organization,\
                                    const char* CustomData, const char* MachineID, sLicenseFeatures* LicenseFeatures,\
                                    char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseFileKeyExW(const wchar_t* LicenseHash, const wchar_t* UserName, const wchar_t* Organization,\
                                     const wchar_t* CustomData, const wchar_t* MachineID, sLicenseFeatures* LicenseFeatures,\
                                     char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseRegistryKey(char* LicenseHash, char* UserName, char* Organization,\
                                      char* CustomData, char* MachineID, int NumDays, int NumExec, SYSTEMTIME* NewDate,\
                                      int CountryId, int Runtime, int GlobalMinutes, char* KeyName, char* KeyValueName,\
                                      char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseRegistryKeyW(const wchar_t* LicenseHash, const wchar_t* UserName, const wchar_t* Organization,\
                                       const wchar_t* CustomData, const wchar_t* MachineID, int NumDays, int NumExec,\
                                       SYSTEMTIME* NewDate, int CountryId, int Runtime, int GlobalMinutes,\
                                       const wchar_t* KeyName, const wchar_t* KeyValueName, char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseRegistryKeyEx(const char* LicenseHash, const char* UserName, const char* Organization,\
                                        const char* CustomData, const char* MachineID, sLicenseFeatures* LicenseFeatures,\
                                        char* KeyName, char* KeyValueName, char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseRegistryKeyExW(const wchar_t* LicenseHash, const wchar_t* UserName, const wchar_t* Organization,\
                                         const wchar_t* CustomData, const wchar_t* MachineID, sLicenseFeatures* LicenseFeatures,\
                                         const wchar_t* KeyName, const wchar_t* KeyValueName, wchar_t* BufferOut);

int STDCALL_CONVENTION WLGenLicenseTextKey(char* LicenseHash, char* UserName, char* Organization, char* CustomData,\
                                  char* MachineID, int NumDays, int NumExec, SYSTEMTIME* NewDate,\
                                  int CountryId, int Runtime, int GlobalMinutes, char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseTextKeyW(const wchar_t* LicenseHash, const wchar_t* UserName, const wchar_t* Organization,\
                                   const wchar_t* CustomData, const wchar_t* MachineID, int NumDays, int NumExec,\
                                   SYSTEMTIME* NewDate, int CountryId, int Runtime, int GlobalMinutes, wchar_t* BufferOut);

int STDCALL_CONVENTION WLGenLicenseTextKeyEx(const char* LicenseHash, const char* UserName, const char* Organization,\
                                    const char* CustomData, const char* MachineID, sLicenseFeatures* LicenseFeatures,\
                                    char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseTextKeyExW(const wchar_t* LicenseHash, const wchar_t* UserName, const wchar_t* Organization,\
                                     const wchar_t* CustomData, const wchar_t* MachineID, sLicenseFeatures* LicenseFeatures,\
                                     wchar_t* BufferOut);

int STDCALL_CONVENTION WLGenLicenseSmartKey(char* LicenseHash, char* UserName, char* Organization, char* CustomData,\
                                   char* MachineID, int NumDays, int NumExec, SYSTEMTIME* NewDate, char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseSmartKeyW(wchar_t* LicenseHash, wchar_t* UserName, wchar_t* Organization, wchar_t* CustomData,\
                                    wchar_t* MachineID, int NumDays, int NumExec, SYSTEMTIME* NewDate, wchar_t* BufferOut);

int STDCALL_CONVENTION WLGenLicenseDynSmartKey(const char* LicenseHash, const char* UserName, const char* Organization,\
                                      const char* CustomData, const char* MachineID, sLicenseFeatures* LicenseFeatures,\
                                      char* BufferOut);

int STDCALL_CONVENTION WLGenLicenseDynSmartKeyW(const wchar_t* LicenseHash, const wchar_t* UserName, const wchar_t* Organization,\
                                       const wchar_t* CustomData, const wchar_t* MachineID, sLicenseFeatures* LicenseFeatures,\
                                       wchar_t* BufferOut);

int STDCALL_CONVENTION WLRegGetStatus(int* pExtendedInfo);

int STDCALL_CONVENTION WLTrialGetStatus(int* pExtendedInfo);

int STDCALL_CONVENTION WLTrialExtGetStatus(void);

BOOL STDCALL_CONVENTION WLRegGetLicenseInfo(char* pName, char* pCompanyName, char* pCustomData);

BOOL STDCALL_CONVENTION WLRegGetLicenseInfoW(wchar_t* pName, wchar_t* pCompanyName, wchar_t* pCustomData);

int STDCALL_CONVENTION WLTrialTotalDays(void);

int STDCALL_CONVENTION WLTrialTotalExecutions(void);

int STDCALL_CONVENTION WLTrialDaysLeft(void);

int STDCALL_CONVENTION WLTrialExecutionsLeft(void);

int STDCALL_CONVENTION WLTrialExpirationDate(SYSTEMTIME* pExpDate);

int STDCALL_CONVENTION WLTrialGlobalTimeLeft(void);

int STDCALL_CONVENTION WLTrialRuntimeLeft(void);

int STDCALL_CONVENTION WLTrialLockedCountry(void);

int STDCALL_CONVENTION WLRegDaysLeft(void);

int STDCALL_CONVENTION WLRegExecutionsLeft(void);

int STDCALL_CONVENTION WLRegExpirationDate(SYSTEMTIME* pExpDate);

int STDCALL_CONVENTION WLRegInstallBeforeDate(SYSTEMTIME* pInstallDate);

BOOL STDCALL_CONVENTION WLRegLicenseCreationDate(SYSTEMTIME* pCreationDate);

int STDCALL_CONVENTION WLRegTotalExecutions(void);

int STDCALL_CONVENTION WLRegTotalDays(void);

BOOL STDCALL_CONVENTION WLHardwareGetID(char* pHardwareId);

BOOL STDCALL_CONVENTION WLHardwareCheckID(char* pHardwareId);

BOOL STDCALL_CONVENTION WLRegSmartKeyCheck(const char* UserName, const char* Organization, const char* Custom, const char* AsciiKey);

BOOL STDCALL_CONVENTION WLRegSmartKeyCheckW(const wchar_t* UserName, const wchar_t* Organization, const wchar_t* Custom,\
                                   const wchar_t* AsciiKey);

BOOL STDCALL_CONVENTION WLRegNormalKeyCheck(const char* AsciiKey);

BOOL STDCALL_CONVENTION WLRegNormalKeyCheckW(const wchar_t* AsciiKey);

BOOL STDCALL_CONVENTION WLRegNormalKeyInstallToFile(const char* AsciiKey);

BOOL STDCALL_CONVENTION WLRegNormalKeyInstallToFileW(const wchar_t* AsciiKey);

BOOL STDCALL_CONVENTION WLRegNormalKeyInstallToRegistry(const char* AsciiKey);

BOOL STDCALL_CONVENTION WLRegNormalKeyInstallToRegistryW(const wchar_t* AsciiKey);

BOOL STDCALL_CONVENTION WLRegSmartKeyInstallToFile(const char* UserName, const char* Organization, const char* Custom,\
                                          const char* AsciiKey);

BOOL STDCALL_CONVENTION WLRegSmartKeyInstallToRegistry(const char* UserName, const char* Organization, const char* Custom,\
                                              const char* AsciiKey);

BOOL STDCALL_CONVENTION WLRegSmartKeyInstallToFileW(const wchar_t* UserName, const wchar_t* Organization, const wchar_t* Custom,\
                                            const wchar_t* AsciiKey);

BOOL STDCALL_CONVENTION WLRegSmartKeyInstallToRegistryW(const wchar_t* UserName, const wchar_t* Organization, const wchar_t* Custom,\
                                               const wchar_t* AsciiKey);

int STDCALL_CONVENTION WLTrialCustomCounterInc(int Value, int CounterId);

int STDCALL_CONVENTION WLTrialCustomCounterDec(int Value, int CounterId);

int STDCALL_CONVENTION WLTrialCustomCounter(int CounterId);

int STDCALL_CONVENTION WLTrialCustomCounterSet(int Value, int CounterId);

BOOL STDCALL_CONVENTION WLRestartApplication(void);

int STDCALL_CONVENTION WLRegLockedCountry(void);

int STDCALL_CONVENTION WLRegRuntimeLeft(void);

int STDCALL_CONVENTION WLRegGlobalTimeLeft(void);

BOOL STDCALL_CONVENTION WLRegDisableCurrentKey(int DisableFlags);

BOOL STDCALL_CONVENTION WLRegRemoveCurrentKey(void);

BOOL STDCALL_CONVENTION WLHardwareGetFormattedID(int BlockCharSize, int Uppercase, char* Buffer);

BOOL STDCALL_CONVENTION WLPasswordCheck(char* UserName, char* Password);

BOOL STDCALL_CONVENTION WLTrialExpireTrial(void);

void STDCALL_CONVENTION WLRegLicenseName(char* FileKeyName, char* RegKeyName, char* RegKeyValueName);

BOOL STDCALL_CONVENTION WLRestartApplicationArgs(char* pArgs);

BOOL STDCALL_CONVENTION WLActGetInfo(int* Custom1, int* Custom2, int* Custom3);

BOOL STDCALL_CONVENTION WLActCheck(char* ActivationCode);

BOOL STDCALL_CONVENTION WLActInstall(char* ActivationCode);

BOOL STDCALL_CONVENTION WLActExpirationDate(SYSTEMTIME* pExpDate);

int STDCALL_CONVENTION WLActDaysToActivate(void);

BOOL STDCALL_CONVENTION WLActUninstall(void);

BOOL STDCALL_CONVENTION WLRegGetLicenseHardwareID(char* pHardwareId);

int STDCALL_CONVENTION WLGetCurrentCountry(void);

int STDCALL_CONVENTION WLTrialExtGetLevel(void);

BOOL STDCALL_CONVENTION WLProtectCheckDebugger(void);

BOOL STDCALL_CONVENTION  WLTrialExtendExpiration(int NumDays, int NumExec, SYSTEMTIME* NewDate, int Runtime, int GlobalMinutes);

BOOL STDCALL_CONVENTION WLTrialFirstRun(void);

BOOL STDCALL_CONVENTION WLRegFirstRun(void);

BOOL STDCALL_CONVENTION WLRegCheckMachineLocked(void);

void STDCALL_CONVENTION WLSplashHide(void);

void STDCALL_CONVENTION WLBufferCrypt(void* Buffer, int BufferLength, char* Password);

void STDCALL_CONVENTION WLBufferDecrypt(void* Buffer, int BufferLength, char* Password);

BOOL STDCALL_CONVENTION WLRegSmartKeyInstallToFileInFolder(const char* UserName, const char* Organization, const char* Custom,\
                                                  const char* AsciiKey, const char* FilePath);

BOOL STDCALL_CONVENTION WLRegSmartKeyInstallToFileInFolderW(const wchar_t* UserName, const wchar_t* Organization, const wchar_t* Custom,\
                                                  const wchar_t* UnicodeKey, const wchar_t* FilePath);

int STDCALL_CONVENTION WLTrialDateDaysLeft(void);

int STDCALL_CONVENTION WLRegDateDaysLeft(void);

void STDCALL_CONVENTION WLResetLicenseFeatures(sLicenseFeatures *LicenseFeatures, int SizeStructure);

BOOL STDCALL_CONVENTION WLRegGetDynSmartKey(char* SmartKey);

BOOL STDCALL_CONVENTION WLRegDisableKeyCurrentInstance(void);

BOOL STDCALL_CONVENTION WLHardwareRuntimeCheckU3(void);

void STDCALL_CONVENTION WLGetVersion(char* Buffer);

BOOL STDCALL_CONVENTION WLIsProtected(void);

int STDCALL_CONVENTION WLRegNetInstancesGet(void);

int STDCALL_CONVENTION WLRegNetInstancesMax(void);

void STDCALL_CONVENTION WLGetProtectionDate(SYSTEMTIME* pProtectionDate);

BOOL STDCALL_CONVENTION WLProtectCheckCodeIntegrity(void);

int STDCALL_CONVENTION WLHardwareGetIdType(void);

BOOL STDCALL_CONVENTION WLTrialStringRead(const char *StringName, char *StringValue);

BOOL STDCALL_CONVENTION WLTrialStringReadW(const wchar_t *StringName, wchar_t *StringValue);

BOOL STDCALL_CONVENTION WLTrialStringWrite(const char *StringName, const char *StringValue);

BOOL STDCALL_CONVENTION WLTrialStringWriteW(const wchar_t *StringName, const wchar_t *StringValue);

BOOL STDCALL_CONVENTION WLTrialDebugCheck(void);

BOOL STDCALL_CONVENTION WLRegExpirationTimestamp(LPFILETIME lpFileTime);

BOOL STDCALL_CONVENTION WLTrialExpirationTimestamp(LPFILETIME lpFileTime);

int STDCALL_CONVENTION WLRegGetLicenseRestrictions(void);

int STDCALL_CONVENTION WLRegGetLicenseType(void);

BOOL STDCALL_CONVENTION WLCheckVirtualPC(void);

BOOL STDCALL_CONVENTION WLHardwareGetIDW(wchar_t * pHardwareId);

int STDCALL_CONVENTION WLTrialGetTrialRestrictions(void);

int STDCALL_CONVENTION WLRegActivateSoftware(char *pActivationKey, int *OutWinsockErrorCode,
                                             char *OutServerOutput, int SizeServerOutput);

int STDCALL_CONVENTION WLRegDeactivateSoftware(char *pActivationKey, int *OutWinsockErrorCode,
                                             char *OutServerOutput, int SizeServerOutput);

int STDCALL_CONVENTION WLHardwareGetNumberUsbDrives(void);

BOOL STDCALL_CONVENTION WLHardwareGetUsbIdAt(int Index, char* pHardwareId);

BOOL STDCALL_CONVENTION WLHardwareGetUsbIdAtW(int Index, wchar_t* pHardwareId);

BOOL STDCALL_CONVENTION WLHardwareGetUsbNameAt(int Index, char* pUsbName);

BOOL STDCALL_CONVENTION WLHardwareGetUsbNameAtW(int Index, wchar_t* pUsbName);

int STDCALL_CONVENTION WLRegNetInstancesGetClientsIp(WL_IP_ADDRESS *pBufferIps, int MaxIpsToRetrieve);

int STDCALL_CONVENTION WLGetLastError(void);

#ifdef __cplusplus
}
#endif


 