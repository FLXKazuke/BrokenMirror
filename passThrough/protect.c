#include <fltKernel.h>
#include <ntstrsafe.h>
#include <Ntifs.h>

// -------------------------------------------------------------
// Flags de nome (compatível com WDK antigos)
#if defined(FLT_FILE_NAME_DOS_VOLUME_NAME)
#define AR_NAME_FLAGS (FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_DOS_VOLUME_NAME)
#else
#define AR_NAME_FLAGS (FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT)
#endif
// -------------------------------------------------------------

static __forceinline BOOLEAN Match(PUNICODE_STRING Name, PCWSTR Pattern)
{
    if (!Name || Name->Length == 0) return FALSE;
    UNICODE_STRING Pat;
    RtlInitUnicodeString(&Pat, Pattern);
    return FsRtlIsNameInExpression(&Pat, Name, TRUE, NULL);
}

static __forceinline FLT_PREOP_CALLBACK_STATUS DenyThis(PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

// ------------------------------------------------------------------
// MODO SEGURO: Protege "tudo do C:\" (usuário/dados), exceto allowlist
//  - Suporta dois formatos de caminho:
//      * DOS (C:\...)  -> quando o WDK expõe FLT_FILE_NAME_DOS_VOLUME_NAME
//      * NT (\Device\HarddiskVolumeX\...) -> sempre disponível
//  - Em máquinas com um único volume, o padrão NT cobre o C:\.
// ------------------------------------------------------------------
BOOLEAN IsProtectedPath(PUNICODE_STRING FullName)
{
    if (!FullName || FullName->Length == 0)
        return FALSE;

    // Sinais de que estamos "no C:\"
    // (1) caminho DOS (C:\...) — só funcionará se o WDK der esse formato
    BOOLEAN isDosC = Match(FullName, L"\\??\\C:\\*") || Match(FullName, L"C:\\*");

    // (2) caminho NT normalizado (\Device\HarddiskVolumeX\...)
    //     Em ambientes comuns (um volume), isso corresponde ao C:.
    //     Mantemos allowlist também nesta forma.
    BOOLEAN isNtVol = Match(FullName, L"\\Device\\HarddiskVolume*\\*");

    if (!(isDosC || isNtVol))
        return FALSE;

    // -------------------- ALLOWLIST DOS --------------------
    if (isDosC) {
        if (Match(FullName, L"C:\\Windows\\*"))                     return FALSE;
        if (Match(FullName, L"C:\\Program Files\\*"))               return FALSE;
        if (Match(FullName, L"C:\\Program Files (x86)\\*"))         return FALSE;
        if (Match(FullName, L"C:\\ProgramData\\*"))                 return FALSE;
        if (Match(FullName, L"C:\\System Volume Information\\*"))   return FALSE;
        if (Match(FullName, L"C:\\$Extend\\*"))                     return FALSE;
        if (Match(FullName, L"C:\\pagefile.sys"))                   return FALSE;
        if (Match(FullName, L"C:\\hiberfil.sys"))                   return FALSE;
        if (Match(FullName, L"C:\\swapfile.sys"))                   return FALSE;

        return TRUE; // demais áreas do C:\ são protegidas
    }

    // -------------------- ALLOWLIST NT ---------------------
    // Equivalentes para o formato \Device\HarddiskVolumeX\...
    if (Match(FullName, L"\\Device\\HarddiskVolume*\\Windows\\*"))                   return FALSE;
    if (Match(FullName, L"\\Device\\HarddiskVolume*\\Program Files\\*"))            return FALSE;
    if (Match(FullName, L"\\Device\\HarddiskVolume*\\Program Files (x86)\\*"))      return FALSE;
    if (Match(FullName, L"\\Device\\HarddiskVolume*\\ProgramData\\*"))              return FALSE;
    if (Match(FullName, L"\\Device\\HarddiskVolume*\\System Volume Information\\*"))return FALSE;
    if (Match(FullName, L"\\Device\\HarddiskVolume*\\$Extend\\*"))                  return FALSE;

    // Arquivos raiz comuns (pode variar de volume para volume)
    if (Match(FullName, L"\\Device\\HarddiskVolume*\\pagefile.sys"))                return FALSE;
    if (Match(FullName, L"\\Device\\HarddiskVolume*\\hiberfil.sys"))                return FALSE;
    if (Match(FullName, L"\\Device\\HarddiskVolume*\\swapfile.sys"))                return FALSE;

    return TRUE;
}

// ------------------------------------------------------------------
// PRE-CREATE: bloquear aberturas com intenção de escrita nas áreas protegidas
// ------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS
PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    ACCESS_MASK desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if ((desired & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, AR_NAME_FLAGS, &nameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        if (IsProtectedPath(&nameInfo->Name)) {
            FltReleaseFileNameInformation(nameInfo);
            return DenyThis(Data);
        }
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ------------------------------------------------------------------
// PRE-WRITE: bloquear escrita em áreas protegidas
// ------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS
PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, AR_NAME_FLAGS, &nameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        if (IsProtectedPath(&nameInfo->Name)) {
            FltReleaseFileNameInformation(nameInfo);
            return DenyThis(Data);
        }
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ------------------------------------------------------------------
// PRE-SETINFO: bloquear RENAME / DELETE em áreas protegidas
// ------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS
PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    FILE_INFORMATION_CLASS fic = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (fic == FileRenameInformation || fic == FileRenameInformationEx ||
        fic == FileDispositionInformation || fic == FileDispositionInformationEx)
    {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        NTSTATUS status = FltGetFileNameInformation(Data, AR_NAME_FLAGS, &nameInfo);

        if (NT_SUCCESS(status)) {
            FltParseFileNameInformation(nameInfo);
            if (IsProtectedPath(&nameInfo->Name)) {
                FltReleaseFileNameInformation(nameInfo);
                return DenyThis(Data);
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
