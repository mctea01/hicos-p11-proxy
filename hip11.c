/** hip11.c – HiCOS PKCS#11 Proxy（防 CKR_BUFFER_TOO_SMALL／動態簽章長度‧多執行緒‧記憶體安全）
--- 公開授權協議: Apache License 2.0
--- 開發人員: ChatGPT o3、林哲全<jclin22873794@gmail.com>
--- (主要由ChatGPT O3) 於2025/4/28生成
--- 測試環境: Windows 11 專業版 24H2 OS組建 26100.3775 Windows 功能體驗套件 1000.26100.66.0
--- HiCOS PKCS11 版本: 3.1.0.00012 AMD64
--- 建議編譯指令(我的編譯指令):
--- clang-cl -fuse-ld=lld-link /D_USRDLL /D_WINDLL /I"%OPENSSL_DIR%/include" /MT hip11.c "%OPENSSL_DIR%/lib/libcrypto.lib" /link /DLL /OUT:hiP11.dll
--- #JAVA CFG#
--- name = HiCOS
--- library = /where/the/dll/path/hiP11.dll
--- slotListIndex = 0
--- attributes = compatibility
--- handleStartupErrors = ignoreAll
--- showInfo = false
--- #END of JAVA CFG#
--- 主要測試工具: Jsign 7.1 (Java HotSpot(TM) 64-Bit Server VM Oracle GraalVM 21.0.7+8.1 (build 21.0.7+8-LTS-jvmci-23.1-b60, mixed mode, sharing) java 21.0.7 2025-04-15 LTS)
--- 提示: 自然人憑證於HiCOS PKCS#11之cert1為數位簽署、cert2為檔案加、解密、資料交換
---*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define CRYPTOKI_EXPORTS
#include "include/pkcs11.h"

#define OPENSSL_SUPPRESS_DEPRECATED          /* 抑制 3.x 的 RSA_* 走期警告 */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

/*===========  前向宣告：避免尚未定義即被使用  ===========*/
extern CK_FUNCTION_LIST proxyList;

/*─────────────  後端 DLL  ─────────────*/
static HMODULE              g_hReal  = NULL;
static CK_FUNCTION_LIST_PTR g_pReal  = NULL;
static INIT_ONCE            g_once   = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION     g_cs;
static int                  g_csInit = 0;

/* 僅於第一次呼叫時載入 HiCOS 正式模組並取出函式表 */
static BOOL CALLBACK load_real(PINIT_ONCE, PVOID, PVOID*)
{
    InitializeCriticalSection(&g_cs); g_csInit = 1;

    /* 您可以改用環境變數或登錄檔取得實際 DLL 名稱 */
    g_hReal = LoadLibraryA("HiCOSPKCS11.dll");
    if (!g_hReal) return FALSE;

    CK_C_GetFunctionList get =
        (CK_C_GetFunctionList)GetProcAddress(g_hReal, "C_GetFunctionList");
    return get && get(&g_pReal) == CKR_OK;
}

static CK_RV ensure_real(void)
{
    if (!InitOnceExecuteOnce(&g_once, load_real, NULL, NULL))
        return CKR_GENERAL_ERROR;
    return g_pReal ? CKR_OK : CKR_GENERAL_ERROR;
}
#define EnsureReal ensure_real   /* 供 PASS 巨集使用 */

/*─────────────  通用轉發巨集  ─────────────*/
#define PASS(name,decl,args)                                              \
CK_DEFINE_FUNCTION(CK_RV, name) decl {                                    \
    if (EnsureReal() != CKR_OK) return CKR_CRYPTOKI_NOT_INITIALIZED;       \
    EnterCriticalSection(&g_cs);                                          \
    CK_RV rv = (g_pReal && g_pReal->name)                                 \
                 ? g_pReal->name args : CKR_FUNCTION_NOT_SUPPORTED;       \
    LeaveCriticalSection(&g_cs);                                          \
    return rv;                                                            \
}

/*─────────────  雜湊 ASNiDER 編碼表  ─────────────*/
typedef struct {
    CK_MECHANISM_TYPE pkcs1;
    CK_MECHANISM_TYPE pss;
    int               nid;
    const unsigned char *asn1;
    size_t            asn1Len;
} HASH_INFO;

static const unsigned char ASN_SHA1[]  =  {0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14};
static const unsigned char ASN_SHA256[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
static const unsigned char ASN_SHA384[] = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
static const unsigned char ASN_SHA512[] = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};

static const HASH_INFO g_hashTbl[] = {
    {CKM_SHA1_RSA_PKCS  , CKM_SHA1_RSA_PKCS_PSS  , NID_sha1  , ASN_SHA1  , sizeof(ASN_SHA1)},
    {CKM_SHA256_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS, NID_sha256, ASN_SHA256, sizeof(ASN_SHA256)},
    {CKM_SHA384_RSA_PKCS, CKM_SHA384_RSA_PKCS_PSS, NID_sha384, ASN_SHA384, sizeof(ASN_SHA384)},
    {CKM_SHA512_RSA_PKCS, CKM_SHA512_RSA_PKCS_PSS, NID_sha512, ASN_SHA512, sizeof(ASN_SHA512)}
};

static const EVP_MD* md_from_nid(int nid) { return EVP_get_digestbynid(nid); }

static const HASH_INFO* find_hash_info(CK_MECHANISM_TYPE m)
{
    for (size_t i = 0; i < sizeof(g_hashTbl) / sizeof(g_hashTbl[0]); ++i)
        if (g_hashTbl[i].pkcs1 == m || g_hashTbl[i].pss == m)
            return &g_hashTbl[i];
    return NULL;
}

/*─────────────  TLS（Thread Local）狀態  ─────────────*/
typedef struct {
    CK_SESSION_HANDLE sess;
    CK_OBJECT_HANDLE  key;
    const HASH_INFO  *info;
    int               pss;
    EVP_MD_CTX       *mdctx;
    size_t            modBytes;
} TLS_CTX;

static __declspec(thread) TLS_CTX tls = {0};

static void tls_reset(void)
{
    if (tls.mdctx) EVP_MD_CTX_free(tls.mdctx);
    memset(&tls, 0, sizeof(tls));
}

static size_t modulus_bytes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k)
{
    /* ① 試讀 CKA_MODULUS_BITS ------------------------------------------------*/
    CK_ULONG bits = 0; CK_ATTRIBUTE bitsAttr = {CKA_MODULUS_BITS, &bits, sizeof(bits)};
    if (g_pReal->C_GetAttributeValue(s, k, &bitsAttr, 1) == CKR_OK &&
        bitsAttr.ulValueLen == sizeof(bits) && bits)
        return (bits + 7) / 8;

    /* ② 失敗就改讀 CKA_MODULUS（公開欄位，最常見亦最可靠）-------------------*/
    CK_ATTRIBUTE modAttr = {CKA_MODULUS, NULL, 0};
    if (g_pReal->C_GetAttributeValue(s, k, &modAttr, 1) == CKR_OK &&
        modAttr.ulValueLen > 0)
        return modAttr.ulValueLen;

    /* ③ 仍取不到 → 回傳 0，由上層自動走「交還原生模組」路徑 ---------------*/
    return 0;
}

/*─────────────  C_Sign* 攔截實作  ─────────────*/
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)
    (CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k)
{
    if (ensure_real() != CKR_OK) return CKR_GENERAL_ERROR;

    const HASH_INFO *inf = find_hash_info(m->mechanism);
    if (!inf)
        return g_pReal->C_SignInit(s, m, k);

    tls_reset();
    tls.sess     = s;
    tls.key      = k;
    tls.info     = inf;
    tls.pss      = (m->mechanism == inf->pss);
    tls.modBytes = modulus_bytes(s, k);
    if (!tls.modBytes) return g_pReal->C_SignInit(s, m, k);

    tls.mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(tls.mdctx, md_from_nid(inf->nid), NULL);
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)
    (CK_SESSION_HANDLE s, CK_BYTE_PTR p, CK_ULONG l)
{
    if (!tls.mdctx || s != tls.sess)
        return g_pReal->C_SignUpdate
                 ? g_pReal->C_SignUpdate(s, p, l)
                 : CKR_FUNCTION_NOT_SUPPORTED;

    EVP_DigestUpdate(tls.mdctx, p, l);
    return CKR_OK;
}

/* 生成 PKCS#1 v1.5 Padding */
static int build_em_v15(unsigned char *em, size_t emLen,
                        const HASH_INFO *inf,
                        const unsigned char *d, size_t dLen)
{
    if (emLen < 3 + inf->asn1Len + dLen) return 0;
    size_t pad = emLen - 3 - inf->asn1Len - dLen;
    em[0] = 0; em[1] = 1; memset(em + 2, 0xFF, pad); em[2 + pad] = 0;
    memcpy(em + 3 + pad, inf->asn1, inf->asn1Len);
    memcpy(em + 3 + pad + inf->asn1Len, d, dLen);
    return 1;
}

/* 生成 PKCS#1 PSS Padding（使用 OpenSSL 內建） */
static int build_em_pss(unsigned char *em, size_t emLen,
                        const HASH_INFO *inf,
                        const unsigned char *d, size_t dLen)
{
    RSA *rsa = RSA_new();
    BIGNUM *n = BN_new();
    BN_set_bit(n, (int)emLen * 8 - 1);
    RSA_set0_key(rsa, n, BN_new(), NULL);

    int ok = RSA_padding_add_PKCS1_PSS_mgf1(
                 rsa, em, d,
                 md_from_nid(inf->nid), md_from_nid(inf->nid),
                 (int)dLen);
    RSA_free(rsa);
    return ok;
}

static CK_RV raw_rsa(CK_BYTE_PTR em, size_t len,
                     CK_BYTE_PTR sig, CK_ULONG_PTR sl)
{
    CK_MECHANISM mech = {CKM_RSA_X_509, NULL, 0};
    if (g_pReal->C_DecryptInit(tls.sess, &mech, tls.key) != CKR_OK)
        return CKR_GENERAL_ERROR;
    return g_pReal->C_Decrypt(tls.sess, em, (CK_ULONG)len, sig, sl);
}

static CK_RV do_final(CK_BYTE_PTR p, CK_ULONG l, int single,
                      CK_BYTE_PTR sig, CK_ULONG_PTR sl)
{
    if (!tls.mdctx) return CKR_OPERATION_NOT_INITIALIZED;
    if (single) EVP_DigestUpdate(tls.mdctx, p, l);

    unsigned char dgst[EVP_MAX_MD_SIZE];
    unsigned int  dgLen;
    EVP_DigestFinal_ex(tls.mdctx, dgst, &dgLen);

    size_t emLen = tls.modBytes;
    unsigned char *em = (unsigned char*)OPENSSL_malloc(emLen);

    int ok = tls.pss ? build_em_pss(em, emLen, tls.info, dgst, dgLen)
                     : build_em_v15(em, emLen, tls.info, dgst, dgLen);
    if (!ok) {
        OPENSSL_free(em); tls_reset(); return CKR_GENERAL_ERROR;
    }

    CK_ULONG outLen = (CK_ULONG)emLen;
    CK_RV rv = raw_rsa(em, emLen,
                       sig ? sig : (CK_BYTE_PTR)&outLen,
                       &outLen);

    OPENSSL_cleanse(em, emLen);
    OPENSSL_free(em);
    tls_reset();

    if (rv == CKR_OK) {
        if (!sig) { *sl = outLen; }
        else if (*sl < outLen) { *sl = outLen; rv = CKR_BUFFER_TOO_SMALL; }
        else *sl = outLen;
    }
    OPENSSL_cleanse(dgst, sizeof(dgst));
    return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Sign)
    (CK_SESSION_HANDLE s, CK_BYTE_PTR d, CK_ULONG l,
     CK_BYTE_PTR sig, CK_ULONG_PTR sl)
{
    if (ensure_real() != CKR_OK) return CKR_GENERAL_ERROR;
    if (s != tls.sess)
        return g_pReal->C_Sign(s, d, l, sig, sl);
    return do_final(d, l, 1, sig, sl);
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)
    (CK_SESSION_HANDLE s, CK_BYTE_PTR sig, CK_ULONG_PTR sl)
{
    if (ensure_real() != CKR_OK) return CKR_GENERAL_ERROR;
    if (s != tls.sess)
        return g_pReal->C_SignFinal(s, sig, sl);
    return do_final(NULL, 0, 0, sig, sl);
}

/* ───── 其餘轉發 ───── */
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR args)
{
    CK_RV rv = EnsureReal();              /* 保證 g_pReal 可用 */
    if (rv != CKR_OK) return rv;

    /* 多執行緒：Forward 前先鎖定，避免重入 */
    EnterCriticalSection(&g_cs);
    rv = g_pReal->C_Initialize
            ? g_pReal->C_Initialize(args)
            : CKR_OK;
    LeaveCriticalSection(&g_cs);
    return rv;
}
PASS(C_GetInfo,(CK_INFO_PTR i),(i))
PASS(C_GetSlotList,(CK_BBOOL tp,CK_SLOT_ID_PTR l,CK_ULONG_PTR c),(tp,l,c))
PASS(C_GetSlotInfo,(CK_SLOT_ID id,CK_SLOT_INFO_PTR i),(id,i))
PASS(C_GetTokenInfo,(CK_SLOT_ID id,CK_TOKEN_INFO_PTR i),(id,i))
PASS(C_GetMechanismList,(CK_SLOT_ID id,CK_MECHANISM_TYPE_PTR m,CK_ULONG_PTR c),(id,m,c))
PASS(C_GetMechanismInfo,(CK_SLOT_ID id,CK_MECHANISM_TYPE t,CK_MECHANISM_INFO_PTR i),(id,t,i))
PASS(C_InitToken,(CK_SLOT_ID id,CK_UTF8CHAR_PTR p,CK_ULONG l,CK_UTF8CHAR_PTR lbl),(id,p,l,lbl))
PASS(C_InitPIN,(CK_SESSION_HANDLE s,CK_UTF8CHAR_PTR p,CK_ULONG l),(s,p,l))
PASS(C_SetPIN,(CK_SESSION_HANDLE s,CK_UTF8CHAR_PTR o,CK_ULONG ol,CK_UTF8CHAR_PTR n,CK_ULONG nl),(s,o,ol,n,nl))
PASS(C_OpenSession,(CK_SLOT_ID id,CK_FLAGS f,CK_VOID_PTR app,CK_NOTIFY n,CK_SESSION_HANDLE_PTR ph),(id,f,app,n,ph))
PASS(C_CloseSession,(CK_SESSION_HANDLE s),(s))
PASS(C_CloseAllSessions,(CK_SLOT_ID id),(id))
PASS(C_GetSessionInfo,(CK_SESSION_HANDLE s,CK_SESSION_INFO_PTR i),(s,i))
PASS(C_GetOperationState,(CK_SESSION_HANDLE s,CK_BYTE_PTR st,CK_ULONG_PTR l),(s,st,l))
PASS(C_SetOperationState,(CK_SESSION_HANDLE s,CK_BYTE_PTR st,CK_ULONG l,CK_OBJECT_HANDLE ek,CK_OBJECT_HANDLE ak),(s,st,l,ek,ak))
PASS(C_Login,(CK_SESSION_HANDLE s,CK_USER_TYPE u,CK_UTF8CHAR_PTR p,CK_ULONG l),(s,u,p,l))
PASS(C_Logout,(CK_SESSION_HANDLE s),(s))
PASS(C_CreateObject,(CK_SESSION_HANDLE s,CK_ATTRIBUTE_PTR t,CK_ULONG n,CK_OBJECT_HANDLE_PTR o),(s,t,n,o))
PASS(C_CopyObject,(CK_SESSION_HANDLE s,CK_OBJECT_HANDLE o,CK_ATTRIBUTE_PTR t,CK_ULONG n,CK_OBJECT_HANDLE_PTR no),(s,o,t,n,no))
PASS(C_DestroyObject,(CK_SESSION_HANDLE s,CK_OBJECT_HANDLE o),(s,o))
PASS(C_GetObjectSize,(CK_SESSION_HANDLE s,CK_OBJECT_HANDLE o,CK_ULONG_PTR sz),(s,o,sz))
PASS(C_SetAttributeValue,(CK_SESSION_HANDLE s,CK_OBJECT_HANDLE o,CK_ATTRIBUTE_PTR t,CK_ULONG n),(s,o,t,n))
PASS(C_FindObjectsInit,(CK_SESSION_HANDLE s,CK_ATTRIBUTE_PTR t,CK_ULONG n),(s,t,n))
PASS(C_FindObjects,(CK_SESSION_HANDLE s,CK_OBJECT_HANDLE_PTR o,CK_ULONG m,CK_ULONG_PTR c),(s,o,m,c))
PASS(C_FindObjectsFinal,(CK_SESSION_HANDLE s),(s))
PASS(C_EncryptInit,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE k),(s,m,k))
PASS(C_Encrypt,(CK_SESSION_HANDLE s,CK_BYTE_PTR d,CK_ULONG dl,CK_BYTE_PTR ed,CK_ULONG_PTR edl),(s,d,dl,ed,edl))
PASS(C_EncryptUpdate,(CK_SESSION_HANDLE s,CK_BYTE_PTR p,CK_ULONG pl,CK_BYTE_PTR ep,CK_ULONG_PTR epl),(s,p,pl,ep,epl))
PASS(C_EncryptFinal,(CK_SESSION_HANDLE s,CK_BYTE_PTR l,CK_ULONG_PTR ll),(s,l,ll))
PASS(C_DecryptInit,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE k),(s,m,k))
PASS(C_Decrypt,(CK_SESSION_HANDLE s,CK_BYTE_PTR ed,CK_ULONG edl,CK_BYTE_PTR d,CK_ULONG_PTR dl),(s,ed,edl,d,dl))
PASS(C_DecryptUpdate,(CK_SESSION_HANDLE s,CK_BYTE_PTR ep,CK_ULONG epl,CK_BYTE_PTR p,CK_ULONG_PTR pl),(s,ep,epl,p,pl))
PASS(C_DecryptFinal,(CK_SESSION_HANDLE s,CK_BYTE_PTR lp,CK_ULONG_PTR lpl),(s,lp,lpl))
PASS(C_DigestInit,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m),(s,m))
PASS(C_Digest,(CK_SESSION_HANDLE s,CK_BYTE_PTR d,CK_ULONG dl,CK_BYTE_PTR dig,CK_ULONG_PTR digl),(s,d,dl,dig,digl))
PASS(C_DigestUpdate,(CK_SESSION_HANDLE s,CK_BYTE_PTR p,CK_ULONG pl),(s,p,pl))
PASS(C_DigestKey,(CK_SESSION_HANDLE s,CK_OBJECT_HANDLE k),(s,k))
PASS(C_DigestFinal,(CK_SESSION_HANDLE s,CK_BYTE_PTR dig,CK_ULONG_PTR digl),(s,dig,digl))
/* Sign / SignFinal / C_SignUpdate 已手動實作 */
PASS(C_SignRecoverInit,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE k),(s,m,k))
PASS(C_SignRecover,(CK_SESSION_HANDLE s,CK_BYTE_PTR d,CK_ULONG dl,CK_BYTE_PTR sig,CK_ULONG_PTR sl),(s,d,dl,sig,sl))
PASS(C_VerifyInit,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE k),(s,m,k))
PASS(C_Verify,(CK_SESSION_HANDLE s,CK_BYTE_PTR d,CK_ULONG dl,CK_BYTE_PTR sig,CK_ULONG sl),(s,d,dl,sig,sl))
PASS(C_VerifyUpdate,(CK_SESSION_HANDLE s,CK_BYTE_PTR p,CK_ULONG pl),(s,p,pl))
PASS(C_VerifyFinal,(CK_SESSION_HANDLE s,CK_BYTE_PTR sig,CK_ULONG sl),(s,sig,sl))
PASS(C_VerifyRecoverInit,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE k),(s,m,k))
PASS(C_VerifyRecover,(CK_SESSION_HANDLE s,CK_BYTE_PTR sig,CK_ULONG sl,CK_BYTE_PTR d,CK_ULONG_PTR dl),(s,sig,sl,d,dl))
PASS(C_DigestEncryptUpdate,(CK_SESSION_HANDLE s,CK_BYTE_PTR p,CK_ULONG pl,CK_BYTE_PTR ep,CK_ULONG_PTR epl),(s,p,pl,ep,epl))
PASS(C_DecryptDigestUpdate,(CK_SESSION_HANDLE s,CK_BYTE_PTR ep,CK_ULONG epl,CK_BYTE_PTR p,CK_ULONG_PTR pl),(s,ep,epl,p,pl))
PASS(C_SignEncryptUpdate,(CK_SESSION_HANDLE s,CK_BYTE_PTR p,CK_ULONG pl,CK_BYTE_PTR ep,CK_ULONG_PTR epl),(s,p,pl,ep,epl))
PASS(C_DecryptVerifyUpdate,(CK_SESSION_HANDLE s,CK_BYTE_PTR ep,CK_ULONG epl,CK_BYTE_PTR p,CK_ULONG_PTR pl),(s,ep,epl,p,pl))
PASS(C_GenerateKey,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_ATTRIBUTE_PTR t,CK_ULONG n,CK_OBJECT_HANDLE_PTR k),(s,m,t,n,k))
PASS(C_GenerateKeyPair,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_ATTRIBUTE_PTR pub,CK_ULONG pc,CK_ATTRIBUTE_PTR priv,CK_ULONG prc,CK_OBJECT_HANDLE_PTR pk,CK_OBJECT_HANDLE_PTR sk),(s,m,pub,pc,priv,prc,pk,sk))
PASS(C_WrapKey,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE wk,CK_OBJECT_HANDLE k,CK_BYTE_PTR w,CK_ULONG_PTR wl),(s,m,wk,k,w,wl))
PASS(C_UnwrapKey,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE uk,CK_BYTE_PTR w,CK_ULONG wl,CK_ATTRIBUTE_PTR t,CK_ULONG n,CK_OBJECT_HANDLE_PTR k),(s,m,uk,w,wl,t,n,k))
PASS(C_DeriveKey,(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE bk,CK_ATTRIBUTE_PTR t,CK_ULONG n,CK_OBJECT_HANDLE_PTR k),(s,m,bk,t,n,k))
PASS(C_SeedRandom,(CK_SESSION_HANDLE s,CK_BYTE_PTR sd,CK_ULONG sl),(s,sd,sl))
PASS(C_GenerateRandom,(CK_SESSION_HANDLE s,CK_BYTE_PTR rd,CK_ULONG rl),(s,rd,rl))
PASS(C_GetFunctionStatus,(CK_SESSION_HANDLE s),(s))
PASS(C_CancelFunction,(CK_SESSION_HANDLE s),(s))
PASS(C_WaitForSlotEvent,(CK_FLAGS f,CK_SLOT_ID_PTR si,CK_VOID_PTR r),(f,si,r))
PASS(C_GetAttributeValue, (CK_SESSION_HANDLE s,CK_OBJECT_HANDLE o,
                           CK_ATTRIBUTE_PTR t,CK_ULONG n), (s,o,t,n))

/* C_Finalize – 轉發並釋放資源 */
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR reserved)
{
    CK_RV rv = ensure_real();
    if (rv == CKR_OK && g_pReal->C_Finalize)
        rv = g_pReal->C_Finalize(reserved);

    /* 卸載後端 DLL 與 CS */
    if (g_hReal) { FreeLibrary(g_hReal); g_hReal = NULL; }
    if (g_csInit) { DeleteCriticalSection(&g_cs); g_csInit = 0; }
    g_pReal = NULL;
    return rv;
}

/* C_GetFunctionList – 回傳本 Proxy 的函式表 */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR pp)
{
    if (!pp) return CKR_ARGUMENTS_BAD;
    *pp = &proxyList;
    return CKR_OK;
}

/* ───── Function List ───── */
CK_FUNCTION_LIST proxyList = {
  {2,20},
  C_Initialize,C_Finalize,C_GetInfo,C_GetFunctionList,
  C_GetSlotList,C_GetSlotInfo,C_GetTokenInfo,
  C_GetMechanismList,C_GetMechanismInfo,
  C_InitToken,C_InitPIN,C_SetPIN,
  C_OpenSession,C_CloseSession,C_CloseAllSessions,
  C_GetSessionInfo,C_GetOperationState,C_SetOperationState,
  C_Login,C_Logout,
  C_CreateObject,C_CopyObject,C_DestroyObject,C_GetObjectSize,
  C_GetAttributeValue,C_SetAttributeValue,
  C_FindObjectsInit,C_FindObjects,C_FindObjectsFinal,
  C_EncryptInit,C_Encrypt,C_EncryptUpdate,C_EncryptFinal,
  C_DecryptInit,C_Decrypt,C_DecryptUpdate,C_DecryptFinal,
  C_DigestInit,C_Digest,C_DigestUpdate,C_DigestKey,C_DigestFinal,
  C_SignInit,C_Sign,C_SignUpdate,C_SignFinal,
  C_SignRecoverInit,C_SignRecover,
  C_VerifyInit,C_Verify,C_VerifyUpdate,C_VerifyFinal,
  C_VerifyRecoverInit,C_VerifyRecover,
  C_DigestEncryptUpdate,C_DecryptDigestUpdate,
  C_SignEncryptUpdate,C_DecryptVerifyUpdate,
  C_GenerateKey,C_GenerateKeyPair,
  C_WrapKey,C_UnwrapKey,C_DeriveKey,
  C_SeedRandom,C_GenerateRandom,
  C_GetFunctionStatus,C_CancelFunction,
  C_WaitForSlotEvent
};

/*─────────────  DllMain – 清理保險  ─────────────*/
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_DETACH) C_Finalize(NULL);
    return TRUE;
}
