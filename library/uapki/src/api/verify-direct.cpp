// Direct verification interface for UAPKI: bytes in, verdict out.
//
// Living under src/api/ gets it compiled into libuapki by UAPKI's own CMake;
// visibility("default") exports the symbols despite the hidden default.
//
// Validation levels:
//   STRUCT   — signature and content digest only; needs no certificates.
//   ENVELOPE — plus the timestamps and references the envelope carries. Builds
//              no chain, so it accepts without the signer's CA — but a timestamp
//              is signed too, and verifying it needs the TSA's certificate.
//   CHAIN    — plus the chain to trusted CAs, offline.
//   FULL     — plus revocation status, every CAdES level; needs offline = 0.

#include "content-hasher.h"
#include "doc-verify.h"
#include "global-objects.h"
#include "cer-store.h"
#include "byte-array.h"
#include "http-helper.h"
#include "library-config.h"
#include "ocsp-helper.h"
#include "signature-format.h"
#include "uapki-ns.h"
#include "uapki-errors.h"

#include <cstring>
#include <cstdint>
#include <vector>

#define DIRECT_EXPORT __attribute__((visibility("default")))

using namespace UapkiNS;

static const size_t MAX_SIGNER_INFOS = 128;

//  No exception may cross the C boundary: every entry point answers with a
//  UAPKI error code instead.
template <typename Body>
static int guarded(Body body)
{
    try {
        return body();
    }
    catch (...) {
        return RET_UAPKI_GENERAL_ERROR;
    }
}

extern "C" {

DIRECT_EXPORT int uapki_direct_add_trusted(
    const uint8_t* const* certs,
    const size_t* cert_lens,
    size_t cert_count);

// Library config, HTTP layer, request timeouts, and trusted certificates added
// to those already trusted. Offline keeps the library off the network; online
// enables the OCSP/CRL fetching FULL needs. Timeouts are milliseconds, 0 keeps
// the current value; only_crl restricts revocation checking to CRLs.
//
// Only ever widens the trusted set — to state one, call
// uapki_direct_clear_trusted() first and read its contract.
DIRECT_EXPORT int uapki_direct_init(
    int offline,
    const char* proxy_url,
    const char* proxy_credentials,
    int connect_timeout_ms,
    int total_timeout_ms,
    int only_crl,
    const uint8_t* const* certs,
    const size_t* cert_lens,
    size_t cert_count)
{
    return guarded([&] {
        LibraryConfig* config = get_config();
        if (!config) return RET_UAPKI_GENERAL_ERROR;

        config->setOffline(offline != 0);
        config->setOcsp(LibraryConfig::OcspParams());  //  defaults (nonce length)
        config->setValidationByCrl(only_crl != 0);
        config->setInitialized(true);

        //  Create the global CRL store here, on the single-threaded init path.
        //  It is otherwise first touched inside verify_core, which runs
        //  concurrently, and the lazy new in global-objects.cpp is unlocked —
        //  parallel first-use would race. get_config/get_cerstore are already
        //  warmed above (the latter via add_trusted); this closes the last one.
        if (!get_crlstore()) return RET_UAPKI_GENERAL_ERROR;

        HttpHelper::setTimeouts(connect_timeout_ms, total_timeout_ms);

        const int ret = HttpHelper::init(offline != 0, proxy_url, proxy_credentials);
        if (ret != RET_OK) return ret;

        return uapki_direct_add_trusted(certs, cert_lens, cert_count);
    });
}

// Appends to the same global cache verify reads; adding twice is harmless.
DIRECT_EXPORT int uapki_direct_add_trusted(
    const uint8_t* const* certs,
    const size_t* cert_lens,
    size_t cert_count)
{
    return guarded([&] {
        Cert::CerStore* cer_store = get_cerstore();
        if (!cer_store) return RET_UAPKI_GENERAL_ERROR;
        if (cert_count == 0) return RET_OK;

        VectorBA vba;
        vba.resize(cert_count);
        for (size_t i = 0; i < cert_count; i++) {
            vba[i] = ba_alloc_from_uint8(certs[i], cert_lens[i]);
            if (!vba[i]) return RET_UAPKI_GENERAL_ERROR;
        }
        std::vector<Cert::CerStore::AddedCerItem> added;
        // VectorBA frees its ByteArrays in the destructor
        return cer_store->addCerts(true /*trusted*/, false /*permanent*/, vba, added);
    });
}

// Drops every trusted certificate, so trust can be withdrawn and not only granted.
//
// Caller contract: must not run concurrently with a verification, which borrows
// the certificates this frees; nothing here enforces that. Callers that never
// withdraw trust simply never call this.
DIRECT_EXPORT int uapki_direct_clear_trusted(void)
{
    return guarded([&] {
        Cert::CerStore* cer_store = get_cerstore();
        if (!cer_store) return RET_UAPKI_GENERAL_ERROR;
        cer_store->clear();
        return RET_OK;
    });
}

DIRECT_EXPORT int uapki_direct_cert_count(size_t* out_total, size_t* out_trusted)
{
    return guarded([&] {
        Cert::CerStore* cer_store = get_cerstore();
        if (!cer_store) return RET_UAPKI_GENERAL_ERROR;
        size_t total = 0, trusted = 0;
        int ret = cer_store->getCount(total, trusted);
        if (ret != RET_OK) return ret;
        if (out_total) *out_total = total;
        if (out_trusted) *out_trusted = trusted;
        return RET_OK;
    });
}

// --- FULL validation: revocation status of every certificate in the chain ---

static int validate_by_ocsp(
    Doc::Verify::VerifiedSignerInfo& vsi,
    Doc::Verify::CertChainItem& item)
{
    Ocsp::OcspHelper ocsp_helper;
    SmartBA sba_sn;

    int ret = vsi.validateByOcsp(
        item.getSubject(), item.getIssuer(), item.getResultValidationByOcsp());
    if (ret != RET_OK) return ret;

    ret = ocsp_helper.parseBasicOcspResponse(
        item.getResultValidationByOcsp().basicOcspResponse.get());
    if (ret != RET_OK) return ret;
    ret = ocsp_helper.scanSingleResponses();
    if (ret != RET_OK) return ret;
    //  One OCSP request carries one certificate, so index 0 is the answer
    ret = ocsp_helper.getSerialNumberFromCertId(0, &sba_sn);
    if (ret != RET_OK) return ret;

    if (ba_cmp(sba_sn.get(), item.getSubject()->getSerialNumber()) == 0) {
        CertValidator::ResultValidationByOcsp& result = item.getResultValidationByOcsp();
        result.dataSource = CertValidator::DataSource::STORE;
        result.responseStatus = Ocsp::ResponseStatus::SUCCESSFUL;
        result.statusSignature = SignatureVerifyStatus::VALID;  //  checked above
        result.msProducedAt = ocsp_helper.getProducedAt();
        result.singleResponseInfo = ocsp_helper.getSingleResponseInfo(0);
    }
    item.setValidationType(Cert::ValidationType::OCSP);
    return RET_OK;
}

static int validate_by_crl(
    Doc::Verify::VerifiedSignerInfo& vsi,
    Doc::Verify::CertChainItem& item)
{
    const int ret = vsi.validateByCrl(
        item.getSubject(), vsi.getBestSignatureTime(), false,
        item.getResultValidationByCrl());
    if (ret != RET_OK) return ret;

    item.setValidationType(Cert::ValidationType::CRL);
    return RET_OK;
}

//  Try one source, fall back to the other; the CAdES level decides which comes
//  first and only_crl drops OCSP. The standard leaves the source to policy.
static void validate_chain(
    Doc::Verify::VerifiedSignerInfo& vsi,
    const bool crl_first,
    const bool only_crl)
{
    typedef int (*Source)(Doc::Verify::VerifiedSignerInfo&, Doc::Verify::CertChainItem&);
    const Source first = (only_crl || crl_first) ? validate_by_crl : validate_by_ocsp;
    const Source second = crl_first ? validate_by_ocsp : validate_by_crl;

    for (auto& it : vsi.getCertChainItems()) {
        if (it->isExpired()) continue;
        if (it->getValidationType() != Cert::ValidationType::UNDEFINED) continue;

        if ((first(vsi, *it) != RET_OK) && !only_crl) {
            it->setValidationType(Cert::ValidationType::UNDEFINED);
            (void)second(vsi, *it);
        }
    }
}

//  Mirrors validate_certs, per CAdES level.
static int validate_certs_full(Doc::Verify::VerifiedSignerInfo& vsi, const bool only_crl)
{
    const uint64_t bestsign_time = vsi.getBestSignatureTime();
    int ret = RET_OK;

    switch (vsi.getSignatureFormat()) {
    case SignatureFormat::CMS_SID_KEYID:
    case SignatureFormat::CADES_BES:
    case SignatureFormat::CADES_T:
    case SignatureFormat::CADES_C:
        //  Nothing embedded, so fetch it. C references a CRL and looks there
        //  first; the rest go to OCSP first.
        vsi.validateValidityTimeCerts(bestsign_time);
        validate_chain(vsi, vsi.getSignatureFormat() == SignatureFormat::CADES_C, only_crl);
        ret = vsi.addOcspCertsToChain(bestsign_time);
        if (ret != RET_OK) return ret;
        ret = vsi.addCrlCertsToChain(bestsign_time);
        break;

    case SignatureFormat::CADES_XL:
    case SignatureFormat::CADES_A:
        //  Carries revocation *values*: use them, then fill any gaps.
        ret = vsi.setRevocationValuesForChain(bestsign_time);
        if (ret != RET_OK) return ret;
        validate_chain(vsi, true, only_crl);
        ret = vsi.addOcspCertsToChain(bestsign_time);
        break;

    default:
        break;
    }
    return ret;
}

//  Past signature validation (ETSI EN 319 102-1): a revocation dated after the
//  signature existed does not invalidate it. The clock is the best-signature-time,
//  the same one validateValidityTimeCerts uses. Dates alone decide — rfc5280
//  $5.3.2 expects a compromise to surface as invalidityDate, which is what
//  excludes signatures made inside that window. certificateHold never rescues.
static bool revoked_before(
    const uint64_t bestsign_time,
    const uint64_t revocation_time,
    const uint64_t invalidity_time,
    const UapkiNS::CrlReason reason)
{
    if (reason == UapkiNS::CrlReason::CERTIFICATE_HOLD) return false;
    if ((bestsign_time == 0) || (revocation_time == 0)) return false;

    //  invalidityDate supersedes the date the CA processed the revocation. Both
    //  sources may carry it (rfc6960 $4.4.5 repeats CRL entry extensions), but it
    //  is optional.
    const uint64_t invalid_from = (invalidity_time > 0) ? invalidity_time : revocation_time;
    return bestsign_time < invalid_from;
}

//  From whichever source answered. `status` is writable so past validation can
//  reconcile it, and null when no source answered at all.
struct RevocationFacts {
    UapkiNS::CertStatus* status = nullptr;
    uint64_t    revocationTime = 0;
    uint64_t    invalidityTime = 0;
    UapkiNS::CrlReason reason = UapkiNS::CrlReason::UNDEFINED;
};

static RevocationFacts revocation_facts(Doc::Verify::CertChainItem& item)
{
    RevocationFacts facts;
    switch (item.getValidationType()) {
    case Cert::ValidationType::CRL: {
        CertValidator::ResultValidationByCrl& r = item.getResultValidationByCrl();
        facts.status = &r.certStatus;
        facts.revocationTime = r.revokedCertItem.revocationDate;
        facts.invalidityTime = r.revokedCertItem.invalidityDate;
        facts.reason = r.revokedCertItem.crlReason;
        break;
    }
    case Cert::ValidationType::OCSP: {
        Ocsp::OcspHelper::SingleResponseInfo& o =
            item.getResultValidationByOcsp().singleResponseInfo;
        facts.status = &o.certStatus;
        facts.revocationTime = o.msRevocationTime;
        facts.invalidityTime = o.msInvalidityDate;
        facts.reason = o.revocationReason;
        break;
    }
    default:
        break;
    }
    return facts;
}

//  An unfetchable CAdES-C reference leaves an "expected CRL" that UAPKI turns
//  into INDETERMINATE even when OCSP already answered — stricter than rfc5126
//  $6.2.2, where a reference is a CRL *or* an OCSP response, and only a "should".
//  So it is a gap only where no status was established, and VerifyStatus VALID
//  does not prove one was: a certificate checked on validity time alone is VALID
//  too. Each must be settled by a definitive answer, or be a trust anchor.
static bool revocation_established_despite_crl_refs(Doc::Verify::VerifiedSignerInfo& vsi)
{
    if (!vsi.getExpectedCerts().empty()) return false;
    if (vsi.getExpectedCrls().empty()) return false;

    for (const auto& it : vsi.getCertChainItems()) {
        if (it->getValidationType() == Cert::ValidationType::NONE) continue;  // trust anchor

        const RevocationFacts facts = revocation_facts(*it);
        if (!facts.status) return false;
        if ((*facts.status != UapkiNS::CertStatus::GOOD)
            && (*facts.status != UapkiNS::CertStatus::REVOKED)) return false;
    }
    return true;
}

static bool has_revoked_cert(Doc::Verify::VerifiedSignerInfo& vsi)
{
    for (auto& it : vsi.getCertChainItems()) {
        const RevocationFacts facts = revocation_facts(*it);
        if (facts.status && (*facts.status == UapkiNS::CertStatus::REVOKED)) return true;
    }
    return false;
}

//  Clears the revocations the signature predates. Returns true if one survives.
static bool apply_past_validation(Doc::Verify::VerifiedSignerInfo& vsi)
{
    //  Without a time to compare against, nothing is placed at all.
    const uint64_t bestsign_time = vsi.getBestSignatureTime();
    if (bestsign_time == 0) return has_revoked_cert(vsi);

    for (auto& it : vsi.getCertChainItems()) {
        const RevocationFacts facts = revocation_facts(*it);
        if (!facts.status || (*facts.status != UapkiNS::CertStatus::REVOKED)) continue;

        if (revoked_before(bestsign_time, facts.revocationTime,
                facts.invalidityTime, facts.reason)) {
            *facts.status = UapkiNS::CertStatus::GOOD;
        }
    }

    //  ETSI EN 319 102-1 $5.6.2.4: a survivor is REVOKED_NO_POE — undecidable,
    //  since the signature may still pre-date the revocation.
    return has_revoked_cert(vsi);
}

//  Finer-grained than UAPKI's own levels; see the file header.
static const int LEVEL_STRUCT = 0;
static const int LEVEL_ENVELOPE = 1;
static const int LEVEL_CHAIN = 2;
static const int LEVEL_FULL = 3;

//  The three outcomes the standards define; INDETERMINATE is not a weaker
//  failure but a lack of evidence, which the caller's policy reads either way.
//  The numbers are the wire contract for `out_verdict`, declared again on the
//  caller's side: changing one here means changing both.
static const int VERDICT_FAILED = 0;
static const int VERDICT_VALID = 1;
static const int VERDICT_INDETERMINATE = 2;

//  Everything one signer needs before its certificates are judged. STRUCT stops
//  after the digest: the two statuses it reads come only from verifySignedAttribute
//  and verifyMessageDigest, so the rest would only be discarded.
static int verify_signer(
    Doc::Verify::VerifySignedDoc& verify_sdoc,
    Doc::Verify::VerifiedSignerInfo& vsi,
    const size_t idx,
    const bool struct_only)
{
    int ret = vsi.init(verify_sdoc.libConfig, verify_sdoc.cerStore, verify_sdoc.crlStore, false);
    if (ret != RET_OK) return ret;
    ret = verify_sdoc.sdataParser.parseSignerInfo(idx, vsi.getSignerInfo());
    if (ret != RET_OK) return ret;
    if (!verify_sdoc.sdataParser.isContainDigestAlgorithm(vsi.getSignerInfo().getDigestAlgorithm())) {
        return RET_UAPKI_UNSUPPORTED_ALG;
    }

    ret = vsi.parseAttributes();            if (ret != RET_OK) return ret;
    ret = vsi.verifySignedAttribute();      if (ret != RET_OK) return ret;
    ret = vsi.verifyMessageDigest(*verify_sdoc.refContentHasher); if (ret != RET_OK) return ret;
    if (struct_only) return RET_OK;

    ret = vsi.verifySigningCertificateV2(); if (ret != RET_OK) return ret;

    vsi.determineSignFormat();
    ret = vsi.tspCertToStore();             if (ret != RET_OK) return ret;
    ret = vsi.certValuesToStore();          if (ret != RET_OK) return ret;
    ret = vsi.verifyContentTimeStamp(*verify_sdoc.refContentHasher); if (ret != RET_OK) return ret;
    ret = vsi.verifySignatureTimeStamp();   if (ret != RET_OK) return ret;
    ret = vsi.verifyCertificateRefs();      if (ret != RET_OK) return ret;
    ret = vsi.verifyArchiveTimeStamp(verify_sdoc.addedCerts, verify_sdoc.addedCrls);
    if (ret != RET_OK) return ret;

    vsi.validateSignFormat(verify_sdoc.validateTime, verify_sdoc.refContentHasher->isPresent());
    return RET_OK;
}

// content_hasher arrives ready: filled for detached, empty for attached.
static int verify_core(
    const uint8_t* sig, size_t sig_len,
    ContentHasher& content_hasher,
    int validation_type,
    uint32_t* out_signer_count,
    int* out_verdict)
{
    *out_signer_count = 0;
    *out_verdict = VERDICT_FAILED;

    // RAII: freed on every exit, including a thrown exception mid-verification.
    SmartBA sba_sig;
    if (!sba_sig.set(ba_alloc_from_uint8(sig, sig_len))) return RET_UAPKI_GENERAL_ERROR;

    const int level = ((validation_type >= LEVEL_STRUCT) && (validation_type <= LEVEL_FULL))
        ? validation_type : LEVEL_STRUCT;

    Doc::Verify::VerifyOptions opts;
    opts.onlyCrl = get_config()->getValidationByCrl();
    //  ENVELOPE judges no certificate, so UAPKI itself still runs at STRUCT.
    switch (level) {
    case LEVEL_FULL:  opts.validationType = Doc::Verify::VerifyOptions::ValidationType::FULL;   break;
    case LEVEL_CHAIN: opts.validationType = Doc::Verify::VerifyOptions::ValidationType::CHAIN;  break;
    default:          opts.validationType = Doc::Verify::VerifyOptions::ValidationType::STRUCT; break;
    }

    // Short-lived, so envelope certs die with it instead of accumulating in the
    // global store. addReference borrows that store's CerItems rather than copying,
    // so they must outlive this call — see uapki_direct_clear_trusted.
    Cert::CerStore local_store;
    if (Cert::CerStore* trusted = get_cerstore()) {
        Cert::CerStore::FilterListCerts all;  // empty filter accepts every cert
        for (Cert::CerItem* c : trusted->getCerItems(all)) {
            local_store.addReference(c);
        }
    }

    Doc::Verify::VerifySignedDoc verify_sdoc(
        get_config(), &local_store, get_crlstore(), opts);
    int ret = RET_OK;

    do {
        if (!verify_sdoc.isInitialized()) { ret = RET_UAPKI_GENERAL_ERROR; break; }
        ret = verify_sdoc.parse(sba_sig.get());       if (ret != RET_OK) break;
        ret = verify_sdoc.getContent(content_hasher); if (ret != RET_OK) break;
        ret = verify_sdoc.addCertsToStore();          if (ret != RET_OK) break;

        const size_t n = verify_sdoc.sdataParser.getCountSignerInfos();
        // A malformed envelope must not turn resize(n) into an unbounded
        // allocation; no real CMS has thousands of signers.
        if (n > MAX_SIGNER_INFOS) { ret = RET_UAPKI_GENERAL_ERROR; break; }
        verify_sdoc.verifiedSignerInfos.resize(n);
        //  Worst outcome across signers wins: the verdict only ever moves toward
        //  worse, so an undecidable signer never masks a failed one.
        int verdict = (n > 0) ? VERDICT_VALID : VERDICT_FAILED;
        bool undecidable_revocation = false;

        for (size_t idx = 0; idx < n; idx++) {
            Doc::Verify::VerifiedSignerInfo& vsi = verify_sdoc.verifiedSignerInfos[idx];

            ret = verify_signer(verify_sdoc, vsi, idx, level == LEVEL_STRUCT);
            if (ret != RET_OK) break;

            //  What STRUCT checks, and the floor under every level above it:
            //  INDETERMINATE is never reported for a signature that is not sound.
            const bool crypto_held =
                (vsi.getStatusSignature() == SignatureVerifyStatus::VALID)
                && (!verify_sdoc.refContentHasher->isPresent()
                    || (vsi.getStatusMessageDigest() == DigestVerifyStatus::VALID));

            if (level >= LEVEL_CHAIN) {
                ret = vsi.buildCertChain();
                if (ret != RET_OK) break;

                if (opts.validationType == Doc::Verify::VerifyOptions::ValidationType::FULL) {
                    ret = validate_certs_full(vsi, opts.onlyCrl);
                    if (ret != RET_OK) break;
                    undecidable_revocation = apply_past_validation(vsi);
                }
                else {
                    vsi.validateValidityTimeCerts(vsi.getBestSignatureTime());
                    for (auto& it : vsi.getCertChainItems()) {
                        it->setValidationType(Cert::ValidationType::NONE);
                    }
                }
                vsi.validateStatusCerts();

                const char* st = vsi.getValidationStatus();
                if (!st) {
                    verdict = VERDICT_FAILED;
                }
                else if (std::strcmp(st, "INDETERMINATE") == 0) {
                    if (revocation_established_despite_crl_refs(vsi)) {
                        //  only an unresolved CRL reference — leave the verdict
                    }
                    else if (!crypto_held) {
                        verdict = VERDICT_FAILED;
                    }
                    else if (verdict == VERDICT_VALID) {
                        verdict = VERDICT_INDETERMINATE;
                    }
                }
                else if (std::strcmp(st, "TOTAL-VALID") != 0) {
                    if (undecidable_revocation && crypto_held) {
                        if (verdict == VERDICT_VALID) verdict = VERDICT_INDETERMINATE;
                    }
                    else {
                        verdict = VERDICT_FAILED;
                    }
                }
            }
            else if (level == LEVEL_ENVELOPE) {
                //  validateSignFormat already aggregated every signature, digest,
                //  timestamp and reference; no chain, no certificate judged.
                const char* st = vsi.getValidationStatus();
                if (!st || !crypto_held) {
                    verdict = VERDICT_FAILED;
                }
                else if (std::strcmp(st, "INDETERMINATE") == 0) {
                    if (verdict == VERDICT_VALID) verdict = VERDICT_INDETERMINATE;
                }
                else if (std::strcmp(st, "TOTAL-VALID") != 0) {
                    verdict = VERDICT_FAILED;
                }
            }
            else if (!crypto_held) {
                verdict = VERDICT_FAILED;
            }
        }
        if (ret != RET_OK) break;

        *out_signer_count = (uint32_t)n;
        *out_verdict = verdict;
    } while (0);

    return ret;
}

//  The entry points differ only in where the detached content comes from.
static int verify_entry(
    const uint8_t* sig, size_t sig_len,
    const uint8_t* data, size_t data_len,
    const char* data_path,
    int validation_type,
    uint32_t* out_signer_count,
    int* out_verdict)
{
    *out_signer_count = 0;
    *out_verdict = VERDICT_FAILED;
    return guarded([&] {
        ContentHasher content_hasher;
        int ret = RET_OK;
        if (data && data_len) {
            ret = content_hasher.setContent(data, data_len);
        }
        else if (data_path && (data_path[0] != '\0')) {
            ret = content_hasher.setContent(data_path);
        }
        if (ret != RET_OK) return ret;

        return verify_core(sig, sig_len, content_hasher, validation_type,
                           out_signer_count, out_verdict);
    });
}

// In-memory verification.
//   data == nullptr → attached; otherwise detached with data/data_len.
//   validation_type: 0 STRUCT, 1 ENVELOPE, 2 CHAIN, 3 FULL
DIRECT_EXPORT int uapki_direct_verify(
    const uint8_t* sig, size_t sig_len,
    const uint8_t* data, size_t data_len,
    int validation_type,
    uint32_t* out_signer_count,
    int* out_verdict)
{
    return verify_entry(sig, sig_len, data, data_len, nullptr,
                        validation_type, out_signer_count, out_verdict);
}

// Detached, with the library reading and hashing the file itself.
DIRECT_EXPORT int uapki_direct_verify_file(
    const uint8_t* sig, size_t sig_len,
    const char* data_path,
    int validation_type,
    uint32_t* out_signer_count,
    int* out_verdict)
{
    return verify_entry(sig, sig_len, nullptr, 0, data_path,
                        validation_type, out_signer_count, out_verdict);
}

} // extern "C"
