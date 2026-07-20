// Direct (JSON-free) verification interface for UAPKI.
//
// This file lives in library/uapki/src/api/, so UAPKI's own CMake compiles
// it into libuapki via aux_source_directory(src/api ...). visibility("default")
// exports our symbols despite CXX_VISIBILITY_PRESET=hidden (the same way
// UAPKI_EXPORT does for process()).
//
// The logic mirrors verify_p7s from api/verify.cpp but works with ByteArray
// directly — no parson/JSON/base64. Supports the STRUCT and CHAIN validation
// levels (offline); FULL (OCSP/CRL) stays behind the JSON path.

#include "content-hasher.h"
#include "doc-verify.h"
#include "global-objects.h"
#include "cer-store.h"
#include "byte-array.h"
#include "uapki-ns.h"
#include "uapki-errors.h"

#include <cstring>
#include <cstdint>
#include <vector>

#define DIRECT_EXPORT __attribute__((visibility("default")))

using namespace UapkiNS;

// Upper bound on signer count accepted from an envelope.
static const size_t MAX_SIGNER_INFOS = 128;

extern "C" {

// Adds trusted certificates (DER) to the global get_cerstore() cache.
// Idempotently appends; the same singleton that verify uses.
DIRECT_EXPORT int uapki_direct_add_trusted(
    const uint8_t* const* certs,
    const size_t* cert_lens,
    size_t cert_count)
{
    try {
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
    }
    catch (...) {
        return RET_UAPKI_GENERAL_ERROR;
    }
}

// Reports how many certs live in the global store right now,
// splitting out how many are trusted. Used to prove/measure the accumulation
// of non-trusted envelope certs across verifications.
DIRECT_EXPORT int uapki_direct_cert_count(size_t* out_total, size_t* out_trusted)
{
    try {
        Cert::CerStore* cer_store = get_cerstore();
        if (!cer_store) return RET_UAPKI_GENERAL_ERROR;
        size_t total = 0, trusted = 0;
        int ret = cer_store->getCount(total, trusted);
        if (ret != RET_OK) return ret;
        if (out_total) *out_total = total;
        if (out_trusted) *out_trusted = trusted;
        return RET_OK;
    }
    catch (...) {
        return RET_UAPKI_GENERAL_ERROR;
    }
}

// Shared core: content_hasher is already set up by the caller (detached —
// filled with data/file; attached — empty, UAPKI takes it from the envelope).
static int verify_core(
    const uint8_t* sig, size_t sig_len,
    ContentHasher& content_hasher,
    int validation_type,
    int* out_signer_count,
    int* out_all_valid)
{
    *out_signer_count = 0;
    *out_all_valid = 0;

    // RAII: freed on every exit, including a thrown exception mid-verification.
    SmartBA sba_sig;
    if (!sba_sig.set(ba_alloc_from_uint8(sig, sig_len))) return RET_UAPKI_GENERAL_ERROR;

    Doc::Verify::VerifyOptions opts;
    opts.validationType = (validation_type >= 1)
        ? Doc::Verify::VerifyOptions::ValidationType::CHAIN
        : Doc::Verify::VerifyOptions::ValidationType::STRUCT;

    // Verification runs against a short-lived LOCAL cert store, so the certs
    // pulled from the envelope (signer, intermediates, TSP) die with it — they
    // never accumulate in the process-global store. The global store is used
    // purely as a trusted-cert cache: the local store *borrows* its already-
    // parsed trusted CerItems (no re-parsing, no ownership transfer). CerItem is
    // internally mutex-guarded, so the same borrowed items are safe to share
    // across concurrent verifications.
    Cert::CerStore local_store;
    if (Cert::CerStore* trusted = get_cerstore()) {
        // Snapshot the trusted items under a single lock (getCerItems).
        // An empty filter accepts every cert. addReference borrows the pointers;
        // the CerItems stay owned by the global store.
        Cert::CerStore::FilterListCerts all;
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
        // Guard against a malformed envelope claiming an absurd signer count:
        // no real CMS has thousands of signers, and resize(n) would otherwise
        // attempt an unbounded allocation.
        if (n > MAX_SIGNER_INFOS) { ret = RET_UAPKI_GENERAL_ERROR; break; }
        verify_sdoc.verifiedSignerInfos.resize(n);
        bool all_valid = (n > 0);

        for (size_t idx = 0; idx < n; idx++) {
            Doc::Verify::VerifiedSignerInfo& vsi = verify_sdoc.verifiedSignerInfos[idx];

            ret = vsi.init(verify_sdoc.libConfig, verify_sdoc.cerStore, verify_sdoc.crlStore, false);
            if (ret != RET_OK) break;
            ret = verify_sdoc.sdataParser.parseSignerInfo(idx, vsi.getSignerInfo());
            if (ret != RET_OK) break;
            if (!verify_sdoc.sdataParser.isContainDigestAlgorithm(vsi.getSignerInfo().getDigestAlgorithm())) {
                ret = RET_UAPKI_UNSUPPORTED_ALG; break;
            }

            ret = vsi.parseAttributes();            if (ret != RET_OK) break;
            ret = vsi.verifySignedAttribute();      if (ret != RET_OK) break;
            ret = vsi.verifyMessageDigest(*verify_sdoc.refContentHasher); if (ret != RET_OK) break;
            ret = vsi.verifySigningCertificateV2(); if (ret != RET_OK) break;

            //  full verify_p7s sequence: format + timestamps (CAdES-T/…)
            vsi.determineSignFormat();
            ret = vsi.tspCertToStore();             if (ret != RET_OK) break;
            ret = vsi.certValuesToStore();          if (ret != RET_OK) break;
            ret = vsi.verifyContentTimeStamp(*verify_sdoc.refContentHasher); if (ret != RET_OK) break;
            ret = vsi.verifySignatureTimeStamp();   if (ret != RET_OK) break;
            ret = vsi.verifyCertificateRefs();      if (ret != RET_OK) break;
            ret = vsi.verifyArchiveTimeStamp(verify_sdoc.addedCerts, verify_sdoc.addedCrls);
            if (ret != RET_OK) break;

            vsi.validateSignFormat(verify_sdoc.validateTime, verify_sdoc.refContentHasher->isPresent());

            if (opts.validationType >= Doc::Verify::VerifyOptions::ValidationType::CHAIN) {
                ret = vsi.buildCertChain();
                if (ret != RET_OK) break;
                //  CHAIN: validity-time checks only, no OCSP/CRL (as in validate_certs)
                vsi.validateValidityTimeCerts(vsi.getBestSignatureTime());
                for (auto& it : vsi.getCertChainItems()) {
                    it->setValidationType(Cert::ValidationType::NONE);
                }
            }
            vsi.validateStatusCerts();

            const char* st = vsi.getValidationStatus();
            if (!st || std::strcmp(st, "TOTAL-VALID") != 0) all_valid = false;
        }
        if (ret != RET_OK) break;

        *out_signer_count = (int)n;
        *out_all_valid = all_valid ? 1 : 0;
    } while (0);

    return ret;
}

// In-memory verification.
//   data == nullptr → attached; otherwise detached with data/data_len.
//   validation_type: 0 = STRUCT, 1 = CHAIN
DIRECT_EXPORT int uapki_direct_verify(
    const uint8_t* sig, size_t sig_len,
    const uint8_t* data, size_t data_len,
    int validation_type,
    int* out_signer_count,
    int* out_all_valid)
{
    *out_signer_count = 0;
    *out_all_valid = 0;
    try {
        ContentHasher content_hasher;
        if (data && data_len) {
            int ret = content_hasher.setContent(data, data_len);
            if (ret != RET_OK) return ret;
        }
        return verify_core(sig, sig_len, content_hasher, validation_type,
                           out_signer_count, out_all_valid);
    }
    catch (...) {
        return RET_UAPKI_GENERAL_ERROR;
    }
}

// Detached verification where the library reads and hashes the data from a
// file itself.
DIRECT_EXPORT int uapki_direct_verify_file(
    const uint8_t* sig, size_t sig_len,
    const char* data_path,
    int validation_type,
    int* out_signer_count,
    int* out_all_valid)
{
    *out_signer_count = 0;
    *out_all_valid = 0;
    try {
        ContentHasher content_hasher;
        if (data_path && data_path[0] != '\0') {
            int ret = content_hasher.setContent(data_path);
            if (ret != RET_OK) return ret;
        }
        return verify_core(sig, sig_len, content_hasher, validation_type,
                           out_signer_count, out_all_valid);
    }
    catch (...) {
        return RET_UAPKI_GENERAL_ERROR;
    }
}

} // extern "C"
