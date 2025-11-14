//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#ifndef __PKE_SERIAL_EXTERN_H__
#define __PKE_SERIAL_EXTERN_H__

#include "lattice/lat-hal.h"
#include "utils/serial-extern.h"
#include "binfhe-serial-extern.h"

#include <memory>
#include <map>
#include <string>
#include <vector>

// #if !defined(OPENFHE_ENABLE_SERIALIZATION)
//   #define OPENFHE_ENABLE_SERIALIZATION
// #endif

namespace lbcrypto {
    // template <typename T> class DCRTPolyImpl;
    // using DCRTPoly = DCRTPolyImpl<bigintdyn::mubintvec<bigintdyn::ubint<unsigned long>>>;

    // template <typename Element> class CiphertextImpl;
    // extern template class lbcrypto::CiphertextImpl<lbcrypto::Poly>;
    // extern template class lbcrypto::CiphertextImpl<lbcrypto::NativePoly>;
    // extern template class lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>;

    template <typename Element> class EvalKeyImpl;
    template <typename Element> class EvalKeyRelinImpl;
    template <typename Element> using EvalKey = std::shared_ptr<EvalKeyImpl<Element>>;

    class CryptoParametersRNS;
    class FHERNS;

    // Scheme-specific forwards (no include of the actual headers here)
    class CryptoParametersBFVRNS;
    class SchemeBFVRNS;
    class FHEBFVRNS;

    class CryptoParametersBGVRNS;
    class SchemeBGVRNS;
    class FHEBGVRNS;

    class CryptoParametersCKKSRNS;
    class SchemeCKKSRNS;
    class FHECKKSRNS;

    class SWITCHCKKSRNS;

    template <typename Element> class CryptoContextImpl;
    template <typename Element> class PublicKeyImpl;
    template <typename Element> class PrivateKeyImpl;
    template <typename Element> class CiphertextImpl;

    // extern template class CryptoContextImpl<DCRTPoly>;
    // extern template class PublicKeyImpl<DCRTPoly>;
    // extern template class PrivateKeyImpl<DCRTPoly>;
    // extern template class CiphertextImpl<DCRTPoly>;
}

EXTERN_SERIAL_FOR(std::map<std::string, std::vector<lbcrypto::EvalKey<lbcrypto::DCRTPoly>>>)
EXTERN_SERIAL_FOR(std::map<std::string, std::shared_ptr<std::map<uint32_t, lbcrypto::EvalKey<lbcrypto::DCRTPoly>>>>)

// RNS base + scheme-specific parameter and FHE types (polymorphic)
EXTERN_SERIAL_FOR(lbcrypto::CryptoParametersRNS)
EXTERN_SERIAL_FOR(lbcrypto::FHERNS)
EXTERN_SERIAL_FOR(lbcrypto::CryptoParametersBFVRNS)
EXTERN_SERIAL_FOR(lbcrypto::SchemeBFVRNS)
EXTERN_SERIAL_FOR(lbcrypto::FHEBFVRNS)
EXTERN_SERIAL_FOR(lbcrypto::CryptoParametersBGVRNS)
EXTERN_SERIAL_FOR(lbcrypto::SchemeBGVRNS)
EXTERN_SERIAL_FOR(lbcrypto::FHEBGVRNS)
EXTERN_SERIAL_FOR(lbcrypto::CryptoParametersCKKSRNS)
EXTERN_SERIAL_FOR(lbcrypto::SchemeCKKSRNS)
EXTERN_SERIAL_FOR(lbcrypto::FHECKKSRNS)
EXTERN_SERIAL_FOR(lbcrypto::SWITCHCKKSRNS)

EXTERN_SERIAL_FOR(std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>>)
EXTERN_SERIAL_FOR(std::shared_ptr<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>)
EXTERN_SERIAL_FOR(std::shared_ptr<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>)
EXTERN_SERIAL_FOR(std::shared_ptr<lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>>)

// EXTERN_SERIAL_FOR(lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>)
EXTERN_SERIAL_FOR(lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>)
EXTERN_SERIAL_FOR(lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>)
EXTERN_SERIAL_FOR(lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>)

#endif // __PKE_SERIAL_EXTERN_H__
