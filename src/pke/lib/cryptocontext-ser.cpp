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

#include "cryptocontext-ser.h"   // generic declarations
#include "cryptocontext.h"       // full class template definition
#include "cryptocontextfactory.h"

// pull in the heavy scheme-specific serialization glue ONLY HERE
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

// cereal / std
#include "cereal/archives/json.hpp"
#include "cereal/archives/portable_binary.hpp"
#include <fstream>
#include <sstream>

// Single place to define the version specialization to avoid multiple defs
CEREAL_CLASS_VERSION(lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>,
                     lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::SerializedVersion());

namespace lbcrypto {

namespace Serial {

// ---------- JSON ----------
template <typename Element>
void Deserialize(CryptoContext<Element>& obj, std::istream& stream, const SerType::SERJSON&) {
    CryptoContext<Element> newob;
    cereal::JSONInputArchive archive(stream);
    archive(newob);
    obj = CryptoContextFactory<Element>::GetContext(
        newob->GetCryptoParameters(), newob->GetScheme(), newob->getSchemeId());
}

template <typename Element>
bool DeserializeFromFile(const std::string& filename, CryptoContext<Element>& obj, const SerType::SERJSON& st) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (!file.is_open()) return false;
    Deserialize(obj, file, st);
    return true;
}

// ---------- BINARY ----------
template <typename Element>
void Deserialize(CryptoContext<Element>& obj, std::istream& stream, const SerType::SERBINARY&) {
    CryptoContext<Element> newob;
    cereal::PortableBinaryInputArchive archive(stream);
    archive(newob);
    obj = CryptoContextFactory<Element>::GetContext(
        newob->GetCryptoParameters(), newob->GetScheme(), newob->getSchemeId());
}

template <typename Element>
bool DeserializeFromFile(const std::string& filename, CryptoContext<Element>& obj, const SerType::SERBINARY& st) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (!file.is_open()) return false;
    Deserialize(obj, file, st);
    return true;
}

template <typename Element>
void DeserializeFromString(CryptoContext<Element>& obj, const std::string& json) {
    std::stringstream s;
    s << json;
    Deserialize(obj, s, SerType::JSON);
}

} // namespace Serial

// -----------------------------
// Explicit INSTANTIATIONS you actually need (for DCRTPoly)
// -----------------------------
template void Serial::Deserialize<DCRTPoly>(CryptoContext<DCRTPoly>&, std::istream&, const SerType::SERJSON&);
template bool Serial::DeserializeFromFile<DCRTPoly>(const std::string&, CryptoContext<DCRTPoly>&, const SerType::SERJSON&);
template void Serial::DeserializeFromString<DCRTPoly>(CryptoContext<DCRTPoly>&, const std::string&);

template void Serial::Deserialize<DCRTPoly>(CryptoContext<DCRTPoly>&, std::istream&, const SerType::SERBINARY&);
template bool Serial::DeserializeFromFile<DCRTPoly>(const std::string&, CryptoContext<DCRTPoly>&, const SerType::SERBINARY&);

// -----------------------------
// (Optional) If you want to keep the member-template explicit instantiations,
// define them here (no externs in headers).
// -----------------------------
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERJSON>(
    std::ostream&, const SerType::SERJSON&, const std::string&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERJSON>(
    std::ostream&, const SerType::SERJSON&, const CryptoContext<DCRTPoly>);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERJSON>(
    std::istream&, const SerType::SERJSON&);

template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERJSON>(
    std::ostream&, const SerType::SERJSON&, const std::string&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERJSON>(
    std::ostream&, const SerType::SERJSON&, const CryptoContext<DCRTPoly>);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey<SerType::SERJSON>(
    std::istream&, const SerType::SERJSON&);

template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERJSON>(
    std::ostream&, const SerType::SERJSON&, const std::string&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERJSON>(
    std::ostream&, const SerType::SERJSON&, const CryptoContext<DCRTPoly>);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERJSON>(
    std::istream&, const SerType::SERJSON&);

// ----- BINARY variants -----
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(
    std::ostream&, const SerType::SERBINARY&, const std::string&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(
    std::ostream&, const SerType::SERBINARY&, const CryptoContext<DCRTPoly>);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERBINARY>(
    std::istream&, const SerType::SERBINARY&);

template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERBINARY>(
    std::ostream&, const SerType::SERBINARY&, const std::string&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERBINARY>(
    std::ostream&, const SerType::SERBINARY&, const CryptoContext<DCRTPoly>);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey<SerType::SERBINARY>(
    std::istream&, const SerType::SERBINARY&);

template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(
    std::ostream&, const SerType::SERBINARY&, const std::string&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(
    std::ostream&, const SerType::SERBINARY&, const CryptoContext<DCRTPoly>);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERBINARY>(
    std::istream&, const SerType::SERBINARY&);

} // namespace lbcrypto
