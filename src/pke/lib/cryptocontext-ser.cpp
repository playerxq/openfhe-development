//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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

#include "cryptocontext-ser.h"
#include "cryptocontext.h"
#include "utils/serial.h"
#include "utils/sertype.h"

#include <cereal/archives/json.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/memory.hpp>
#include <fstream>
#include <sstream>

// clang-format off
namespace lbcrypto {
namespace Serial {
// ================================= JSON serialization/deserialization
template <typename T>
void Deserialize(CryptoContext<T>& obj, std::istream& stream, const SerType::SERJSON&) {
    CryptoContext<T> newob;

    cereal::JSONInputArchive archive(stream);
    archive(newob);

    obj = CryptoContextFactory<T>::GetContext(newob->GetCryptoParameters(), newob->GetScheme(), newob->getSchemeId());
}

template <typename T>
bool DeserializeFromFile(const std::string& filename, CryptoContext<T>& obj, const SerType::SERJSON& sertype) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        Serial::Deserialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

template <typename T>
void DeserializeFromString(CryptoContext<T>& obj, const std::string& json) {
    std::stringstream s;
    s << json;
    Serial::Deserialize(obj, s, SerType::JSON);
}

// ================================= BINARY serialization/deserialization
template <typename T>
void Deserialize(CryptoContext<T>& obj, std::istream& stream, const SerType::SERBINARY&) {
    CryptoContext<T> newob;

    cereal::PortableBinaryInputArchive archive(stream);
    archive(newob);

    obj = CryptoContextFactory<T>::GetContext(newob->GetCryptoParameters(), newob->GetScheme(), newob->getSchemeId());
}

template <typename T>
bool DeserializeFromFile(const std::string& filename, CryptoContext<T>& obj, const SerType::SERBINARY& sertype) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        Serial::Deserialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

// Explicit instantiations for CryptoContext<DCRTPoly>
template void Deserialize<DCRTPoly>(CryptoContext<DCRTPoly>& obj, std::istream& stream, const SerType::SERJSON&);
template bool DeserializeFromFile<DCRTPoly>(const std::string& filename, CryptoContext<DCRTPoly>& obj, const SerType::SERJSON&);
template void DeserializeFromString<DCRTPoly>(CryptoContext<DCRTPoly>& obj, const std::string& json);

template void Deserialize<DCRTPoly>(CryptoContext<DCRTPoly>& obj, std::istream& stream, const SerType::SERBINARY&);
template bool DeserializeFromFile<DCRTPoly>(const std::string& filename, CryptoContext<DCRTPoly>& obj, const SerType::SERBINARY&);

}  // namespace Serial
}  // namespace lbcrypto
// clang-format on
