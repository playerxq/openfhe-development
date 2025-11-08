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

/*
  Serialization utilities
 */

#ifndef __SERIAL_TEMPLATES_IMPL_H__
#define __SERIAL_TEMPLATES_IMPL_H__

#include "utils/serial-cereal-headers.h"
#include "utils/serial-fwd.h"

#include <fstream>
#include <sstream>
#include <string>


namespace lbcrypto {

namespace Serial {
//========================== BINARY serialization ==========================
template <typename T>
void Serialize(const T& obj, std::ostream& stream, const SerType::SERBINARY& st) {
    cereal::PortableBinaryOutputArchive archive(stream);
    archive(obj);
}
template <typename T>
void Deserialize(T& obj, std::istream& stream, const SerType::SERBINARY& st) {
    cereal::PortableBinaryInputArchive archive(stream);
    archive(obj);
}

template <typename T>
bool SerializeToFile(const std::string& filename, const T& obj, const SerType::SERBINARY& sertype) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        Serial::Serialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}
template <typename T>
bool DeserializeFromFile(const std::string& filename, T& obj, const SerType::SERBINARY& sertype) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        Serial::Deserialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

//========================== JSON serialization ==========================
template <typename T>
void Serialize(const T& obj, std::ostream& stream, const SerType::SERJSON& ser) {
    cereal::JSONOutputArchive archive(stream);
    archive(obj);
}
template <typename T>
void Deserialize(T& obj, std::istream& stream, const SerType::SERJSON& ser) {
    cereal::JSONInputArchive archive(stream);
    archive(obj);
}

template <typename T>
bool SerializeToFile(const std::string& filename, const T& obj, const SerType::SERJSON& sertype) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        Serial::Serialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}
template <typename T>
bool DeserializeFromFile(const std::string& filename, T& obj, const SerType::SERJSON& sertype) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        Serial::Deserialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

template <typename T>
std::string SerializeToString(const T& t) {
    std::stringstream s;
    Serialize(t, s, SerType::JSON);
    return s.str();
}
template <typename T>
void DeserializeFromString(T& obj, const std::string& json) {
    std::stringstream s;
    s << json;
    Serial::Deserialize(obj, s, SerType::JSON);
}

}  // namespace Serial

} // namespace lbcrypto

#endif // __SERIAL_TEMPLATES_IMPL_H__
