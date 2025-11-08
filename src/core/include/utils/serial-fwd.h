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

/*
  Serialization utilities
 */

#ifndef __SERIAL_FWD_H__
#define __SERIAL_FWD_H__

#include "utils/sertype.h"

#include <iosfwd>
#include <string>

namespace lbcrypto {
namespace Serial {

/**
 * Serialize an object
 * @param obj - object to serialize
 * @param os - stream to serialize to
 * @param sertype - type of serialization; default is BINARY
 */

template <typename T>
void Serialize(const T& obj, std::ostream& os, const SerType::SERBINARY& sertype);
/**
 * Deserialize an object
 * @param obj - object to deserialize into
 * @param is - stream to deserialize from
 * @param sertype - type of de-serialization; default is BINARY
 */
template <typename T>
void Deserialize(T& obj, std::istream& is, const SerType::SERBINARY& sertype);

template <typename T>
void Serialize(const T& obj, std::ostream& os, const SerType::SERJSON&);
template <typename T>
void Deserialize(T& obj, std::istream& is, const SerType::SERJSON&);

template <typename T>
bool SerializeToFile(const std::string& filename, const T& obj, const SerType::SERBINARY&);
template <typename T>
bool DeserializeFromFile(const std::string& filename, T& obj, const SerType::SERBINARY&);

template <typename T>
bool SerializeToFile(const std::string& filename, const T& obj, const SerType::SERJSON&);
template <typename T>
bool DeserializeFromFile(const std::string& filename, T& obj, const SerType::SERJSON&);

// for JSON only
/**
 * SerializeToString - serialize the object to a JSON string and return the
 * string
 * @param t - any serializable object
 * @return JSON string
 */
template <typename T>
std::string SerializeToString(const T& t);
/**
 * DeserializeFromString - deserialize the object from a JSON string
 * @param obj - any object to deserialize into
 * @param json - JSON string
 */
template <typename T>
void DeserializeFromString(T& obj, const std::string& json);

} // namespace Serial
} // namespace lbcrypto


#endif // __SERIAL_FWD_H__
