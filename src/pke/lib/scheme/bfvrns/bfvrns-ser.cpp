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

#include "config_core.h"
#ifdef WITH_SERIALIZATION
#pragma message("WITH_SERIALIZATION is defined")
#else
#pragma message("WITH_SERIALIZATION is NOT defined")
#endif
#if defined(WITH_SERIALIZATION)
// namespace lbcrypto {
// // function used as a link anchor to force this TU in when another file references it
// void RegisterBFVRNSSerialization() {}
// }

#include "scheme/bfvrns/bfvrns-scheme.h"
#include "utils/serial-cereal-headers.h"

CEREAL_REGISTER_TYPE(lbcrypto::CryptoParametersBFVRNS);
CEREAL_REGISTER_TYPE(lbcrypto::SchemeBFVRNS);
CEREAL_REGISTER_TYPE(lbcrypto::FHEBFVRNS);

CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::CryptoParametersRNS, lbcrypto::CryptoParametersBFVRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::FHERNS, lbcrypto::FHEBFVRNS);

CEREAL_REGISTER_DYNAMIC_INIT(bfvrns_ser)

#endif  // WITH_SERIALIZATION
