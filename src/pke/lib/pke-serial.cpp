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

#include <cereal/types/polymorphic.hpp>

#include "utils/serial-templates-impl.h"
#include "utils/serial-instantiator.h"

#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "scheme/bfvrns/bfvrns-scheme.h"
#include "scheme/bfvrns/bfvrns-fhe.h"

#include "scheme/bgvrns/bgvrns-cryptoparameters.h"
#include "scheme/bgvrns/bgvrns-scheme.h"
#include "scheme/bgvrns/bgvrns-fhe.h"

#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-scheme.h"
#include "scheme/ckksrns/ckksrns-fhe.h"

#include "scheme/ckksrns/ckksrns-schemeswitching.h"

#include "key/evalkeyrelin.h"

#include "ciphertext.h"
#include "cryptocontext.h"
// #include "binfhecontext.h"

// clang-format off

namespace lbcrypto {
    template class CryptoContextImpl<DCRTPoly>;
    template class PublicKeyImpl<DCRTPoly>;
    template class PrivateKeyImpl<DCRTPoly>;
    template class CiphertextImpl<DCRTPoly>;
} // namespace lbcrypto

CEREAL_REGISTER_TYPE(lbcrypto::CryptoParametersBase<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::CryptoParametersRLWE<lbcrypto::DCRTPoly>);
// CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::Serializable, lbcrypto::CryptoParametersBase<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::CryptoParametersBase<lbcrypto::DCRTPoly>, lbcrypto::CryptoParametersRLWE<lbcrypto::DCRTPoly>);

CEREAL_REGISTER_TYPE(lbcrypto::SchemeBase<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::FHEBase<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::FHEBase<lbcrypto::DCRTPoly>, lbcrypto::FHERNS);

CEREAL_REGISTER_TYPE(lbcrypto::CryptoParametersRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::CryptoParametersRLWE<lbcrypto::DCRTPoly>, lbcrypto::CryptoParametersRNS);
CEREAL_REGISTER_TYPE(lbcrypto::SchemeRNS);
CEREAL_REGISTER_TYPE(lbcrypto::FHERNS);

CEREAL_REGISTER_TYPE(lbcrypto::CryptoParametersBFVRNS);
CEREAL_REGISTER_TYPE(lbcrypto::SchemeBFVRNS);
CEREAL_REGISTER_TYPE(lbcrypto::FHEBFVRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::CryptoParametersRNS, lbcrypto::CryptoParametersBFVRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::FHERNS, lbcrypto::FHEBFVRNS);

CEREAL_REGISTER_TYPE(lbcrypto::CryptoParametersBGVRNS);
CEREAL_REGISTER_TYPE(lbcrypto::SchemeBGVRNS);
CEREAL_REGISTER_TYPE(lbcrypto::FHEBGVRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::CryptoParametersRNS, lbcrypto::CryptoParametersBGVRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::FHERNS, lbcrypto::FHEBGVRNS);

CEREAL_REGISTER_TYPE(lbcrypto::CryptoParametersCKKSRNS);
CEREAL_REGISTER_TYPE(lbcrypto::SchemeCKKSRNS);
CEREAL_REGISTER_TYPE(lbcrypto::FHECKKSRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::CryptoParametersRNS, lbcrypto::CryptoParametersCKKSRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::FHERNS, lbcrypto::FHECKKSRNS);

CEREAL_REGISTER_TYPE(lbcrypto::CKKSBootstrapPrecom);

CEREAL_REGISTER_TYPE(lbcrypto::SWITCHCKKSRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::FHERNS, lbcrypto::SWITCHCKKSRNS);

CEREAL_REGISTER_TYPE(lbcrypto::Metadata);

CEREAL_REGISTER_TYPE(lbcrypto::EvalKeyImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::EvalKeyRelinImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::EvalKeyImpl<lbcrypto::DCRTPoly>, lbcrypto::EvalKeyRelinImpl<lbcrypto::DCRTPoly>);

INSTANTIATE_SERIAL_FOR(std::map<std::string, std::vector<lbcrypto::EvalKey<lbcrypto::DCRTPoly>>>)
INSTANTIATE_SERIAL_FOR(std::map<std::string, std::shared_ptr<std::map<uint32_t, lbcrypto::EvalKey<lbcrypto::DCRTPoly>>>>)

// The RNS bases and concrete scheme classes
INSTANTIATE_SERIAL_FOR(lbcrypto::CryptoParametersRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::FHERNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::CryptoParametersBFVRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::SchemeBFVRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::FHEBFVRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::CryptoParametersBGVRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::SchemeBGVRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::FHEBGVRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::CryptoParametersCKKSRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::SchemeCKKSRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::FHECKKSRNS)
INSTANTIATE_SERIAL_FOR(lbcrypto::SWITCHCKKSRNS)

// INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>>)

// INSTANTIATE_SERIAL_FOR(lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>)
INSTANTIATE_SERIAL_FOR(lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>)
INSTANTIATE_SERIAL_FOR(lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>)
INSTANTIATE_SERIAL_FOR(lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>)

INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>>)
// // CryptoContextImpl functions must be instantiated separately as they are overloads to
// // the generic serializers/deserializer 
// namespace lbcrypto {
// namespace Serial {

// // JSON
// template void Serialize<std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(const std::shared_ptr<CryptoContextImpl<DCRTPoly>>&,
//                                   std::ostream&,
//                                   const SerType::SERJSON&);
// template void Deserialize<std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(std::shared_ptr<CryptoContextImpl<DCRTPoly>>&,
//                                     std::istream&,
//                                     const SerType::SERJSON&);
// template bool SerializeToFile<std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(const std::string&,
//                                         const std::shared_ptr<CryptoContextImpl<DCRTPoly>>&,
//                                         const SerType::SERJSON&);
// template bool DeserializeFromFile<std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(const std::string&,
//                                             std::shared_ptr<CryptoContextImpl<DCRTPoly>>&,
//                                             const SerType::SERJSON&);
// // BINARY
// template void Serialize<std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(const std::shared_ptr<CryptoContextImpl<DCRTPoly>>&,
//                                   std::ostream&,
//                                   const SerType::SERBINARY&);
// template void Deserialize<std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(std::shared_ptr<CryptoContextImpl<DCRTPoly>>&,
//                                     std::istream&,
//                                     const SerType::SERBINARY&);
// template bool SerializeToFile<std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(const std::string&,
//                                         const std::shared_ptr<CryptoContextImpl<DCRTPoly>>&,
//                                         const SerType::SERBINARY&);
// template bool DeserializeFromFile<std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(const std::string&,
//                                             std::shared_ptr<CryptoContextImpl<DCRTPoly>>&,
//                                             const SerType::SERBINARY&);
// }
// }

namespace lbcrypto {
// JSON
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERJSON>(std::ostream& ser,
                                                                                  const SerType::SERJSON&,
                                                                                  const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERJSON>(std::ostream& ser,
                                                                                  const SerType::SERJSON&,
                                                                                  const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERJSON>(std::istream& ser,
                                                                                    const SerType::SERJSON&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERJSON>(std::ostream& ser,
                                                                                 const SerType::SERJSON&,
                                                                                 const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERJSON>(std::ostream& ser,
                                                                                 const SerType::SERJSON&,
                                                                                 const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey<SerType::SERJSON>(std::istream& ser,
                                                                                   const SerType::SERJSON&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERJSON>(std::ostream& ser,
                                                                                          const SerType::SERJSON&,
                                                                                          const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERJSON>(std::ostream& ser,
                                                                                          const SerType::SERJSON&,
                                                                                          const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERJSON>(std::istream& ser,
                                                                                            const SerType::SERJSON&);
// BINARY
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                    const SerType::SERBINARY&,
                                                                                    const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                    const SerType::SERBINARY&,
                                                                                    const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERBINARY>(std::istream& ser,
                                                                                      const SerType::SERBINARY&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                   const SerType::SERBINARY&,
                                                                                   const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                   const SerType::SERBINARY&,
                                                                                   const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey<SerType::SERBINARY>(std::istream& ser,
                                                                                     const SerType::SERBINARY&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                            const SerType::SERBINARY&,
                                                                                            const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                            const SerType::SERBINARY&,
                                                                                            const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERBINARY>(std::istream& ser,
                                                                                              const SerType::SERBINARY&);

}  // namespace lbcrypto

// clang-format on
