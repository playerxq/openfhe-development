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
#ifndef __PKE_SERIAL_ANCHOR_H__
#define __PKE_SERIAL_ANCHOR_H__

#if defined(WITH_SERIALIZATION)
    // namespace lbcrypto {
    //     // void RegisterRNSSerialization();
    //     void RegisterBFVRNSSerialization();
    //     void RegisterBGVRNSSerialization();
    //     void RegisterCKKSRNSSerialization();
    // }

    // // the variables below force the linker to pull in the TUs that define the function above, along with the CEREAL_REGISTER_*.
    // [[maybe_unused]] static auto* g_force_rns_serial_anchor     = &lbcrypto::RegisterRNSSerialization;
    // [[maybe_unused]] static auto* g_force_bfvrns_serial_anchor  = &lbcrypto::RegisterBFVRNSSerialization;
    // [[maybe_unused]] static auto* g_force_bgvrns_serial_anchor  = &lbcrypto::RegisterBGVRNSSerialization;
    // [[maybe_unused]] static auto* g_force_ckksrns_serial_anchor = &lbcrypto::RegisterCKKSRNSSerialization;

    // Force dynamic init modules, so the linker pulls in the trnslation units that contain
    // CEREAL_REGISTER_DYNAMIC_INIT(...) for each of these.
    CEREAL_FORCE_DYNAMIC_INIT(rns_ser)
    CEREAL_FORCE_DYNAMIC_INIT(bfvrns_ser)
    CEREAL_FORCE_DYNAMIC_INIT(bgvrns_ser)
    CEREAL_FORCE_DYNAMIC_INIT(ckksrns_ser)
    CEREAL_FORCE_DYNAMIC_INIT(ciphertext_ser)
    CEREAL_FORCE_DYNAMIC_INIT(key_ser)
    CEREAL_FORCE_DYNAMIC_INIT(metadata_ser)
    CEREAL_FORCE_DYNAMIC_INIT(base_ser)
#endif

#endif // __PKE_SERIAL_ANCHOR_H__

