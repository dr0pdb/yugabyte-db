// Copyright (c) YugabyteDB, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.  You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.  See the License for the specific language governing permissions and limitations
// under the License.

#pragma once

#include <jwt-cpp/jwt.h>

#include <set>
#include <string>

#include "yb/util/result.h"
#include "yb/util/status.h"
#include "yb/yql/pggate/ybc_pg_typedefs.h"

// This file contains utility wrappers & extensions over the JWT-CPP library.
//
// The library throws exceptions, hence each function that we need in our codebase has a wrapper
// which catches the exception and return a Result.
//
// Additionally, we also have functions which combine a few related functionalities into one for
// ease of use of the callers. For e.g. GetClaimAsStringsArray, GetVerifier etc.

namespace yb::util {

//--------------------------------------------------------------------------------------------------
// JWK and JWKS.

Result<jwt::jwks<jwt::traits::kazuho_picojson>> ParseJwks(const std::string& key_set);

Result<jwt::jwk<jwt::traits::kazuho_picojson>> GetJwkFromJwks(
    jwt::jwks<jwt::traits::kazuho_picojson> jwks, const std::string& key_id);

Result<std::string> GetX5cKeyValueFromJWK(jwt::jwk<jwt::traits::kazuho_picojson> jwk);

Result<std::string> GetClaimFromJwkAsString(
    jwt::jwk<jwt::traits::kazuho_picojson> jwk, const std::string& key);

Result<std::string> ConvertX5cDerToPem(const std::string& x5c);

Result<std::string> GetKeyAsPEM(const jwt::jwk<jwt::traits::kazuho_picojson> jwk);

//--------------------------------------------------------------------------------------------------
// JWT.

Result<jwt::decoded_jwt<jwt::traits::kazuho_picojson>> DecodeJwt(const std::string& token);

Result<std::string> GetKeyId(const jwt::decoded_jwt<jwt::traits::kazuho_picojson> decoded_jwt);

Result<std::string> GetIssuer(const jwt::decoded_jwt<jwt::traits::kazuho_picojson> decoded_jwt);

Result<std::set<std::string>> GetAudiences(
    const jwt::decoded_jwt<jwt::traits::kazuho_picojson> decoded_jwt);

Result<std::vector<std::string>> GetClaimAsStringsArray(
    const jwt::decoded_jwt<jwt::traits::kazuho_picojson> decoded_jwt, const std::string& name);

Result<std::string> GetAlgorithm(const jwt::decoded_jwt<jwt::traits::kazuho_picojson> decoded_jwt);

Result<jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson>> GetVerifier(
    const std::string& key_pem, const std::string& algo);

Status VerifyJwtUsingVerifier(
    const jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson>& verifier,
    const jwt::decoded_jwt<jwt::traits::kazuho_picojson> decoded_jwt);

}  // namespace yb::util
