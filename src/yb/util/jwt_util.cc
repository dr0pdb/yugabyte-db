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

#include "yb/util/jwt_util.h"

#include <jwt-cpp/jwt.h>

#include <string>

#include <glog/logging.h>

#include "yb/gutil/casts.h"
#include "yb/util/jwtcpp_util.h"
#include "yb/util/result.h"
#include "yb/yql/pggate/ybc_pg_typedefs.h"

using jwt::decoded_jwt;
using jwt::json::type;
using jwt::jwk;
using jwt::jwks;
using jwt::traits::kazuho_picojson;

namespace yb::util {

namespace {

bool DoesValueExist(
    const std::string& value, char* const* values, int length, const std::string& field_name) {
  for (auto idx = 0; idx < length; ++idx) {
    LOG_IF(DFATAL, values[idx] == nullptr)
        << "JWT " << field_name << " unexpectedly NULL for idx " << idx;

    const std::string valueToCompare(values[idx]);
    if (valueToCompare == value) {
      return true;
    }

    VLOG(4) << Format("Mismatch, expected = $0, actual = $1", valueToCompare, value);
  }
  return false;
}

}  // namespace

Status ValidateDecodedJWT(
    const decoded_jwt<kazuho_picojson> decoded_jwt, const jwk<kazuho_picojson> jwk) {
  // To verify the JWT, the library expects the key to be provided in the PEM format (see
  // GetVerifier). Ref: https://github.com/Thalhammer/jwt-cpp/issues/271.
  //
  // The x5c (X.509 Certificate Chain) is an *optional* claim that contains the PEM representation
  // of the X509 certificate. The first certificate of the chain must match the public part of the
  // key used to sign the JWT. Ref: https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
  //
  // Therefor, the easiest way to get the key in PEM format is to extract it out from the x5c
  // claim whenever it is available. So try to get it from the x5c field, else calculate using
  // other JWK fields using openssl.
  std::string key_pem;
  if (jwk.has_x5c()) {
    auto x5c = VERIFY_RESULT(GetX5cKeyValueFromJWK(jwk));
    key_pem = VERIFY_RESULT(ConvertX5cDerToPem(x5c));
  } else {
    key_pem = VERIFY_RESULT(GetKeyAsPEM(jwk));
  }
  VLOG(4) << "Serialized pem is:\n" << key_pem << "\n";

  auto algo = VERIFY_RESULT(GetAlgorithm(decoded_jwt));
  auto verifier = VERIFY_RESULT(GetVerifier(key_pem, algo));
  return VerifyJwtUsingVerifier(verifier, decoded_jwt);
}

Status ValidateJWT(
    const std::string& token, const YBCPgJwtAuthOptions* options,
    std::vector<std::string>* identity_claims) {
  LOG_IF(DFATAL, options == nullptr) << "JWT options unexpectedly NULL";

  VLOG(4) << Format(
      "Start with token = $0, jwks = $1, matching_claim_key = $2, allowed_issuers = $3, "
      "allowed_audiences = $4",
      token, options->jwks, options->matching_claim_key,
      CStringArrayToString(options->allowed_issuers, options->allowed_issuers_length),
      CStringArrayToString(options->allowed_audiences, options->allowed_audiences_length));

  auto jwks = VERIFY_RESULT(ParseJwks(options->jwks));
  auto decoded_jwt = VERIFY_RESULT(DecodeJwt(token));

  auto key_id = VERIFY_RESULT(GetKeyId(decoded_jwt));
  auto jwk = VERIFY_RESULT(GetJwkFromJwks(jwks, key_id));

  // Validate for signature, expiry and issued_at.
  RETURN_NOT_OK(ValidateDecodedJWT(decoded_jwt, jwk));

  // Validate issuer.
  auto jwt_issuer = VERIFY_RESULT(GetIssuer(decoded_jwt));
  bool valid_issuer = DoesValueExist(
      jwt_issuer, options->allowed_issuers, options->allowed_issuers_length, "issuer");
  if (!valid_issuer) {
    return STATUS_FORMAT(InvalidArgument, "Invalid JWT issuer: $0", jwt_issuer);
  }

  // Validate audiences. A JWT can be issued for more than one audience and is valid as long as one
  // of the audience matches the allowed audiences in the JWT config.
  auto jwt_audiences = VERIFY_RESULT(GetAudiences(decoded_jwt));
  bool valid_audience = false;
  for (const auto& audience : jwt_audiences) {
    valid_audience = DoesValueExist(
        audience, options->allowed_audiences, options->allowed_audiences_length, "audience");
    if (valid_audience) {
      break;
    }
  }
  if (!valid_audience) {
    // We don't add audiences in the error message since there can be many. Also, it is very easy to
    // look up the audiences present in a JWT online.
    return STATUS(InvalidArgument, "Invalid JWT audience(s)");
  }

  // Get the matching claim key and return to the caller.
  auto matching_claim_key = std::string(options->matching_claim_key);
  *identity_claims = VERIFY_RESULT(GetClaimAsStringsArray(decoded_jwt, matching_claim_key));

  VLOG(1) << "JWT validation successful";
  return Status::OK();
}

}  // namespace yb::util
