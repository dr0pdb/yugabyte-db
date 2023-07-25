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
//

// This file contains utility wrappers over the JWT-CPP library.
//
// The library throws exceptions, hence each function that we need in our codebase has a wrapper
// which catches the exception and return a Result.
//
// The general structure of the catch blocks is such that we return as much information as possible
// in the Result. Hence, we first try to catch the exception as a std::exception and add the error
// details (e.what()) into the Result. As a fallback, we have a catch-all statement which catches
// all the exceptions and returns a generic error message.

#include "yb/util/jwt_util.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <jwt-cpp/jwt.h>

#include <string>

#include <glog/logging.h>

#include "yb/gutil/casts.h"
#include "yb/util/result.h"
#include "yb/yql/pggate/ybc_pg_typedefs.h"

namespace yb {
namespace util {

namespace {

bool DoesValueExist(
    const std::string &value, const char* const* values, int length,
    const std::string &field_name) {
  for (auto idx = 0; idx < length; idx++) {
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

Result<jwt::jwks<jwt::traits::kazuho_picojson>> ParseJwks(const std::string& key_set) {
  try {
    return jwt::parse_jwks(key_set);
  } catch (...) {
    VLOG(4) << "Could not parse JWKS: " << key_set;
    return STATUS(InvalidArgument, "Parsing JWKS failed.");
  }
}

template <typename json_traits>
Result<jwt::jwk<json_traits>> GetJwkForJwt(
    jwt::jwks<json_traits> jwks, const jwt::decoded_jwt<json_traits> decoded_jwt) {
  try {
    auto key_id = decoded_jwt.get_key_id();

    VLOG(4) << "Fetching key id: " << key_id;
    return jwks.get_jwk(decoded_jwt.get_key_id());
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Fetching JWK from JWKS failed with error: $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching JWK from JWKS failed for unknown reasons.");
  }
}

template <typename json_traits>
Result<std::string> TryGetX5cFromJWK(jwt::jwk<json_traits> jwk) {
  try {
    return jwk.get_x5c_key_value();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Fetching x5c from JWK failed with error: $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching x5c from JWK failed for unknown reasons.");
  }
}

template <typename json_traits>
Result<std::string> GetClaimFromJWKAsString(jwt::jwk<json_traits> jwk, const std::string& key) {
  try {
    // Exception will be thrown if the key does not exist or is not a string.
    return jwk.get_jwk_claim(key).as_string();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Fetching claim $0 from JWK failed with error: $1", key, e.what());
  } catch (...) {
    return STATUS_FORMAT(InvalidArgument, "Fetching claim $0 from JWK failed", key);
  }
}

Result<jwt::decoded_jwt<jwt::traits::kazuho_picojson>> DecodeJwt(const std::string& token) {
  try {
    return jwt::decode(token);
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Parsing JWT failed with error: $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Parsing JWT failed.");
  }
}

Result<jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson>> GetVerifier(
    const std::string& key_pem, const std::string& algo) {
  try {
    auto verifier = jwt::verify();

    // Algorithm names are case-sensitive.
    // Ref: https://datatracker.ietf.org/doc/html/rfc7517#section-4.4.
    //
    // We support two families of algorithms:
    // 1. RSA: RS256, RS384, RS512, PS256, PS384, PS512
    // 2. EC: ES256, ES256K, ES384, ES512
    //
    // We do not support HMAC family of algorithms such as HS256 since it falls in symmetric class
    // of algorithms and thus not safe for the users to share their keys in hba conf. This is OK
    // because almost all major IDPs use asymmetric keys for signing JWTs with RS256 being the most
    // widely used.
    // For e.g: Azure AD always uses asymmetric keys.
    if (algo == "RS256") {
      verifier.allow_algorithm(jwt::algorithm::rs256(key_pem));
    } else if (algo == "RS384") {
      verifier.allow_algorithm(jwt::algorithm::rs384(key_pem));
    } else if (algo == "RS512") {
      verifier.allow_algorithm(jwt::algorithm::rs512(key_pem));
    } else if (algo == "PS256") {
      verifier.allow_algorithm(jwt::algorithm::ps256(key_pem));
    } else if (algo == "PS384") {
      verifier.allow_algorithm(jwt::algorithm::ps384(key_pem));
    } else if (algo == "PS512") {
      verifier.allow_algorithm(jwt::algorithm::ps512(key_pem));
    } else if (algo == "ES256") {
      verifier.allow_algorithm(jwt::algorithm::es256(key_pem));
    } else if (algo == "ES384") {
      verifier.allow_algorithm(jwt::algorithm::es384(key_pem));
    } else if (algo == "ES512") {
      verifier.allow_algorithm(jwt::algorithm::es512(key_pem));
    } else if (algo == "ES256K") {
      verifier.allow_algorithm(jwt::algorithm::es256k(key_pem));
    } else {
      return STATUS_FORMAT(NotSupported, "Unsupported JWT algorithm: $.", algo);
    }

    return verifier;
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument,
        "Could not construct JWT verifier for public key: $0 and algo: $1. Error: $2", key_pem,
        algo, e.what());
  } catch (...) {
    return STATUS_FORMAT(
        InvalidArgument, "Could not construct JWT verifier for public key: $0 and algo: $1",
        key_pem, algo);
  }
}

// Convert a JWK to the PEM format.
// Supports conversion for RSA and EC family of keys.
template <typename json_traits>
Result<std::string> GetKeyAsPEM(const jwt::jwk<json_traits> jwk) {
  try {
    auto decode = [](const std::string& base64url_encoded) {
      return jwt::base::decode<jwt::alphabet::base64url>(
          jwt::base::pad<jwt::alphabet::base64url>(base64url_encoded));
    };

    std::string key_type = jwk.get_key_type();
    if (key_type == "RSA") {
      auto n = VERIFY_RESULT(GetClaimFromJWKAsString(jwk, "n"));
      auto e = VERIFY_RESULT(GetClaimFromJWKAsString(jwk, "e"));

      auto modulus = decode(n);
      auto exponent = decode(e);

      BIGNUM* bnModulus = BN_bin2bn(
          pointer_cast<const unsigned char*>(modulus.data()), narrow_cast<int>(modulus.size()),
          nullptr /* ret */);
      BIGNUM* bnExponent = BN_bin2bn(
          pointer_cast<const unsigned char*>(exponent.data()), narrow_cast<int>(exponent.size()),
          nullptr /* ret */);

      RSA* rsa_key = RSA_new();
      RSA_set0_key(rsa_key, bnModulus, bnExponent, NULL);

      EVP_PKEY* pkey = EVP_PKEY_new();
      auto res = EVP_PKEY_assign_RSA(pkey, rsa_key);
      if (res != 1) {
        return STATUS(InvalidArgument, "Failed to assign private key");
      }

      BIO* pem_bio = BIO_new(BIO_s_mem());
      if (pem_bio == nullptr) {
        return STATUS(InternalError, "Could not create pem_bio");
      }

      if (PEM_write_bio_RSA_PUBKEY(pem_bio, rsa_key) != 1) {
        return STATUS(InternalError, "Could not write RSA key into the pem_bio");
      }

      char* pem_data = nullptr;
      size_t pem_size = BIO_get_mem_data(pem_bio, &pem_data);
      std::string pem(pem_data, pem_size);

      BIO_free(pem_bio);
      EVP_PKEY_free(pkey);
      return pem;
    } else if (key_type == "EC") {
      auto x_claim = VERIFY_RESULT(GetClaimFromJWKAsString(jwk, "x"));
      auto y_claim = VERIFY_RESULT(GetClaimFromJWKAsString(jwk, "y"));
      auto curve_name = VERIFY_RESULT(GetClaimFromJWKAsString(jwk, "crv"));

      auto x_coordinate = decode(x_claim);
      auto y_coordinate = decode(y_claim);

      auto nid = EC_curve_nist2nid(curve_name.c_str());
      if (nid == NID_undef) {
        // P-256K aka secp256k1 is not included in the openssl's list of nist2nid lookup table via
        // EC_curve_nist2nid.
        //
        // It is present in the lookup table used in ossl_ec_curve_name2nid function but that is not
        // exposed publicly.
        //
        // So we set a hardcoded value as a hack. This is fine because the NIDs are public values
        // i.e. they shouldn't change between stable releases of openssl.
        if (curve_name == "P-256K" || curve_name == "secp256k1") {
          nid = NID_secp256k1;
        } else {
          return STATUS_FORMAT(
              InvalidArgument, "Could not determine the NID for curve name: $0", curve_name);
        }
      }

      EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
      if (ec_key == nullptr) {
        return STATUS_FORMAT(
            InvalidArgument, "Could not create EC_KEY with curve name $0 and nid $1.", curve_name,
            nid);
      }

      BIGNUM* x = BN_bin2bn(
          reinterpret_cast<const unsigned char*>(x_coordinate.data()),
          narrow_cast<int>(x_coordinate.size()), nullptr);
      BIGNUM* y = BN_bin2bn(
          reinterpret_cast<const unsigned char*>(y_coordinate.data()),
          narrow_cast<int>(y_coordinate.size()), nullptr);

      if (EC_KEY_set_public_key_affine_coordinates(ec_key, x, y) != 1) {
        return STATUS(InvalidArgument, "Could not set public key affine coordinates.");
      }
      EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

      BIO* pem_bio = BIO_new(BIO_s_mem());
      if (pem_bio == nullptr) {
        return STATUS(InternalError, "Could not create pem_bio.");
      }

      if (PEM_write_bio_EC_PUBKEY(pem_bio, ec_key) != 1) {
        return STATUS(InternalError, "Could not write EC key into the pem_bio.");
      }

      char* pem_data = nullptr;
      size_t pem_size = BIO_get_mem_data(pem_bio, &pem_data);
      std::string pem(pem_data, pem_size);

      BIO_free(pem_bio);
      EC_KEY_free(ec_key);
      BN_free(x);
      BN_free(y);
      return pem;
    }

    return STATUS(NotSupported, "Unsupported kty. Only RSA and EC are supported.");
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Converting JWK to PEM format failed with error $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Converting JWK to PEM format failed");
  }
}

template <typename json_traits>
Status ValidateJWT(
    const jwt::decoded_jwt<json_traits> decoded_jwt,
    const jwt::jwk<json_traits> jwk) {
  try {
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
      auto x5c = VERIFY_RESULT(TryGetX5cFromJWK(jwk));
      key_pem = jwt::helper::convert_base64_der_to_pem(x5c);
    } else {
      key_pem = VERIFY_RESULT(GetKeyAsPEM(jwk));
    }
    VLOG(4) << "Serialized pem is:\n" << key_pem << "\n";

    auto algo = decoded_jwt.get_algorithm();
    auto verifier = VERIFY_RESULT(GetVerifier(key_pem, algo));
    verifier.verify(decoded_jwt);
    return Status::OK();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "JWT validation failed with error: $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "JWT validation failed for unknown reasons.");
  }
}

template <typename json_traits>
Result<typename json_traits::string_type> GetIssuer(
    const jwt::decoded_jwt<json_traits> decoded_jwt) {
  try {
    return decoded_jwt.get_issuer();
  } catch (const std::exception& e) {
    return STATUS(InvalidArgument, "Fetching issuer from the JWT failed with error: $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching issuer from the JWT failed");
  }
}

template <typename json_traits>
Result<std::set<std::string>> GetAudiences(const jwt::decoded_jwt<json_traits> decoded_jwt) {
  try {
    return decoded_jwt.get_audience();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Fetching audience from the JWT failed with error: $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching audience from the JWT failed");
  }
}

// Returns the claim value with the given name from the decoded jwt.
// Assumes that the claim value is either a string or an array of string. In both the cases, we
// return a set<string> to the caller.
// In case the claim value isn't a string/array of string, an error is returned.
template <typename json_traits>
Result<std::set<std::string>> GetClaimAsStringsSet(
    const jwt::decoded_jwt<json_traits> decoded_jwt, const std::string& name) {
  try {
    std::set<std::string> result;
    auto claim_value = decoded_jwt.get_payload_claim(name);

    auto claim_value_type = claim_value.get_type();
    switch (claim_value_type) {
      case jwt::json::type::string: {
        result.insert(claim_value.as_string());
        break;
      }
      case jwt::json::type::array: {
        result = claim_value.as_set();
        break;
      }
      case jwt::json::type::boolean: FALLTHROUGH_INTENDED;
      case jwt::json::type::integer: FALLTHROUGH_INTENDED;
      case jwt::json::type::number: FALLTHROUGH_INTENDED;
      case jwt::json::type::object:
        return STATUS_FORMAT(
            InvalidArgument, "Claim value with name $0 was not a string or array of string.", name);
    }

    return result;
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Couldn't get claim with name $0 from the JWT. Error: $1", name, e.what());
  } catch (...) {
    return STATUS_FORMAT(InvalidArgument, "Couldn't get claim with name $0 from the JWT.", name);
  }
}

Status ValidateJWKS(const std::string& jwks) {
    RETURN_NOT_OK(ParseJwks(jwks));
    return Status::OK();
}

Status ValidateJWT(
    const std::string &token, const YBCPgJwtAuthOptions *options,
    std::set<std::string> *identity_claims) {
  LOG_IF(DFATAL, options == nullptr) << "JWT options unexpectedly NULL";

  VLOG(4) << Format(
      "Start with token = $0, jwks = $1, matching_claim_key = $2, allowed_issuers = $3, "
      "allowed_audiences = $4",
      token, options->jwks, options->matching_claim_key,
      CStringArrayToString(options->issuers, options->issuers_length),
      CStringArrayToString(options->audiences, options->audiences_length));

  auto jwks = VERIFY_RESULT(util::ParseJwks(options->jwks));
  auto decoded_jwt = VERIFY_RESULT(util::DecodeJwt(token));
  auto jwk = VERIFY_RESULT(util::GetJwkForJwt(jwks, decoded_jwt));

  // Validate for signature, expiry and issued_at.
  RETURN_NOT_OK(util::ValidateJWT(decoded_jwt, jwk));

  // Validate issuer.
  auto jwt_issuer = VERIFY_RESULT(util::GetIssuer(decoded_jwt));
  bool valid_issuer =
      DoesValueExist(jwt_issuer, options->issuers, options->issuers_length, "issuer");
  if (!valid_issuer) {
    return STATUS_FORMAT(InvalidArgument, "Invalid JWT issuer: $0", jwt_issuer);
  }

  // Validate audiences. A JWT can be issued for more than one audience and is valid as long as one
  // of the audience matches the allowed audiences in the JWT config.
  auto jwt_audience = VERIFY_RESULT(util::GetAudiences(decoded_jwt));
  bool valid_audience = false;
  for (auto jwt_aud : jwt_audience) {
    valid_audience =
        DoesValueExist(jwt_aud, options->audiences, options->audiences_length, "audience");
    if (valid_audience) {
      break;
    }
  }
  if (!valid_audience) {
    // We don't add audiences in the error message since there can be many. Also, it is very easy to
    // look up the audiences present in a JWT online.
    return STATUS_FORMAT(InvalidArgument, "Invalid JWT audience(s)");
  }

  // Get the matching claim key and return to the caller.
  auto matching_claim_key = std::string(options->matching_claim_key);
  auto matching_claim_values =
      VERIFY_RESULT(util::GetClaimAsStringsSet(decoded_jwt, matching_claim_key));
  *identity_claims = std::move(matching_claim_values);

  VLOG(1) << "JWT validation successful";
  return Status::OK();
}

}  // namespace util
}  // namespace yb
