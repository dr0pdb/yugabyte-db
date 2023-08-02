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

#include <jwt-cpp/jwt.h>

#include <gtest/gtest.h>

#include "yb/util/jwt_util.h"
#include "yb/util/result.h"
#include "yb/util/test_macros.h"

namespace yb::util {

// RS256
const std::string PEM_RS256_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3dkN0LTLvH9wl+vL+MYX
tVsvyd4NS9oatGzPfJWTIUOii+N7SmMV383XHfysAm6M/DTqW3HOxzDF0hLIMXzq
UDjyQizGIZ37RkF4GqIcOSEYwkc2IWVnWl4WcSK+2KUlwMe3PpXdxtVZBFGdOVkw
bXrdsFiYU11kRhfTbz0pP3lmm84QEzCrP9Jueu1zqeyj/SBLUszNkgofp/DpTVPK
TVtkkqqNYBRF7HhPgR3G2F90NCfHMTjUQICFNP+HT+UO7XS35dmqBJNgAO7aIiok
rZhl3TrQUrknwlxBTF3gv1Zjru1YG6k/lTHVFcVN3pY+Lr2IiJUdppgpreklY7n8
jwIDAQAB
-----END PUBLIC KEY-----
)";
const std::string JWK_RS256 =
    "{\"kty\":\"RSA\","
    "\"e\":\"AQAB\","
    "\"kid\":\"rs256_keyid\","
    "\"alg\":\"RS256\","
    "\"n\":\"3dkN0LTLvH9wl-vL-MYXtVsvyd4NS9oatGzPfJWTIUOii-N7SmMV383XHfysAm6M_D"
        "TqW3HOxzDF0hLIMXzqUDjyQizGIZ37RkF4GqIcOSEYwkc2IWVnWl4WcSK-2KUlwMe3PpXd"
        "xtVZBFGdOVkwbXrdsFiYU11kRhfTbz0pP3lmm84QEzCrP9Jueu1zqeyj_SBLUszNkgofp_"
        "DpTVPKTVtkkqqNYBRF7HhPgR3G2F90NCfHMTjUQICFNP-HT-UO7XS35dmqBJNgAO7aIiok"
        "rZhl3TrQUrknwlxBTF3gv1Zjru1YG6k_lTHVFcVN3pY-Lr2IiJUdppgpreklY7n8jw\"}";

// RS384
const std::string PEM_RS384_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqtUV/qPEXN7a2jR/E4k9
pdqy1wiRHKyQoiybOW7Nm+JMR7qa6fq6U95YyeuC6mpDEQUpnEyqLrEP8HxBZOgw
Hkln5PwUhyAS2kcsQTf0RDGG2YBeNNA+sCb4+oM5O0NwWt0pJIoFPNIyOxRYdSZB
A3h5MvwIgQPbj4+a+YSjQsborfEywcqozHUDQ4VFadoO9tIIVaPIRqANs54BokCf
OyduP+dqlf2d3q1yukFQ2K7L27mrDtCXcWjS5CJW+oGf/CyOSj+yyaNug7sOlvU5
AwjG3l7EZ0GRFeROWl5pj6Hf054o4WI2m3xXY8S38hO6jb/NvlG0pg4ZHZEvvqCM
dQIDAQAB
-----END PUBLIC KEY-----
)";
const std::string JWK_RS384 =
    "{\"kty\":\"RSA\","
    "\"e\":\"AQAB\","
    "\"use\":\"sig\","
    "\"kid\":\"rs384_keyid\","
    "\"alg\":\"RS384\","
    "\"n\":\"qtUV_qPEXN7a2jR_E4k9pdqy1wiRHKyQoiybOW7Nm-JMR7qa6fq6U95YyeuC6mpDEQ"
        "UpnEyqLrEP8HxBZOgwHkln5PwUhyAS2kcsQTf0RDGG2YBeNNA-sCb4-oM5O0NwWt0pJIoF"
        "PNIyOxRYdSZBA3h5MvwIgQPbj4-a-YSjQsborfEywcqozHUDQ4VFadoO9tIIVaPIRqANs5"
        "4BokCfOyduP-dqlf2d3q1yukFQ2K7L27mrDtCXcWjS5CJW-oGf_CyOSj-yyaNug7sOlvU5"
        "AwjG3l7EZ0GRFeROWl5pj6Hf054o4WI2m3xXY8S38hO6jb_NvlG0pg4ZHZEvvqCMdQ\"}";

// RS512
const std::string PEM_RS512_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoF6oCRUztdPc2/jCuuD0
aKlv+baqMmymiYYwU1Gf+UZ4dNUI8gxDLHZW7tS0uYYTn85r8UJ3DeSskT41FdAZ
b1Bfi21fSqAhT169P+hB8RYIyVQNubyJsFXK1xfRp7H3tlO60C1lrv9YLNNXXxQn
hGdxAAXQeAsecEUQ/GQS1PdS22vl95cn42051pLf4/ssmReZZmRz3htlJDIumVMM
P6FJLbxvBgdODCdUappMwkI/com2Orz4sYFk8GYvsJC4o/hsE9AQU8OTm0z9Jxmy
WDu6FE/BOr9UryKwsqon/2K4ufAqU5ePvmiEv0goqInC9DU7fGFLc8shv4S3fY8w
vwIDAQAB
-----END PUBLIC KEY-----
)";
const std::string JWK_RS512 =
    "{\"kty\":\"RSA\","
    "\"e\":\"AQAB\","
    "\"use\":\"sig\","
    "\"kid\":\"rs512_keyid\","
    "\"alg\":\"RS512\","
    "\"n\":\"oF6oCRUztdPc2_jCuuD0aKlv-baqMmymiYYwU1Gf-UZ4dNUI8gxDLHZW7tS0uYYTn8"
        "5r8UJ3DeSskT41FdAZb1Bfi21fSqAhT169P-hB8RYIyVQNubyJsFXK1xfRp7H3tlO60C1l"
        "rv9YLNNXXxQnhGdxAAXQeAsecEUQ_GQS1PdS22vl95cn42051pLf4_ssmReZZmRz3htlJD"
        "IumVMMP6FJLbxvBgdODCdUappMwkI_com2Orz4sYFk8GYvsJC4o_hsE9AQU8OTm0z9Jxmy"
        "WDu6FE_BOr9UryKwsqon_2K4ufAqU5ePvmiEv0goqInC9DU7fGFLc8shv4S3fY8wvw\"}";

// PS256
const std::string PEM_PS256_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo2vAJwdvkyIICvLRvvGn
0rEsoSkQHFyPIVoELqKXNxBke8Xkn+yxe1zWx62d71h6ewIpPPHZ7K5lMZJbj+Xq
JIy+g2/7ZWujQhmE/v1JY3TNkAGNsKJupBWPqsyUzEou+ApERvj+IHASQ+zinitD
UxhFPb+1q32T1gRgzU2YWVDTa7StgPxu5cu+GuCeh5uc5FCmCYvtD2TOzWWbh8qi
ESmYTFR/4n6gQyt/v16iRJCDuR7/HUG0LlgDf78AJDQOZllPXG8Kcj1/Y1lOosUW
g0hjMIS6KqB2nQ+PiLoc9QqOklfHDy2JHrOFb5P1S6vmK75JL3kdd1EyxkgVOWAE
iQIDAQAB
-----END PUBLIC KEY-----
)";
const std::string JWK_PS256 =
    "{\"kty\":\"RSA\","
    "\"e\":\"AQAB\","
    "\"kid\":\"ps256_keyid\","
    "\"alg\":\"PS256\","
    "\"n\":\"o2vAJwdvkyIICvLRvvGn0rEsoSkQHFyPIVoELqKXNxBke8Xkn-yxe1zWx62d71h6ew"
        "IpPPHZ7K5lMZJbj-XqJIy-g2_7ZWujQhmE_v1JY3TNkAGNsKJupBWPqsyUzEou-ApERvj-"
        "IHASQ-zinitDUxhFPb-1q32T1gRgzU2YWVDTa7StgPxu5cu-GuCeh5uc5FCmCYvtD2TOzW"
        "Wbh8qiESmYTFR_4n6gQyt_v16iRJCDuR7_HUG0LlgDf78AJDQOZllPXG8Kcj1_Y1lOosUW"
        "g0hjMIS6KqB2nQ-PiLoc9QqOklfHDy2JHrOFb5P1S6vmK75JL3kdd1EyxkgVOWAEiQ\"}";

// PS384
const std::string PEM_PS384_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+an4opwpewibqEzJ3nzo
yjT6fJrXxG8cwLaUy1HYs/CfsuD3+sV/XAXxvY6x8n6P+VBNRY7XUCfL+Z4qodLa
j2rmzGw6Drjxpj+4EDqf4OsTdIe00qfYcdUvuEcuDtnKhE+oHVuGd/nFn4sFjsa7
rMpvqn9JVTe0farJ8w2oAxh8SAE3bv0WsazCSKR9d8StgqJc24RfiylP/pDm36y5
Tp/VgLxlJDuH/3/27BcNvcts7P7ZFxQ2lbJBYSsouI7n9bryLX6FXhBYZOoBwXjz
jvsjU/mpbIlI/CCoP0CJps/XRa4yIG1vQf9zKdnULje+OnCuPJa+sb43XPDzQuq+
iQIDAQAB
-----END PUBLIC KEY-----
)";
const std::string JWK_PS384 =
    "{\"kty\":\"RSA\","
    "\"e\":\"AQAB\","
    "\"use\":\"sig\","
    "\"kid\":\"ps384_keyid\","
    "\"alg\":\"PS384\","
    "\"n\":\"-an4opwpewibqEzJ3nzoyjT6fJrXxG8cwLaUy1HYs_CfsuD3-sV_XAXxvY6x8n6P-V"
        "BNRY7XUCfL-Z4qodLaj2rmzGw6Drjxpj-4EDqf4OsTdIe00qfYcdUvuEcuDtnKhE-oHVuG"
        "d_nFn4sFjsa7rMpvqn9JVTe0farJ8w2oAxh8SAE3bv0WsazCSKR9d8StgqJc24RfiylP_p"
        "Dm36y5Tp_VgLxlJDuH_3_27BcNvcts7P7ZFxQ2lbJBYSsouI7n9bryLX6FXhBYZOoBwXjz"
        "jvsjU_mpbIlI_CCoP0CJps_XRa4yIG1vQf9zKdnULje-OnCuPJa-sb43XPDzQuq-iQ\"}";

// PS512
const std::string PEM_PS512_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhcPDlRPlk7J/Ch6CcPu9
3L5TsESmYcnJbSfKhobOqpKmoQGDVB6wE+Lel5nZzB23+rPpBa0tUPeWHn0g4vJ9
vGjZQMDYvJJ3q5QPkO+KGqigNAMGQkv4tc2y6tdutuZ9q6ftlsysDuooKrtpNDMH
OhUIIVf8W9aaMrJa5PwnjoLS0eaZQVKi/uMYY7gdICjKP173GYJg733Tvv0rVTZs
RvFgj5EQRx2e8vfFxJFtXGUcAEpEViYKwWjjvwJDlDsI/zjiggAgoIQfZJxqRuyY
b5FAuIUJyd9fNM67YzidYrS3JzoBftrOWU2trO5lqpt0VE+Y98UzLslnGEXiBrcX
rQIDAQAB
-----END PUBLIC KEY-----
)";
const std::string JWK_PS512 =
    "{\"kty\":\"RSA\","
    "\"e\":\"AQAB\","
    "\"use\":\"sig\","
    "\"kid\":\"ps512_keyid\","
    "\"alg\":\"PS512\","
    "\"n\":\"hcPDlRPlk7J_Ch6CcPu93L5TsESmYcnJbSfKhobOqpKmoQGDVB6wE-Lel5nZzB23-r"
        "PpBa0tUPeWHn0g4vJ9vGjZQMDYvJJ3q5QPkO-KGqigNAMGQkv4tc2y6tdutuZ9q6ftlsys"
        "DuooKrtpNDMHOhUIIVf8W9aaMrJa5PwnjoLS0eaZQVKi_uMYY7gdICjKP173GYJg733Tvv"
        "0rVTZsRvFgj5EQRx2e8vfFxJFtXGUcAEpEViYKwWjjvwJDlDsI_zjiggAgoIQfZJxqRuyY"
        "b5FAuIUJyd9fNM67YzidYrS3JzoBftrOWU2trO5lqpt0VE-Y98UzLslnGEXiBrcXrQ\"}";

// ES256
const std::string PEM_ES256_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErOWQ2GjcxRosI46VL16zTL3Vlti3
ri0yLU6J6H0Nw+3qgvBXnN8SauSZkgGNq33Z6cHcX7DL37u6jLAB0ZFzYQ==
-----END PUBLIC KEY-----
)";
const std::string JWK_ES256 = R"(
{
  "kty": "EC",
  "d": "zapLxXUHHWO5eI1IOhzYIX0kD9WdWz4jo-tXK6h2xxs",
  "crv": "P-256",
  "kid": "es256_keyid",
  "x": "rOWQ2GjcxRosI46VL16zTL3Vlti3ri0yLU6J6H0Nw-0",
  "y": "6oLwV5zfEmrkmZIBjat92enB3F-wy9-7uoywAdGRc2E",
  "alg": "ES256"
})";

// ES384
const std::string PEM_ES384_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEptnqg7gKUWKg5+gD2b1KMV5LiufPsimw
abFRu9ENCMydclBe+/28iPpBzisy8iTzKsnRa6QVJPb8BCOjPGVTX48cOeoT6Brd
qYtzK1IiA8L7MIwngxTVLKptlizEPMDS
-----END PUBLIC KEY-----
)";
const std::string JWK_ES384 = R"(
{
  "kty": "EC",
  "d": "dKm92BVXljbysYDDd731iTdUjzMfzRpLkZ1SaGbxYIhdgG_YYkWIQXMO0NqJFcTN",
  "crv": "P-384",
  "kid": "es384_keyid",
  "x": "ptnqg7gKUWKg5-gD2b1KMV5LiufPsimwabFRu9ENCMydclBe-_28iPpBzisy8iTz",
  "y": "KsnRa6QVJPb8BCOjPGVTX48cOeoT6BrdqYtzK1IiA8L7MIwngxTVLKptlizEPMDS",
  "alg": "ES384"
})";

// ES512
const std::string PEM_ES512_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBcb2qErMKuZvR//y28LiXXKXZYbrS
pYKCn8497TlZH71md+94kxjPJgXzE695J6wxYQrNbGeNtqLeRS7DGwPnZ6kBn+U/
+utnHxnqzEihoWVuC8eoeAXFYQaJwFtc2h+BfC464coqyrspI1KaHaGNPOg9U4Az
WxeYwL+eFCCa0oJmcuM=
-----END PUBLIC KEY-----
)";
const std::string JWK_ES512 = R"(
{
    "kty": "EC",
    "d": "AHhv8WAkNgZApSn3o-xJMwbL1SD8XeUUZJrQwefFFc7K2iKVbeFq2ST0P3SwRcBJWSCv1cFAuKNWpZ82G5aqxzze",
    "crv": "P-521",
    "kid": "es512_keyid",
    "x": "AXG9qhKzCrmb0f_8tvC4l1yl2WG60qWCgp_OPe05WR-9ZnfveJMYzyYF8xOveSesMWEKzWxnjbai3kUuwxsD52ep",
    "y": "AZ_lP_rrZx8Z6sxIoaFlbgvHqHgFxWEGicBbXNofgXwuOuHKKsq7KSNSmh2hjTzoPVOAM1sXmMC_nhQgmtKCZnLj",
    "alg": "ES512"
})";

// ES256K
const std::string PEM_ES256K_PUBLIC = R"(-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEIMlyAhf2nqY1gTtVuQhHjr8sJGTR9UAl
qEyIApUNZKxG/fZx0KpagOFxYT596nzEyDZJHeGqLhN6vQn0mT9Vvw==
-----END PUBLIC KEY-----
)";
const std::string JWK_ES256K = R"(
{
  "kty": "EC",
  "d": "N8JUNzTt-alwdQjCCDzdoGMebq1OaQl7OZpsUbx0x9Y",
  "crv": "secp256k1",
  "kid": "es256k_keyid",
  "x": "IMlyAhf2nqY1gTtVuQhHjr8sJGTR9UAlqEyIApUNZKw",
  "y": "Rv32cdCqWoDhcWE-fep8xMg2SR3hqi4Ter0J9Jk_Vb8",
  "alg": "ES256K"
})";

#define TEST_JWK_TO_PEM_CONVERSION(algorithm, jwk_json, expected_pem) \
  TEST(JwtCppUtilTest, JWKToPEMConversion##algorithm) { \
    auto jwk = jwt::parse_jwk(jwk_json); \
    auto actual_pem = ASSERT_RESULT(Test_GetKeyAsPEM(jwk)); \
    ASSERT_EQ(actual_pem, expected_pem); \
  }
TEST_JWK_TO_PEM_CONVERSION(RS256, JWK_RS256, PEM_RS256_PUBLIC)
TEST_JWK_TO_PEM_CONVERSION(RS384, JWK_RS384, PEM_RS384_PUBLIC)
TEST_JWK_TO_PEM_CONVERSION(RS512, JWK_RS512, PEM_RS512_PUBLIC)
TEST_JWK_TO_PEM_CONVERSION(PS256, JWK_PS256, PEM_PS256_PUBLIC)
TEST_JWK_TO_PEM_CONVERSION(PS384, JWK_PS384, PEM_PS384_PUBLIC)
TEST_JWK_TO_PEM_CONVERSION(PS512, JWK_PS512, PEM_PS512_PUBLIC)
TEST_JWK_TO_PEM_CONVERSION(ES256, JWK_ES256, PEM_ES256_PUBLIC)
TEST_JWK_TO_PEM_CONVERSION(ES384, JWK_ES384, PEM_ES384_PUBLIC)
TEST_JWK_TO_PEM_CONVERSION(ES512, JWK_ES512, PEM_ES512_PUBLIC)
TEST_JWK_TO_PEM_CONVERSION(ES256K, JWK_ES256K, PEM_ES256K_PUBLIC)

}  // namespace yb::util
