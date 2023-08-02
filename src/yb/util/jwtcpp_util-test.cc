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

#include "yb/util/jwtcpp_util.h"
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
const std::string PEM_RS256_PRIVATE = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3dkN0LTLvH9wl+vL+MYXtVsvyd4NS9oatGzPfJWTIUOii+N7
SmMV383XHfysAm6M/DTqW3HOxzDF0hLIMXzqUDjyQizGIZ37RkF4GqIcOSEYwkc2
IWVnWl4WcSK+2KUlwMe3PpXdxtVZBFGdOVkwbXrdsFiYU11kRhfTbz0pP3lmm84Q
EzCrP9Jueu1zqeyj/SBLUszNkgofp/DpTVPKTVtkkqqNYBRF7HhPgR3G2F90NCfH
MTjUQICFNP+HT+UO7XS35dmqBJNgAO7aIiokrZhl3TrQUrknwlxBTF3gv1Zjru1Y
G6k/lTHVFcVN3pY+Lr2IiJUdppgpreklY7n8jwIDAQABAoIBAAOkcKmgjkfF/98+
q9alyfXcTWiPEMDSD+YucymkewnsxlptnbSW8+D8zC9d2qUfk4kAhWiC8dYrYtQU
It1NI7u1c6TKf2ZF5b49jO9DAhueA34NFUJvG8dMDCpHW8LK01fa75NDeqStFA0S
Gfa7FCR4A/PFQJr9yYutEHefFXJJUCadeSdSpJ6MBhYy/wKAhr6Ua8vQbOfQZNg7
Xh3bt7Km5xj1R/lghcVc4e7vx4NbELItnO8QbzHSxFb8Xs+r8K5qp/gHYDj/dPEE
NDYqBd/aODDxYtjg9G4lZOtM5H0mpi2TNzlXyfTiRW7kWiBIVuCqI32bKcM+18Tq
F9zLqqECgYEA76HG5qqoW8QrVE8yVvIbg56O293jnTV4vbhN88D7YV72wdNQQkDL
UNN5sbmuoY2LQDg1bVk68IoJNmu0heF0iZmOJYR++iQzWuUS3I7a+xtSp3Qd2qhU
i1opGhxNCuaopKOw5ttK6PKiQm1a/PUCbWn8wDSVDjV5O7y8xeq6QmMCgYEA7QBN
o/wXEz6XuYXh19dVHMZ/vXAZjZGNa03NOcbppUZHq1h7YVR144TansYTM8Xu1myl
egoa2pxN3wYH9gBXsX7iMpL/RD+eXnQXp1yIQOrBc21/CCkDOplAsusdQdnV4EyR
5yA/GZFgY7/IShmGsR/fMvnpXs8xPuRbxZDnHuUCgYEAh31CF+QAIzqsgRPyU4S6
l9XL0ncIHjhAl4ygzqSbvbdS786J/5vhGUco9JsXKRL93Aar9rLQB3cUtGd7f4M1
QCPJYl8i6E4Vl1wUKQ7As+AEANg/lQU+IDiPKss7qGE4kzZWbIErPsEJi2OHYaUq
hTC7DvXsHUeQz3zsgz8vpx8CgYB+h9PrwdHb/2XnsZfCsX8KTtuyGuA5mcTjzfTM
bOsexufKjgHJE9ugrbQ+YkesM3dw2S57elud7ScR89laOBKZe8Ft+Nb56/E0QkzC
mH9SEUNYydOxWpwTs/A71ZSYLKGoD5kxySCHGPtaJfDbxscHV5nFUHGMoZeMGUT5
tIQAFQKBgG/VVVqcFoR/1vVjaABXPtn2kFhv20yXI8fLykMboFpuU5jGRSDoTpiU
C84GN3/pSwLdNAC9wzuvt9sFW1/oQt8i9oM0d6jGYDxGtaPNhLiVl71zCfra+GZD
UwkSSNPJlcIiN84obfQ5Doem2uak0+GqpKBForup7/dz52o5X0i/
-----END RSA PRIVATE KEY-----
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
const std::string PEM_RS384_PRIVATE = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAqtUV/qPEXN7a2jR/E4k9pdqy1wiRHKyQoiybOW7Nm+JMR7qa
6fq6U95YyeuC6mpDEQUpnEyqLrEP8HxBZOgwHkln5PwUhyAS2kcsQTf0RDGG2YBe
NNA+sCb4+oM5O0NwWt0pJIoFPNIyOxRYdSZBA3h5MvwIgQPbj4+a+YSjQsborfEy
wcqozHUDQ4VFadoO9tIIVaPIRqANs54BokCfOyduP+dqlf2d3q1yukFQ2K7L27mr
DtCXcWjS5CJW+oGf/CyOSj+yyaNug7sOlvU5AwjG3l7EZ0GRFeROWl5pj6Hf054o
4WI2m3xXY8S38hO6jb/NvlG0pg4ZHZEvvqCMdQIDAQABAoIBAQCT8X3ezIzdsNHv
bs8uaAhPfhqrRuwE3R1UlTTIhEDj4xMUe3J1d4Gt6D0UgTUbNXNnZgUnKu2nCgg3
yCQJ81rYn9Gt6PEOJKSvDDwzLvYHqKyT6CutqTrg6p9ss//4ZusChc1/q1fl2FNP
/sqsibh7/PVZRhNHR8P5i/A2brvEs3VjXKGw0eOJjUn6dA6mzqs06qsgjqhNI323
iND/PD57ZG5lSIOZM/NhmuJ89XixNUro3RJGzLE6owHa9p6RWh9Gzrl9FxPlzzSi
kmQyVAoCCKUZ99eYTEMQ5R5ZOwNjs821TyOKjQfdJnTrrp7GzQNoY7XwXX+IamuS
+jtMDVlxAoGBAPxh/ulHnhs6rzb3AR1a4y1NKXX+a3b2N1+KsgxG/sDBaesgQcro
5fkA1YVHv95elZu/gB9uHgXly/Rly+NL7TAor7I8nGd+GQTEIbbZ0irXU7OPIQWY
v8Z2UnDd8DJv5T6uoKoN8ri1EojVrVj5uC1CcVBbiVxeI4y+HEvuG7SnAoGBAK1H
4LouEvxVKlS8GQRpjEwmOyVVY8Jd+j/fY3eaPKELLtOsj6Ban63c0qinPjb2PMjY
Z4nqD8GO/E9R+E0SZ2aaNoMNXVu6O7hi2UWH8pe29nIub7Jt2xpdSDh2RaLATCqa
QqWpvM8+A/e3stQ82LfnRFJRpSUkDsJLZ1R6OG2DAoGBALAq7zaCyTgUhI2HaP3G
nWDXxaMZToYhY5GLTLEJNXXzDC4VvBcY7r4a+PApnyJnP2MSDyrhQI+5Ud5s2B72
tr+xBsMRT9Nlz6zmAuqRrQQ+fayOsewoLWUo3m7uXGW4eXqBhqBtUAniSue8z12W
Ihtlj5cZ7g3NoF7zrOjLcgdtAoGBAKXmEDEQFZtCipGvuJ/x0aHCZJQcybL4OLRY
UqnaoDtrMnz0VFopCYHyzjksTbNfUtjT32U6E7W0CLqEdx6LBTZFZPVZoU1F4xFo
ii44tzkrsY2mCcihxsjaEGAGVCs6wnFzWWW0OZGNBU1wsaTjUHXZ1B6gDmWdvQem
G5rUnRuzAoGAeUEHuDJ4lWBfFKg5xcj1pD2k5cuOi2SEROWd74B+tSd6+zKTTOmA
aZvRTtyYq9wwYaVFMcbDpufgbstu+xToBRDpSRWeYW5iqiHqBemcOwP4PgBZeDa5
nPLvydzhsXY5r8SHFuFexphbOMAMypC5Bg4DZTfrLJu0D3XnH0vT7Nw=
-----END RSA PRIVATE KEY-----
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
const std::string PEM_RS512_PRIVATE = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAoF6oCRUztdPc2/jCuuD0aKlv+baqMmymiYYwU1Gf+UZ4dNUI
8gxDLHZW7tS0uYYTn85r8UJ3DeSskT41FdAZb1Bfi21fSqAhT169P+hB8RYIyVQN
ubyJsFXK1xfRp7H3tlO60C1lrv9YLNNXXxQnhGdxAAXQeAsecEUQ/GQS1PdS22vl
95cn42051pLf4/ssmReZZmRz3htlJDIumVMMP6FJLbxvBgdODCdUappMwkI/com2
Orz4sYFk8GYvsJC4o/hsE9AQU8OTm0z9JxmyWDu6FE/BOr9UryKwsqon/2K4ufAq
U5ePvmiEv0goqInC9DU7fGFLc8shv4S3fY8wvwIDAQABAoIBAQCT8t+ZCYtcKumt
slCMMa6pw+8+9AsOW/hEFZ0NsNciFKZaOpN3ImLyaPaIfYmBQrVmD/y7ZfMJyTZ/
BGHbDtH4RLDwo2VvJk20uJVlmPME5KwUeMv014A7QtrQFvRffismdRZ6qfcOPBnv
uMX5PFG8r+Wq/LI3nSJmtwEVp4lMGKqKUypCH0Fyq++9fh+lHaaAH+W6ZYoOHjw4
NadPlk13A3I9Iq6zA9QhrUtNdGoXDUlg2yltQG2fd2lPT4gz6Xlv2naL83JmRluO
EZWsq8C7y5w0/hNIarf+7BrXiIDdsnAzhlVh+7Ix4+Ojx6EnLPAh6I5lGYIhmul8
0E8mT9hRAoGBAOevjpDOGI3omAJR49fRf9B2VI/VLcJb5pO5Ah6PNK/TaiOG0k6J
DpasseITvXnwcYdrPmZBkA35i4QUwnDxn+97/nOovfejWKt40FXWBPBClumE4rfz
dHkAUEGGIaLlIQGOGn+h9WT5KMhYoAPGrNRuheubyrGTNs6sT41E5y3XAoGBALEz
IbC3LvWQf9rfpW2M+WC5/rfWt0CkCBZTzZu9Uk4faa9EczmCSqeXEoQkAwewcuA8
N/T7+Y6ugWgfb/Az8ZsP3iIsbCaYX3vad8s72oL9SItfOBdqB3yxDY+Lonx2zhyC
20XtuVXjcTWll4M+ucUp8N9AMx5+fcKqs54U36dZAoGBAMOmzY4bfUDZmwTagr5O
fNFeHCsaq3nmgeFd6xxDcwrITmmSASexNlCnpdB1Ox0un7DsL9XKqAwlIFx563nV
kmp7G3Ywmbv2hXrIm6bhBWqf0TGCtrMBNOq6CQxMaTtWo3jcuCPwcXrDrl0B+p81
t93tN8qv1Yv/9diySrvR5CghAoGAQdDyFIcVpBQVySAEe9o+zhSHbZUM36+NaW2b
EtuQ9H9qa7UK7zNbsz/Dmt0dWv/Iy0zSo+XrXXmnixsSIq/Ib4XHRf4l9XfnD0On
9w62LK0TAuFNHjU9rqy8krKUmZIvIBvigei4TBR8eiaVTiRAL+FSHDnmQs9Mur9Y
k8DBCZECgYEAhlzn7sM3cuzD20UWRp6OzB2nxsekXDnv94uyQRb1x4k07Z3+YgPH
HIYu8ckjcnNX8+FdAbDR3P16Kisx9DMeswoecXp3IMgSS00Z+MNWkvNiaEtaW54Z
1jiuIyS4aNVodleE1P94FutrAtjwf40eeEcF+uOAqfLLLfXNiKmhuGQ=
-----END RSA PRIVATE KEY-----
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
const std::string PEM_PS256_PRIVATE = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAo2vAJwdvkyIICvLRvvGn0rEsoSkQHFyPIVoELqKXNxBke8Xk
n+yxe1zWx62d71h6ewIpPPHZ7K5lMZJbj+XqJIy+g2/7ZWujQhmE/v1JY3TNkAGN
sKJupBWPqsyUzEou+ApERvj+IHASQ+zinitDUxhFPb+1q32T1gRgzU2YWVDTa7St
gPxu5cu+GuCeh5uc5FCmCYvtD2TOzWWbh8qiESmYTFR/4n6gQyt/v16iRJCDuR7/
HUG0LlgDf78AJDQOZllPXG8Kcj1/Y1lOosUWg0hjMIS6KqB2nQ+PiLoc9QqOklfH
Dy2JHrOFb5P1S6vmK75JL3kdd1EyxkgVOWAEiQIDAQABAoIBAQCJ6glD5taWiQXY
l4vDZRWIjdVoPMtH5CU2tE0LPlP3OHJUsnF7NbmirnrkEPVUZIsY/H3o3QJY5+Sm
rSlwi0vKhKzTJ9I1iV1CD19aAk/JC23fti/pfWt6NmgEcJqyvXheA+wTKVbt8Sa5
BFVLvp8WpUjqD7w1eckluJQpLu7/kAfhDbbM0rj6srrywfqZ+mRgfxiQ/N0O6CN2
Hnsi7gBVw9cEfKIhJzesaCEc6jYTFzhbWN2cvCFfT8aJ8u0N+J9ARwnMk7jqQ6pI
AnSe/ALG9MbhAWeVbJMDyLvH1qvL8dwcz6cXBDnjLgnI+D0wLjqUiR56cKTqP9V8
1PM2NozBAoGBAOCEtMHn0dMTWGgS8Kc5Q3kCAdE3hdVok6lawLvXJ7itCHn5sBqu
gZu+WLJilRib8p8MqaMQzTICuWsgjTuQrtPiXzYNN6NKsguax2UPTUBJoelenHXO
pa5yoAtLvtH4Nan8OFcC3/TqCrKfpNyM5CZ6TG6SuCWF5oeasYNsGf3NAoGBALpV
5OiIG4ePhZ7qa8Qmkg+nHpicYXO08CDreqxl9k3tCxUjW5WN/+bvNWwCJLUy4IeN
Z2nomlxihziplDIRHXL7CHma6kh8OjVHr+cpmWn5xv9R3BTuOZS/1I1c+1mjlYR7
2hB2vv6cfTellPoCXGOSGeCrKYEfQU73CGDCxIWtAoGAZsq7S0/MlBv2TOfnAFjK
WHufw17tSlCv0ki3lwihqf6ms9mqU/zzYA/c4gcahgLYKROOExddKvluVOq5Xr0W
HfI1bzTL9Vn8fC2n/s/rqXRMyeDEN3eeCWl3dtR+D/nY7/OHA+dQC/yfWzqWK1fi
GO/DUJih8KQGcK1Vensixz0CgYBmlIjLVrrJG0L1ZJplRtKcGWWnoFep6k9T4C8N
n6hD6B50yZ1OrPjXOpNPXbK1qkefeEIZNPtdpsRIdlrmYTO0K+zTfWxC8VjeIhP9
j5IsnFxoDLm7MBa1BBJQrIKXK45RfBllfOnSo3Xv35EvPYN9MV5bp/7WXc2HWknb
cv3blQKBgBhfC+kWbFMtGwufLBQkElxIlUFrlFt/L86J2/yymH+t+x67r6fh/L2G
zYo8pyAJV3HBH+/0t7ZucY4KplazPIpRcR78CC3ws7qzFKrEYkgMggaffRXWNZ1o
aqV9+CDcF+WasYXnyva1776OjCZk33b0MQxjKghTRdM/cril3ufQ
-----END RSA PRIVATE KEY-----
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
const std::string PEM_PS384_PRIVATE = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA+an4opwpewibqEzJ3nzoyjT6fJrXxG8cwLaUy1HYs/CfsuD3
+sV/XAXxvY6x8n6P+VBNRY7XUCfL+Z4qodLaj2rmzGw6Drjxpj+4EDqf4OsTdIe0
0qfYcdUvuEcuDtnKhE+oHVuGd/nFn4sFjsa7rMpvqn9JVTe0farJ8w2oAxh8SAE3
bv0WsazCSKR9d8StgqJc24RfiylP/pDm36y5Tp/VgLxlJDuH/3/27BcNvcts7P7Z
FxQ2lbJBYSsouI7n9bryLX6FXhBYZOoBwXjzjvsjU/mpbIlI/CCoP0CJps/XRa4y
IG1vQf9zKdnULje+OnCuPJa+sb43XPDzQuq+iQIDAQABAoIBACqRRmlDQvdNQmzx
msGqfm5rlgHEzOEbKMXa24fHDrGvZysynFVPcyWXhd4SBFkaJyYVAPfJIQDzqB2J
UC+DKeymB2/3S/bSpbD40ENEG5pXult1/+ii4Y6XEKnUyQ+TJqpkgn9u6YBvP7iy
FWKAk+MkKOHjDffPpaB/jCs6uti7785XOl0zZ4pl3L221+bxMW8TwnNS+1CyrpZp
wi12QASjoz2ul1tHY9R16mqfXEjrJysLU5PPjX7T4jkXZd4c0ZbkzonvQA0TRT63
If5SnPPYj3ezAOIznG2mn/wnUsdbMdnNTItrT0tZQ7VZxHEMIVDGM4enincdqd4h
HzqDDwECgYEA/tRb9hooIsgjbWf3XKXQwf1FoaTWwuEthzqB06nixgK6advNCPJ+
FAhUjEjOI2pNKyWKtr+KuGC0aEROLcEFd+HGbIytCgXSqPdrrinMxflo3C55MPDL
CX/C1tiLpl4qS5dLu91GG2/Ao9iqJjjPX/VUwBBqyNZb4AMUwhITx3ECgYEA+s+J
vyUjSgOHyxrJURL+OJXI1UK99I4royr20od6MENtX4RztlOVnAQkhfr9nHhwATaa
bQyj5s6NA3l5tfjlUKbNIRSoYYpK64tzlphBHJ6/Ju26MPm9Fon/NOfkD85OXfmk
QKK9JQX2zSZDqX7PjEyLCdn9ogkzrFpjJhCTTJkCgYAeqNQrpvf/P08r4Z9cUULt
pBhVm2yPY+JDa+Gk4sK7Cib9h4mCsxJCPMJXYocSsb55G3o2BJOfHVt3VAiH7rpG
sy5Zbw9+rjarR6F4AeV2SEy6eQjxv3bePLXnfYRHzvqNv7VH9BZ0RJzL2cyW7qzc
obrBpPgEE+5X5GcB9oTUsQKBgDptTHZ1zVG5ntGmrM0xMn22DvH3OU8WK344TQVg
QAusOXdt4JLRx+FvaZ64iIoB2H2/3ZuXvTrQVTNBAiRtFeaC5PhW2p7WW3uhocys
LUbgiEEmUiCEnRL6FLSbbJpuAf2MYUIZZxyP1h2WU17RxsG1NxKVcKtln18AM2az
p8zJAoGAfnge7bcLqmt6Q8oXlYjQHPTHmUlOgfYebpNrxa3jSjOmtGkPLUQ0GGD1
Lf8EuPuFSRH7v05THU4mhUFzQSRO9pPOcAMuQqm2bo9UfM9wYxe7jD6V2lrcqaYV
oaeW3Z1XGBYjtYJyR0Pogg7umSBeHD37zSELB8HYebCL3SuE184=
-----END RSA PRIVATE KEY-----
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
const std::string PEM_PS512_PRIVATE = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAhcPDlRPlk7J/Ch6CcPu93L5TsESmYcnJbSfKhobOqpKmoQGD
VB6wE+Lel5nZzB23+rPpBa0tUPeWHn0g4vJ9vGjZQMDYvJJ3q5QPkO+KGqigNAMG
Qkv4tc2y6tdutuZ9q6ftlsysDuooKrtpNDMHOhUIIVf8W9aaMrJa5PwnjoLS0eaZ
QVKi/uMYY7gdICjKP173GYJg733Tvv0rVTZsRvFgj5EQRx2e8vfFxJFtXGUcAEpE
ViYKwWjjvwJDlDsI/zjiggAgoIQfZJxqRuyYb5FAuIUJyd9fNM67YzidYrS3JzoB
ftrOWU2trO5lqpt0VE+Y98UzLslnGEXiBrcXrQIDAQABAoIBAHNCKYaM7GaFiT2Y
6GCeKgzI2qepn4vnKW6quLGN+wmy720QNq8G+kVIWPBcGvTsLpkQ6JqBi+iWTX3b
57hlpb3wwjIveRGTSxZGr9r87Azoe5IVgREjERzmL2J3WuiyVlrQicJEfYUkcpPP
hGj8ByAe+zBv9fzUP22rjPJ96z+5bNAuOWfIvVVZoM9ywJCXdWDYUxhEtBHb5BHF
24uXiCfwmY4IIhIoqG7qNwLwR4mcu33pdKkoIeyWm4pvm/v9ymnQz9WO3nqAsf3f
vL1dreye8zlhenGJGYFV1yOngRDqdompFE8CdCmrA3o6VkGobC5p9PdA1Aney2HQ
0Gxq1UECgYEA0R7yyn2N3/Re65/3C2I9U7rWjE64WcFpXOnCB9QIyfN+MTaHdHcu
Y1S0Ow9wfLLlCDlozGBuRz23KpGpzxEk0wnftw+4xRldDf9Dep+QQ91Ra8zu0KSk
5W7JbQNmci+hkWBwBmNkVfvkA1Qhf4LGUABbcgo+7y1nX3SIrl/cXVkCgYEAo8BE
ST9gBmzCZjmUJwrsdd9iF5xp4fC1C8GJ0GayzHrQe/WFrYALQWxB+T6HktuewREk
bI0TIjamzBzkqV+Cgus5aRJNy3W/iEkmqH4ozqK/M8jGvYGoNLpov4xDaMnB5x2W
OltKEJ9ZmAtl9j/GWtC9KjtRdstSuC9P2LKQHnUCgYBSJJT8IytqkCQE7BXvW8x5
KkgCXx2c7BNGEvBLgOde5I1qKWA1yGbpT6loFZ167g53F43p0esfgseDKiqIktRj
LVq6HqvWiCr8R4urDChv7+x+qsYYIMRA9y6Z6p8ANWOCpl36tGoCOGqNQCvUWXsq
i6lf91RXQP99CFp0HGWEKQKBgAm9U9JvfIylR2LBJfi0g5/3K2RwHzQbFwmd9053
7UaQP3o//jV1mjXH9JyYhYPMoEKnfF0gfvTX/0/AoDEaxy52QzHmrs3dMQkwIKaA
6nhv4aN426lF3vVT6QsLkq7W4TuX3OmXqG4YrEGI3AWrgWbBZ57tbEj+iur9lWg0
JrJJAoGAGdfygPsrPbzWt8/HXTFmgyXSvg0lSarYJ3+sLXwq3g5O69ZAo1SrWbE9
i68KM2bwQtQyNqPlGJRbhTAwCqes6zdpZH1eSGxz4i3WGnTXJ9UYH+AX1lyyuxy2
3Z2oID2FZgPpZHuZ0CCdvAl94cQXKpDAfDKZgqdUu+4DC6zlAPw=
-----END RSA PRIVATE KEY-----
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
const std::string PEM_ES256_PRIVATE = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzapLxXUHHWO5eI1I
OhzYIX0kD9WdWz4jo+tXK6h2xxuhRANCAASs5ZDYaNzFGiwjjpUvXrNMvdWW2Leu
LTItTonofQ3D7eqC8Fec3xJq5JmSAY2rfdnpwdxfsMvfu7qMsAHRkXNh
-----END PRIVATE KEY-----
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
const std::string PEM_ES384_PRIVATE = R"(-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB0qb3YFVeWNvKxgMN3
vfWJN1SPMx/NGkuRnVJoZvFgiF2Ab9hiRYhBcw7Q2okVxM2hZANiAASm2eqDuApR
YqDn6APZvUoxXkuK58+yKbBpsVG70Q0IzJ1yUF77/byI+kHOKzLyJPMqydFrpBUk
9vwEI6M8ZVNfjxw56hPoGt2pi3MrUiIDwvswjCeDFNUsqm2WLMQ8wNI=
-----END PRIVATE KEY-----
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
const std::string PEM_ES512_PRIVATE = R"(-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAeG/xYCQ2BkClKfej
7EkzBsvVIPxd5RRkmtDB58UVzsraIpVt4WrZJPQ/dLBFwElZIK/VwUC4o1alnzYb
lqrHPN6hgYkDgYYABAFxvaoSswq5m9H//LbwuJdcpdlhutKlgoKfzj3tOVkfvWZ3
73iTGM8mBfMTr3knrDFhCs1sZ422ot5FLsMbA+dnqQGf5T/662cfGerMSKGhZW4L
x6h4BcVhBonAW1zaH4F8LjrhyirKuykjUpodoY086D1TgDNbF5jAv54UIJrSgmZy
4w==
-----END PRIVATE KEY-----
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
const std::string PEM_ES256K_PRIVATE = R"(-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgN8JUNzTt+alwdQjCCDzd
oGMebq1OaQl7OZpsUbx0x9ahRANCAAQgyXICF/aepjWBO1W5CEeOvywkZNH1QCWo
TIgClQ1krEb99nHQqlqA4XFhPn3qfMTINkkd4aouE3q9CfSZP1W/
-----END PRIVATE KEY-----
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

const std::string JWKS =
    "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"rs384_keyid\",\"alg\":"
    "\"RS384\",\"n\":\"qtUV_qPEXN7a2jR_E4k9pdqy1wiRHKyQoiybOW7Nm-"
    "JMR7qa6fq6U95YyeuC6mpDEQUpnEyqLrEP8HxBZOgwHkln5PwUhyAS2kcsQTf0RDGG2YBeNNA-sCb4-"
    "oM5O0NwWt0pJIoFPNIyOxRYdSZBA3h5MvwIgQPbj4-a-"
    "YSjQsborfEywcqozHUDQ4VFadoO9tIIVaPIRqANs54BokCfOyduP-dqlf2d3q1yukFQ2K7L27mrDtCXcWjS5CJW-oGf_"
    "CyOSj-yyaNug7sOlvU5AwjG3l7EZ0GRFeROWl5pj6Hf054o4WI2m3xXY8S38hO6jb_NvlG0pg4ZHZEvvqCMdQ\"},{"
    "\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"rs512_keyid\",\"alg\":\"RS512\","
    "\"n\":\"oF6oCRUztdPc2_jCuuD0aKlv-baqMmymiYYwU1Gf-"
    "UZ4dNUI8gxDLHZW7tS0uYYTn85r8UJ3DeSskT41FdAZb1Bfi21fSqAhT169P-"
    "hB8RYIyVQNubyJsFXK1xfRp7H3tlO60C1lrv9YLNNXXxQnhGdxAAXQeAsecEUQ_GQS1PdS22vl95cn42051pLf4_"
    "ssmReZZmRz3htlJDIumVMMP6FJLbxvBgdODCdUappMwkI_com2Orz4sYFk8GYvsJC4o_hsE9AQU8OTm0z9JxmyWDu6FE_"
    "BOr9UryKwsqon_2K4ufAqU5ePvmiEv0goqInC9DU7fGFLc8shv4S3fY8wvw\"},{\"kty\":\"RSA\",\"e\":"
    "\"AQAB\",\"use\":\"sig\",\"kid\":\"ps384_keyid\",\"alg\":\"PS384\",\"n\":\"-"
    "an4opwpewibqEzJ3nzoyjT6fJrXxG8cwLaUy1HYs_CfsuD3-sV_XAXxvY6x8n6P-VBNRY7XUCfL-"
    "Z4qodLaj2rmzGw6Drjxpj-4EDqf4OsTdIe00qfYcdUvuEcuDtnKhE-oHVuGd_"
    "nFn4sFjsa7rMpvqn9JVTe0farJ8w2oAxh8SAE3bv0WsazCSKR9d8StgqJc24RfiylP_pDm36y5Tp_VgLxlJDuH_3_"
    "27BcNvcts7P7ZFxQ2lbJBYSsouI7n9bryLX6FXhBYZOoBwXjzjvsjU_mpbIlI_CCoP0CJps_XRa4yIG1vQf9zKdnULje-"
    "OnCuPJa-sb43XPDzQuq-iQ\"},{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"ps512_"
    "keyid\",\"alg\":\"PS512\",\"n\":\"hcPDlRPlk7J_Ch6CcPu93L5TsESmYcnJbSfKhobOqpKmoQGDVB6wE-"
    "Lel5nZzB23-rPpBa0tUPeWHn0g4vJ9vGjZQMDYvJJ3q5QPkO-"
    "KGqigNAMGQkv4tc2y6tdutuZ9q6ftlsysDuooKrtpNDMHOhUIIVf8W9aaMrJa5PwnjoLS0eaZQVKi_"
    "uMYY7gdICjKP173GYJg733Tvv0rVTZsRvFgj5EQRx2e8vfFxJFtXGUcAEpEViYKwWjjvwJDlDsI_"
    "zjiggAgoIQfZJxqRuyYb5FAuIUJyd9fNM67YzidYrS3JzoBftrOWU2trO5lqpt0VE-Y98UzLslnGEXiBrcXrQ\"},{"
    "\"kty\":\"EC\",\"d\":\"N8JUNzTt-alwdQjCCDzdoGMebq1OaQl7OZpsUbx0x9Y\",\"crv\":\"secp256k1\","
    "\"kid\":\"es256k_keyid\",\"x\":\"IMlyAhf2nqY1gTtVuQhHjr8sJGTR9UAlqEyIApUNZKw\",\"y\":"
    "\"Rv32cdCqWoDhcWE-fep8xMg2SR3hqi4Ter0J9Jk_Vb8\",\"alg\":\"ES256K\"},{\"kty\":\"EC\",\"d\":"
    "\"dKm92BVXljbysYDDd731iTdUjzMfzRpLkZ1SaGbxYIhdgG_YYkWIQXMO0NqJFcTN\",\"crv\":\"P-384\","
    "\"kid\":\"es384_keyid\",\"x\":\"ptnqg7gKUWKg5-gD2b1KMV5LiufPsimwabFRu9ENCMydclBe-_"
    "28iPpBzisy8iTz\",\"y\":\"KsnRa6QVJPb8BCOjPGVTX48cOeoT6BrdqYtzK1IiA8L7MIwngxTVLKptlizEPMDS\","
    "\"alg\":\"ES384\"},{\"kty\":\"EC\",\"d\":\"AHhv8WAkNgZApSn3o-"
    "xJMwbL1SD8XeUUZJrQwefFFc7K2iKVbeFq2ST0P3SwRcBJWSCv1cFAuKNWpZ82G5aqxzze\",\"crv\":\"P-521\","
    "\"kid\":\"es512_keyid\",\"x\":\"AXG9qhKzCrmb0f_8tvC4l1yl2WG60qWCgp_OPe05WR-"
    "9ZnfveJMYzyYF8xOveSesMWEKzWxnjbai3kUuwxsD52ep\",\"y\":\"AZ_lP_"
    "rrZx8Z6sxIoaFlbgvHqHgFxWEGicBbXNofgXwuOuHKKsq7KSNSmh2hjTzoPVOAM1sXmMC_nhQgmtKCZnLj\",\"alg\":"
    "\"ES512\"},{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"rs256_keyid\",\"alg\":\"RS256\",\"n\":"
    "\"3dkN0LTLvH9wl-vL-MYXtVsvyd4NS9oatGzPfJWTIUOii-N7SmMV383XHfysAm6M_"
    "DTqW3HOxzDF0hLIMXzqUDjyQizGIZ37RkF4GqIcOSEYwkc2IWVnWl4WcSK-"
    "2KUlwMe3PpXdxtVZBFGdOVkwbXrdsFiYU11kRhfTbz0pP3lmm84QEzCrP9Jueu1zqeyj_SBLUszNkgofp_"
    "DpTVPKTVtkkqqNYBRF7HhPgR3G2F90NCfHMTjUQICFNP-HT-"
    "UO7XS35dmqBJNgAO7aIiokrZhl3TrQUrknwlxBTF3gv1Zjru1YG6k_lTHVFcVN3pY-Lr2IiJUdppgpreklY7n8jw\"},{"
    "\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"ps256_keyid\",\"alg\":\"PS256\",\"n\":"
    "\"o2vAJwdvkyIICvLRvvGn0rEsoSkQHFyPIVoELqKXNxBke8Xkn-yxe1zWx62d71h6ewIpPPHZ7K5lMZJbj-XqJIy-g2_"
    "7ZWujQhmE_v1JY3TNkAGNsKJupBWPqsyUzEou-ApERvj-IHASQ-zinitDUxhFPb-1q32T1gRgzU2YWVDTa7StgPxu5cu-"
    "GuCeh5uc5FCmCYvtD2TOzWWbh8qiESmYTFR_4n6gQyt_v16iRJCDuR7_HUG0LlgDf78AJDQOZllPXG8Kcj1_"
    "Y1lOosUWg0hjMIS6KqB2nQ-PiLoc9QqOklfHDy2JHrOFb5P1S6vmK75JL3kdd1EyxkgVOWAEiQ\"},{\"kty\":\"EC\","
    "\"d\":\"zapLxXUHHWO5eI1IOhzYIX0kD9WdWz4jo-tXK6h2xxs\",\"crv\":\"P-256\",\"kid\":\"es256_"
    "keyid\",\"x\":\"rOWQ2GjcxRosI46VL16zTL3Vlti3ri0yLU6J6H0Nw-0\",\"y\":"
    "\"6oLwV5zfEmrkmZIBjat92enB3F-wy9-7uoywAdGRc2E\",\"alg\":\"ES256\"}]}";
const std::string CLAIM_KEY = "sub";
const std::string ISSUER = "anyissuer";
const std::string AUDIENCE = "anyaud";
const std::string SUBJECT = "anysub";
const std::string CUSTOM_KEY = "customkey";

Result<jwt::builder<jwt::traits::kazuho_picojson>> GenerateBuilder(std::string alg_prefix) {
  try {
    auto builder =
        jwt::create()
            .set_issuer(ISSUER)
            .set_audience(AUDIENCE)
            .set_type("JWT")
            .set_key_id(Format("$0_keyid", alg_prefix))
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{36000})
            .set_subject(SUBJECT);
    return builder;
  } catch (...) {
    return STATUS(InvalidArgument, "Could not create builder");
  }
}

#define JWT_ALGORITHM(alg, private_key) jwt::algorithm::alg("", private_key)

TEST(JwtCppUtilTest, ParseJwksSuccess) { ASSERT_RESULT(ParseJwks(JWKS)); }

TEST(JwtCppUtilTest, ParseJwksInvalid) { ASSERT_NOT_OK(ParseJwks("illformatted_json")); }

TEST(JwtCppUtilTest, GetJwkFromJwksSuccess) {
  auto jwks = ASSERT_RESULT(ParseJwks(JWKS));
  auto jwk = ASSERT_RESULT(GetJwkFromJwks(jwks, "ps512_keyid"));
  ASSERT_EQ(jwk.get_key_id(), "ps512_keyid");
}

TEST(JwtCppUtilTest, GetJwkFromJwksInvalid) {
  auto jwks = ASSERT_RESULT(ParseJwks(JWKS));
  ASSERT_NOT_OK(GetJwkFromJwks(jwks, "missing_keyid"));
}

TEST(JwtCppUtilTest, GetX5cKeyValueFromJWKSuccess) {
  auto jwks_with_x5c = R"(
        {
            "keys": [
                {
                    "kty": "EC",
                    "d": "N8JUNzTt-alwdQjCCDzdoGMebq1OaQl7OZpsUbx0x9Y",
                    "crv": "secp256k1",
                    "kid": "ps512_keyid",
                    "x": "IMlyAhf2nqY1gTtVuQhHjr8sJGTR9UAlqEyIApUNZKw",
                    "y": "Rv32cdCqWoDhcWE-fep8xMg2SR3hqi4Ter0J9Jk_Vb8",
                    "alg": "ES256K",
                    "x5c": [
                        "some x5c value"
                    ]
                }
            ]
        }
    )";
  auto jwks = ASSERT_RESULT(ParseJwks(jwks_with_x5c));
  auto jwk = ASSERT_RESULT(GetJwkFromJwks(jwks, "ps512_keyid"));
  ASSERT_EQ(ASSERT_RESULT(GetX5cKeyValueFromJWK(jwk)), "some x5c value");
}

TEST(JwtCppUtilTest, GetX5cKeyValueFromJWKInvalid) {
  auto jwks_without_x5c = R"(
        {
            "keys": [
                {
                    "kty": "EC",
                    "d": "N8JUNzTt-alwdQjCCDzdoGMebq1OaQl7OZpsUbx0x9Y",
                    "crv": "secp256k1",
                    "kid": "ps512_keyid",
                    "x": "IMlyAhf2nqY1gTtVuQhHjr8sJGTR9UAlqEyIApUNZKw",
                    "y": "Rv32cdCqWoDhcWE-fep8xMg2SR3hqi4Ter0J9Jk_Vb8",
                    "alg": "ES256K",
                    "bool_field": true
                }
            ]
        }
    )";
  auto jwks = ASSERT_RESULT(ParseJwks(jwks_without_x5c));
  auto jwk = ASSERT_RESULT(GetJwkFromJwks(jwks, "ps512_keyid"));
  ASSERT_NOT_OK(GetX5cKeyValueFromJWK(jwk));
}

TEST(JwtCppUtilTest, GetClaimFromJwkAsStringSuccess) {
  auto jwks = ASSERT_RESULT(ParseJwks(JWKS));
  auto jwk = ASSERT_RESULT(GetJwkFromJwks(jwks, "ps512_keyid"));
  ASSERT_EQ(ASSERT_RESULT(GetClaimFromJwkAsString(jwk, "kid")), "ps512_keyid");
}

TEST(JwtCppUtilTest, GetClaimFromJwkAsStringInvalid) {
  auto jwks_with_bool_field = R"(
        {
            "keys": [
                {
                    "kty": "EC",
                    "d": "N8JUNzTt-alwdQjCCDzdoGMebq1OaQl7OZpsUbx0x9Y",
                    "crv": "secp256k1",
                    "kid": "ps512_keyid",
                    "x": "IMlyAhf2nqY1gTtVuQhHjr8sJGTR9UAlqEyIApUNZKw",
                    "y": "Rv32cdCqWoDhcWE-fep8xMg2SR3hqi4Ter0J9Jk_Vb8",
                    "alg": "ES256K",
                    "bool_field": true
                }
            ]
        }
    )";
  auto jwks = ASSERT_RESULT(ParseJwks(jwks_with_bool_field));
  auto jwk = ASSERT_RESULT(GetJwkFromJwks(jwks, "ps512_keyid"));
  ASSERT_NOT_OK(GetClaimFromJwkAsString(jwk, "bool_field"));
}

TEST(JwtCppUtilTest, ConvertX5cDerToPemSuccess) {
    auto der_encoded_x5c = "MIIDBTCCAe2gAwIBAgIQH4FlYNA+UJlF0G3vy9ZrhTANBgkqhki"
        "G9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3Mub"
        "mV0MB4XDTIyMDUyMjIwMDI0OVoXDTI3MDUyMjIwMDI0OVowLTErMCkGA1UEAxMiYWNjb3V"
        "udHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"
        "DCCAQoCggEBAMBDDCbY/cjEHfEEulZ5ud/CuRjdT6/yN9fy1JffjgmLvvfw6w7zxo1YkCv"
        "ZDogowX8qqAC/qQXnJ/fl12kvguMWU59WUcPvhhC2m7qNLvlOq90yo+NsRQxD/v0eUaThr"
        "IaAveZayolObXroZ+HwTN130dhgdHVTHKczd4ePtDjLwSv/2a/bZEAlPys102zQo8gO8m7"
        "W6/NzRfZNyo6U8jsmNkvqrxW2PgKKjIS/UafK9hwY/767K+kV+hnokscY2xMwxQNlSHEim"
        "0h72zQRHltioy15M+kBti4ys+V7GC6epL//pPZT0Acv1ewouGZIQDfuo9UtSnKufGi26dM"
        "AzSkCAwEAAaMhMB8wHQYDVR0OBBYEFLFr+sjUQ+IdzGh3eaDkzue2qkTZMA0GCSqGSIb3D"
        "QEBCwUAA4IBAQCiVN2A6ErzBinGYafC7vFv5u1QD6nbvY32A8KycJwKWy1sa83CbLFbFi9"
        "2SGkKyPZqMzVyQcF5aaRZpkPGqjhzM+iEfsR2RIf+/noZBlR/esINfBhk4oBruj7SY+kPj"
        "YzV03NeY0cfO4JEf6kXpCqRCgp9VDRM44GD8mUV/ooN+XZVFIWs5Gai8FGZX9H8ZSgkIKb"
        "xMbVOhisMqNhhp5U3fT7VPsl94rilJ8gKXP/KBbpldrfmOAdVDgUC+MHw3sSXSt+VnorB4"
        "DU4mUQLcMriQmbXdQc8d1HUZYZEkcKaSgbygHLtByOJF44XUsBotsTfZ4i/zVjnYcjgUQm"
        "wmAWD";
    // The x5c is just enclosed with "BEGIN CERTIFICATE" and "END CERTIFICATE" lines.
    auto expected_pem = R"(-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIQH4FlYNA+UJlF0G3vy9ZrhTANBgkqhkiG9w0BAQsFADAt
MSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4X
DTIyMDUyMjIwMDI0OVoXDTI3MDUyMjIwMDI0OVowLTErMCkGA1UEAxMiYWNjb3Vu
dHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMBDDCbY/cjEHfEEulZ5ud/CuRjdT6/yN9fy1JffjgmLvvfw
6w7zxo1YkCvZDogowX8qqAC/qQXnJ/fl12kvguMWU59WUcPvhhC2m7qNLvlOq90y
o+NsRQxD/v0eUaThrIaAveZayolObXroZ+HwTN130dhgdHVTHKczd4ePtDjLwSv/
2a/bZEAlPys102zQo8gO8m7W6/NzRfZNyo6U8jsmNkvqrxW2PgKKjIS/UafK9hwY
/767K+kV+hnokscY2xMwxQNlSHEim0h72zQRHltioy15M+kBti4ys+V7GC6epL//
pPZT0Acv1ewouGZIQDfuo9UtSnKufGi26dMAzSkCAwEAAaMhMB8wHQYDVR0OBBYE
FLFr+sjUQ+IdzGh3eaDkzue2qkTZMA0GCSqGSIb3DQEBCwUAA4IBAQCiVN2A6Erz
BinGYafC7vFv5u1QD6nbvY32A8KycJwKWy1sa83CbLFbFi92SGkKyPZqMzVyQcF5
aaRZpkPGqjhzM+iEfsR2RIf+/noZBlR/esINfBhk4oBruj7SY+kPjYzV03NeY0cf
O4JEf6kXpCqRCgp9VDRM44GD8mUV/ooN+XZVFIWs5Gai8FGZX9H8ZSgkIKbxMbVO
hisMqNhhp5U3fT7VPsl94rilJ8gKXP/KBbpldrfmOAdVDgUC+MHw3sSXSt+VnorB
4DU4mUQLcMriQmbXdQc8d1HUZYZEkcKaSgbygHLtByOJF44XUsBotsTfZ4i/zVjn
YcjgUQmwmAWD
-----END CERTIFICATE-----
)";
  ASSERT_EQ(ASSERT_RESULT(ConvertX5cDerToPem(der_encoded_x5c)), expected_pem);
}

TEST(JwtCppUtilTest, ConvertX5cDerToPemInvalid) {
  ASSERT_NOT_OK(ConvertX5cDerToPem("an invalid x5c"));
}

TEST(JwtCppUtilTest, DecodeJwtSuccess) {
  auto builder = ASSERT_RESULT(GenerateBuilder("rs256"));
  auto jwt = builder.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));

  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt));

  ASSERT_EQ(decoded_jwt.get_key_id(), "rs256_keyid");
  ASSERT_EQ(decoded_jwt.get_subject(), SUBJECT);
}

TEST(JwtCppUtilTest, DecodeJwtInvalid) { ASSERT_NOT_OK(DecodeJwt("an_invalid_jwt")); }

TEST(JwtCppUtilTest, GetKeyIdSuccess) {
  auto builder = ASSERT_RESULT(GenerateBuilder("rs256"));
  auto jwt = builder.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));

  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt));
  auto key_id = ASSERT_RESULT(GetKeyId(decoded_jwt));

  ASSERT_EQ(key_id, "rs256_keyid");
}

TEST(JwtCppUtilTest, GetKeyIdInvalid) {
  // It is not possible to generate a JWT without key id via the library, so this is hardcoded
  // after generating online.
  auto jwt_without_key_id =
      "eyJhbGciOiJSUzI1NiIsImN0eSI6IkpXVCJ9.eyJzdWIiOiI"
      "xMjM0NTY3ODkwIiwiaWF0IjoxNjAzMzc2MDExfQ.EzWU2fTxcQbOvkK-SkRyEJTFjRboB0"
      "gIdhXjisfrTxd76UewpsNz81wMNeweBKZ1pkUFM1hFsvupO5TOf_yS7NjaMH649uQxG-i2"
      "EZR4H_sbXZ-b7afYPMbmjJg80sxH4C4HLavCi-3PEVajuEHAPFAS1jiRPtMqHMDPtOIymJ"
      "enhdZfReSTsyCPQAqPn-Y4uC-7cbHeT619bb1dvbooOb24VuH7sk1SwZR_ITmQJzx-95Qr"
      "YOA4AnctmdlJ3Ez_-5Ti3WWfIKjOm5QpsbOlILquAJ-q-11scFTwcSbopcz8MkhmX76tJa"
      "wgIPp2_oVjwSSDTUH1WvFPfuN17gSZVw";
  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt_without_key_id));

  ASSERT_NOT_OK(GetKeyId(decoded_jwt));
}

TEST(JwtCppUtilTest, GetIssuerSuccess) {
  auto builder = ASSERT_RESULT(GenerateBuilder("rs256"));
  auto jwt = builder.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));

  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt));
  auto issuer = ASSERT_RESULT(GetIssuer(decoded_jwt));

  ASSERT_EQ(issuer, ISSUER);
}

TEST(JwtCppUtilTest, GetIssuerInvalid) {
  auto builder_without_issuer =
      jwt::create()
          .set_audience(AUDIENCE)
          .set_type("JWT")
          .set_key_id(Format("rs256_keyid"))
          .set_issued_at(std::chrono::system_clock::now())
          .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{36000})
          .set_subject(SUBJECT);
  auto jwt = builder_without_issuer.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));
  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt));

  auto issuer_result = GetIssuer(decoded_jwt);
  ASSERT_NOT_OK(issuer_result);
  ASSERT_NE(
      issuer_result.status().message().ToBuffer().find("Fetching issuer from the JWT failed"),
      std::string::npos)
      << issuer_result.status();
}

TEST(JwtCppUtilTest, GetClaimAsStringsArraySuccess) {
  auto builder = ASSERT_RESULT(GenerateBuilder("rs256"));
  builder.set_payload_claim(CUSTOM_KEY, jwt::claim(picojson::value("abc")));
  auto jwt = builder.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));

  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt));

  auto claim_value = ASSERT_RESULT(GetClaimAsStringsArray(decoded_jwt, CUSTOM_KEY));
  auto expected_value = std::vector<std::string>{"abc"};
  ASSERT_EQ(claim_value, expected_value);
}

void TestGetClaimAsStringsArrayInvalid(const std::string& jwt) {
  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt));

  auto get_claim_result = GetClaimAsStringsArray(decoded_jwt, CUSTOM_KEY);
  ASSERT_NOK(get_claim_result);
  ASSERT_NE(
      get_claim_result.status().message().ToBuffer().find(
          "Claim value with name customkey was not a string or array of string."),
      std::string::npos)
      << get_claim_result.status();
}

TEST(JwtCppUtilTest, GetClaimAsStringsArrayPrimitiveInvalid) {
  auto builder = ASSERT_RESULT(GenerateBuilder("rs256"));
  builder.set_payload_claim(CUSTOM_KEY, jwt::claim(picojson::value(int64_t{12345})));
  auto jwt = builder.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));

  TestGetClaimAsStringsArrayInvalid(jwt);
}

TEST(JwtCppUtilTest, GetClaimAsStringsArrayListInvalid) {
  auto builder = ASSERT_RESULT(GenerateBuilder("rs256"));
  std::vector<picojson::value> claim_value = {
      picojson::value(int64_t{1}), picojson::value(int64_t{2})};
  builder.set_payload_claim(CUSTOM_KEY, jwt::claim(picojson::value(claim_value)));
  auto jwt = builder.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));

  TestGetClaimAsStringsArrayInvalid(jwt);
}

TEST(JwtCppUtilTest, GetAudiencesSingletonSuccess) {
  auto builder = ASSERT_RESULT(GenerateBuilder("rs256"));
  auto jwt = builder.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));

  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt));
  auto audiences = ASSERT_RESULT(GetAudiences(decoded_jwt));

  ASSERT_EQ(audiences, std::set<std::string>{AUDIENCE});
}

TEST(JwtCppUtilTest, GetAudiencesMultipleSuccess) {
  auto builder = ASSERT_RESULT(GenerateBuilder("rs256"));
  builder.set_audience(
      std::vector<picojson::value>{picojson::value(AUDIENCE), picojson::value("ANOTHER_AUDIENCE")});
  auto jwt = builder.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));

  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt));
  auto audiences = ASSERT_RESULT(GetAudiences(decoded_jwt));

  auto expected_audience_set = std::set<std::string>{AUDIENCE, "ANOTHER_AUDIENCE"};
  ASSERT_EQ(audiences, expected_audience_set);
}

TEST(JwtCppUtilTest, GetAudiencesInvalid) {
  auto builder_without_audiences =
      jwt::create()
          .set_issuer(ISSUER)
          .set_type("JWT")
          .set_key_id(Format("rs256_keyid"))
          .set_issued_at(std::chrono::system_clock::now())
          .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{36000})
          .set_subject(SUBJECT);
  auto jwt = builder_without_audiences.sign(JWT_ALGORITHM(rs256, PEM_RS256_PRIVATE));
  auto decoded_jwt = ASSERT_RESULT(DecodeJwt(jwt));

  auto audiences_result = GetAudiences(decoded_jwt);
  ASSERT_NOT_OK(audiences_result);
  ASSERT_NE(
      audiences_result.status().message().ToBuffer().find("Fetching audience from the JWT failed"),
      std::string::npos)
      << audiences_result.status();
}

TEST(JwtCppUtilTest, GetVerifierSuccess) {
  ASSERT_RESULT(GetVerifier(PEM_RS256_PUBLIC, "RS256"));
  ASSERT_RESULT(GetVerifier(PEM_RS384_PUBLIC, "RS384"));
  ASSERT_RESULT(GetVerifier(PEM_RS512_PUBLIC, "RS512"));
  ASSERT_RESULT(GetVerifier(PEM_PS256_PUBLIC, "PS256"));
  ASSERT_RESULT(GetVerifier(PEM_PS384_PUBLIC, "PS384"));
  ASSERT_RESULT(GetVerifier(PEM_PS512_PUBLIC, "PS512"));
  ASSERT_RESULT(GetVerifier(PEM_ES256_PUBLIC, "ES256"));
  ASSERT_RESULT(GetVerifier(PEM_ES384_PUBLIC, "ES384"));
  ASSERT_RESULT(GetVerifier(PEM_ES512_PUBLIC, "ES512"));
  ASSERT_RESULT(GetVerifier(PEM_ES256K_PUBLIC, "ES256K"));
}

TEST(JwtCppUtilTest, GetVerifierUnsupported) {
  auto hs256_verifier = GetVerifier("does not matter", "HS256");
  ASSERT_NOT_OK(hs256_verifier);
  ASSERT_NE(
      hs256_verifier.status().message().ToBuffer().find("Unsupported JWT algorithm: HS256"),
      std::string::npos)
      << hs256_verifier.status();
}

TEST(JwtCppUtilTest, GetVerifierInvalidPublicPEM) {
  auto invalid_verifier = GetVerifier("invalidpem", "RS256");
  ASSERT_NOT_OK(invalid_verifier);
  ASSERT_NE(
      invalid_verifier.status().message().ToBuffer().find(
          "Constructing JWT verifier for public key: invalidpem and algo: RS256 failed"),
      std::string::npos)
      << invalid_verifier.status();
}

// 1. Generate a JWT
// 2. Sign it with the given key
// 3. Get the verifier for the key and algorithm
// 4. Assert that verification is successful
#define TEST_VERIFY_JWT_USING_VERIFIER(algorithm, lowercase_algorithm) \
  TEST(JwtCppUtilTest, VerifyJwtUsingVerifierSuccess##algorithm) { \
    auto builder = ASSERT_RESULT(GenerateBuilder(#lowercase_algorithm)); \
    auto token = builder.sign(JWT_ALGORITHM(lowercase_algorithm, PEM_##algorithm##_PRIVATE)); \
    auto verifier = ASSERT_RESULT(GetVerifier(PEM_##algorithm##_PUBLIC, #algorithm)); \
    auto decoded_jwt = ASSERT_RESULT(DecodeJwt(token)); \
    ASSERT_OK(VerifyJwtUsingVerifier(verifier, decoded_jwt)); \
  }

TEST_VERIFY_JWT_USING_VERIFIER(RS256, rs256);
TEST_VERIFY_JWT_USING_VERIFIER(RS384, rs384);
TEST_VERIFY_JWT_USING_VERIFIER(RS512, rs512);
TEST_VERIFY_JWT_USING_VERIFIER(PS256, ps256);
TEST_VERIFY_JWT_USING_VERIFIER(PS384, ps384);
TEST_VERIFY_JWT_USING_VERIFIER(PS512, ps512);
TEST_VERIFY_JWT_USING_VERIFIER(ES256, es256);
TEST_VERIFY_JWT_USING_VERIFIER(ES384, es384);
TEST_VERIFY_JWT_USING_VERIFIER(ES512, es512);
TEST_VERIFY_JWT_USING_VERIFIER(ES256K, es256k);

// TODO: Also add cases for invalid token - expired, issued in future etc. Right now they are
// present in the Java test but can be moved here.

}  // namespace yb::util
