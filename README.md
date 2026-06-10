# JWT Decoder Functions for PostgreSQL

## Overview
Row-level security (RLS) in PostgreSQL is a feature that enables the restriction of database records visibility and access based on the current user's permissions. Instead of relying on application-level security, RLS enforces access control directly at the database level for each query, which allows for more granular and robust data protection.

By integrating JSON Web Tokens (JWTs) with RLS, PostgreSQL can authenticate users and apply access control policies using the information within the JWTs. This ensures that only the appropriate data is accessible to authenticated users based on their credentials. Verifying JWTs at the database level enhances overall security by preventing unauthorized access due to potential vulnerabilities in the application layer, centralizing critical access control logic within the database itself.

While PostgreSQL is a powerhouse of a database, it lacks the native ability to validate JWTs using RSA signatures. This project provides a set of PL/pgSQL functions that enable PostgreSQL databases to validate JWTs signed with RSA keys and also with HMAC, supporting the RSA verification algorithms RS256, RS384, RS512, and HMAC algorithms HS256, HS384, HS512.


## Features

- Validate RSA-signed and HMAC-signed JWTs within PostgreSQL.
- Support RS256, RS384, RS512, HS256, HS384, and HS512 signing algorithms.
- Validate the registered `exp`, `nbf`, `aud`, and `iss` claims.
- Centralized access control logic within the database.
- Usable with pgcrypto extension.

## Installation

To install the RSA JWT decoding functions in your PostgreSQL database, follow these steps:

1. Ensure you have the `pgcrypto` extension installed. If not, you can create it by running:

   ```sql
   CREATE EXTENSION pgcrypto;
   ```

2. Execute the SQL script `decode_jwt.sql` in your database. This will create the necessary functions for RSA JWT validation.

## Usage Example

To use the RSA JWT decoding functions, provide the JWT token and a JSON array of keys. The function `decode_jwt` returns the decoded JWT claims if the signature is valid, and null otherwise.

The example below is fully self-contained — copy and paste it as-is and it will
return the token's claims. The RSA key and the token it signed are a real,
matching pair (the token carries a single `aud` claim of `postgresql`):

```sql
SELECT jwt.decode_jwt(
    token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ijc1ODg2ODllLTYzY2UtNGFiYi05OTA2LTg3OTdlMDljODkyOCJ9.eyJhdWQiOiJwb3N0Z3Jlc3FsIn0.ddCxuCbIOGwU760UJPWEKbJiCSvs8gONDdut78C5nMR43_OlbtGxL9ZOiOABjleMF9eQMPciRy0ykVOTkhLu4XohQ9f4Ja0tQxABcb6X19V0Ozw1joToR7H4AuGzEowuZsTOBU2LCauiZkSLIZX8cbY5jy0ITGleZuP2CdpZUDATR7pQaQ0dTma6GyPAOWNcBtP3dVgpMDnjvqYnSz_Phtq9HJWIT-OWq2j_Qm9UMO1EmrHIzjmoI4_2fMhLHxt9000THvp3gwgQY67luectLdQDcum6tk-kOtJyEWsaJkYlrgRcNiupZJ2i8IjIFOqGiU3dRF9rK32EQ2SUBUjEMw',
    keys := jsonb_build_array(
        jwt.jwk_to_key('{"alg":"RS256","e":"AQAB","kid":"7588689e-63ce-4abb-9906-8797e09c8928","kty":"RSA","n":"qgfVLnNNaLLoro-7f4y83PN-W78CnF5qHj0tH72tQGk8NDvDlB5uil8f2JZXrT6wp6r3rKXF5Cm_RGOHm0CMM8607IWL5VBkecP7MiOGacTg44NMXe0Dcf2kLcuvJLpX7VerE6SPBWYe4pTOoGPRugb-1dF52Kc9e9Qni9iIgSprTOK23_JEokX573LYTiANGbsMAAyvIRCMGAShp15AeqWn1-7_EIB37b6PJAkbMPN5PHWa_wF8dPSJEOYSPoOPQoxN306-ZXnNx6JF87SyQQmEeoMjhzlASUP1KuMtlQuNHfQkW08MlJvyFdyweAkCeXdL8hAaTW4FiW_klJN0NQ","use":"sig"}'::jsonb)
    )
);
```

Running it returns the decoded claims:

```
        decode_jwt
-----------------------
 {"aud": "postgresql"}
(1 row)
```

To verify your own tokens, replace `token` with your JWT and the JWK(s) in
`keys` with your signing key set. You may pass more than one key — `decode_jwt`
selects the one whose `kid` matches the token header. Always supply each key's
**full** base64url `n` (modulus) and a complete token; abbreviating either with
an ellipsis makes the value invalid base64url and decoding fails with
`invalid symbol "." found while decoding base64 sequence`.

### Claims validation

After the signature is verified, `decode_jwt` validates the registered claims and
returns `null` (just like a signature failure) when validation fails:

- **`exp` / `nbf`** — enforced by default whenever the claim is present. A token
  with no `exp` claim is **not** rejected, so issue your tokens with an
  expiration. Pass `validate_exp := false` or `validate_nbf := false` to disable
  the corresponding check, and `leeway` to allow for clock skew.
- **`aud`** — only checked when you pass an expected `audience`. The token's
  `aud` claim may be a string or an array of strings and must contain the
  expected value.
- **`iss`** — only checked when you pass an expected `issuer`, which must equal
  the token's `iss` claim.

```sql
SELECT jwt.decode_jwt(
    token := 'eyJraWQiOiJMYXNy...',
    keys := jsonb_build_array(
        jwt.jwk_to_key('{"alg":"RS256", ...}'::jsonb)
    ),
    audience := 'postgresql',
    issuer := 'https://issuer.example.com',
    leeway := interval '30 seconds'
);
```

The full signature is:

```sql
jwt.decode_jwt(
    token text,
    keys jsonb,
    audience text default null,
    issuer text default null,
    leeway interval default '0 seconds',
    validate_exp boolean default true,
    validate_nbf boolean default true
)
```

> **Upgrading:** this version replaces the previous two-argument `decode_jwt`
> with the signature above and enforces `exp`/`nbf` by default. Existing
> `decode_jwt(token, keys)` calls keep working but will now reject expired or
> not-yet-valid tokens. Drop any objects that depend on the old function before
> re-running `decode_jwt.sql`.

## License

This project is licensed under the MIT License.
