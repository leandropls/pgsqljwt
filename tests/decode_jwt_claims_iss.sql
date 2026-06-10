select jwt.decode_jwt(
    token := :token,
    keys := jsonb_build_array(
       jwt.jwk_to_key(:jwk)
    ),
    issuer := 'https://example.com'
) as decode_jwt_claims_iss;
