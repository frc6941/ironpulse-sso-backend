use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use axum::extract::FromRef;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use crate::AppState;
use crate::errors::APIError;
use crate::errors::APIError::Unauthorized;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalClaims {
    pub sub: String,
    pub exp: usize
}

impl LocalClaims {
    pub fn new(uid: String) -> LocalClaims {
        LocalClaims {
            sub: uid,
            exp: SystemTime::now().add(Duration::from_mins(10))
                .duration_since(UNIX_EPOCH).unwrap().as_secs() as usize,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuthClaims {
    pub sub: String,
    pub exp: usize,
    pub client_id: String
}

impl OAuthClaims {
    pub fn new(uid: String, client_id: String) -> OAuthClaims {
        OAuthClaims {
            sub: uid,
            exp: SystemTime::now().add(Duration::from_days(5))
                .duration_since(UNIX_EPOCH).unwrap().as_secs() as usize,
            client_id
        }
    }
}

#[derive(Clone)]
pub struct JwtHelper {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey
}

impl JwtHelper {
    pub fn new() -> JwtHelper {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let encoding_key = EncodingKey::from_ed_der(doc.as_ref());

        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());

        JwtHelper {
            encoding_key,
            decoding_key,
        }
    }

    pub fn encode(&self, claims: &impl Serialize) -> String {
        jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), claims, &self.encoding_key)
            .unwrap()
    }

    pub fn decode<T: DeserializeOwned>(&self, token: &String) -> Result<TokenData<T>, APIError> {
        Ok(jsonwebtoken::decode::<T>(token, &self.decoding_key, &Validation::new(Algorithm::EdDSA))
            .map_err(|_| Unauthorized)?)
    }
}

impl FromRef<AppState> for JwtHelper {
    fn from_ref(state: &AppState) -> Self {
        state.jwt_helper.clone()
    }
}
