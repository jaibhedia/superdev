use axum::{
    async_trait,
    extract::{FromRequest, Request},
    http::StatusCode,
    response::Json,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

pub struct JsonExtractor<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for JsonExtractor<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let json_extractor = axum::extract::Json::<T>::from_request(req, state).await;
        
        match json_extractor {
            Ok(axum::extract::Json(data)) => Ok(JsonExtractor(data)),
            Err(rejection) => {
                let error_response = Json(json!({
                    "success": false,
                    "error": format!("Invalid JSON: {}", rejection)
                }));
                Err((StatusCode::BAD_REQUEST, error_response))
            }
        }
    }
}
