use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PlayerInfo {
    peer_id: String,
    address: String,
}

#[derive(Clone)]
struct AppState {
    players: Arc<Mutex<HashMap<String, PlayerInfo>>>, // Almacena los jugadores
}

#[tokio::main]
async fn main() {
    let state = AppState {
        players: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/register", post(register_player))
        .route("/get_peers/:peer_id", get(get_peers))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Servidor en http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

// 📌 Endpoint: Registrar un jugador
async fn register_player(
    State(state): State<AppState>,
    Json(player): Json<PlayerInfo>,
) -> StatusCode {
    let mut players = state.players.lock().unwrap();
    players.insert(player.peer_id.clone(), player);
    StatusCode::OK
}

// 📌 Endpoint: Obtener jugadores permitidos
async fn get_peers(State(state): State<AppState>, peer_id: axum::extract::Path<String>) -> Json<Vec<PlayerInfo>> {
    let players = state.players.lock().unwrap();
    
    // 📌 Lógica de autorización: solo devolver jugadores de la misma mesa (simplificado)
    let allowed_peers: Vec<PlayerInfo> = players
        .values()
        .filter(|p| &p.peer_id != &*peer_id) // No devolvemos el mismo jugador
        .cloned()
        .collect();

    Json(allowed_peers)
}
