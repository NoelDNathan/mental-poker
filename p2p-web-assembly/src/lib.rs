use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

// Message types for poker communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PokerMessage {
    JoinGame { player_name: String },
    LeaveGame,
    CardAction { action: String, data: String },
    GameState { state: String },
    Chat { message: String },
    Heartbeat,
}

// Simple peer-to-peer communication
#[derive(Debug, Clone)]
pub struct PokerPeer {
    pub id: String,
    pub name: String,
    pub is_connected: bool,
}

// Global state for managing players and connections
type PlayerMap = Arc<Mutex<HashMap<String, PokerPeer>>>;

static PLAYERS: Lazy<PlayerMap> = Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

// Callback type for JavaScript integration
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

// Initialize a poker player with P2P capabilities
#[wasm_bindgen]
pub fn start_poker_player(player_name: String) -> Result<(), JsValue> {
    console_log!("Starting poker player: {}", player_name);

    let peer = PokerPeer {
        id: format!("player_{}", player_name),
        name: player_name.clone(),
        is_connected: false,
    };

    {
        let mut players = PLAYERS.lock().unwrap();
        players.insert(player_name.clone(), peer);
    }

    console_log!("Player {} initialized successfully", player_name);
    Ok(())
}

// Connect to another player via WebSocket
#[wasm_bindgen]
pub fn connect_to_player(player_name: String, target_url: String) -> Result<(), JsValue> {
    let player_name_clone = player_name.clone();
    let target_url_clone = target_url.clone();

    spawn_local(async move {
        match connect_player(&player_name_clone, &target_url_clone).await {
            Ok(_) => console_log!(
                "Player {} connected to {}",
                player_name_clone,
                target_url_clone
            ),
            Err(e) => console_log!("Error connecting player {}: {:?}", player_name_clone, e),
        }
    });
    Ok(())
}

// Send a message to a specific peer
#[wasm_bindgen]
pub fn send_message_to_peer(
    player_name: String,
    target_player: String,
    message: String,
) -> Result<(), JsValue> {
    spawn_local(async move {
        match send_message(&player_name, &target_player, &message).await {
            Ok(_) => console_log!("Message sent from {} to {}", player_name, target_player),
            Err(e) => console_log!("Error sending message: {:?}", e),
        }
    });
    Ok(())
}

// Broadcast a message to all connected peers
#[wasm_bindgen]
pub fn broadcast_message(player_name: String, message: String) -> Result<(), JsValue> {
    spawn_local(async move {
        match broadcast(&player_name, &message).await {
            Ok(_) => console_log!("Message broadcasted from {}", player_name),
            Err(e) => console_log!("Error broadcasting message: {:?}", e),
        }
    });
    Ok(())
}

// Get connected peers for a player
#[wasm_bindgen]
pub fn get_connected_peers(player_name: String) -> Result<String, JsValue> {
    let players = PLAYERS.lock().unwrap();
    if let Some(_player) = players.get(&player_name) {
        let connected_peers: Vec<String> = players
            .values()
            .filter(|p| p.is_connected && p.name != player_name)
            .map(|p| p.name.clone())
            .collect();
        Ok(serde_json::to_string(&connected_peers).unwrap_or_else(|_| "[]".to_string()))
    } else {
        Ok("[]".to_string())
    }
}

// Set up a WebSocket server for incoming connections
#[wasm_bindgen]
pub fn start_websocket_server(player_name: String, port: u16) -> Result<(), JsValue> {
    console_log!(
        "Starting WebSocket server for player {} on port {}",
        player_name,
        port
    );

    // In a real implementation, you would set up a WebSocket server
    // For this example, we'll simulate the connection
    {
        let mut players = PLAYERS.lock().unwrap();
        if let Some(player) = players.get_mut(&player_name) {
            player.is_connected = true;
        }
    }

    console_log!("WebSocket server started for player {}", player_name);
    Ok(())
}

// Create a poker message
#[wasm_bindgen]
pub fn create_poker_message(message_type: String, data: String) -> Result<String, JsValue> {
    let poker_msg = match message_type.as_str() {
        "join" => PokerMessage::JoinGame { player_name: data },
        "leave" => PokerMessage::LeaveGame,
        "card_action" => PokerMessage::CardAction {
            action: "action".to_string(),
            data,
        },
        "game_state" => PokerMessage::GameState { state: data },
        "chat" => PokerMessage::Chat { message: data },
        "heartbeat" => PokerMessage::Heartbeat,
        _ => return Err("Invalid message type".into()),
    };

    match serde_json::to_string(&poker_msg) {
        Ok(json) => Ok(json),
        Err(e) => Err(format!("Serialization error: {}", e).into()),
    }
}

// Connect to another player
async fn connect_player(
    player_name: &str,
    target_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    console_log!("Connecting player {} to {}", player_name, target_url);

    // In a real implementation, you would create a WebSocket connection
    // For this example, we'll simulate the connection
    {
        let mut players = PLAYERS.lock().unwrap();
        if let Some(player) = players.get_mut(player_name) {
            player.is_connected = true;
        }
    }

    console_log!("Player {} connected successfully", player_name);
    Ok(())
}

// Send message to specific peer
async fn send_message(
    player_name: &str,
    target_player: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let poker_msg = PokerMessage::Chat {
        message: message.to_string(),
    };
    let serialized = serde_json::to_string(&poker_msg)?;

    console_log!(
        "Sending message from {} to {}: {}",
        player_name,
        target_player,
        serialized
    );

    // In a real implementation, you would send via WebSocket
    // For this example, we'll simulate message delivery
    simulate_message_delivery(target_player, &serialized).await;

    Ok(())
}

// Broadcast message to all peers
async fn broadcast(player_name: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let poker_msg = PokerMessage::Chat {
        message: message.to_string(),
    };
    let serialized = serde_json::to_string(&poker_msg)?;

    console_log!("Broadcasting message from {}: {}", player_name, serialized);

    // Get all connected players except the sender
    let players = PLAYERS.lock().unwrap();
    let target_players: Vec<String> = players
        .values()
        .filter(|p| p.is_connected && p.name != player_name)
        .map(|p| p.name.clone())
        .collect();

    // Simulate message delivery to all players
    for target in target_players {
        simulate_message_delivery(&target, &serialized).await;
    }

    Ok(())
}

// Simulate message delivery (in real implementation, this would be WebSocket)
async fn simulate_message_delivery(target_player: &str, message: &str) {
    console_log!("Delivering message to {}: {}", target_player, message);
}

// Utility function to get player info
#[wasm_bindgen]
pub fn get_player_info(player_name: String) -> Result<String, JsValue> {
    let players = PLAYERS.lock().unwrap();
    if let Some(player) = players.get(&player_name) {
        let info = serde_json::json!({
            "id": player.id,
            "name": player.name,
            "is_connected": player.is_connected
        });
        Ok(serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string()))
    } else {
        Err("Player not found".into())
    }
}

// Utility function to list all players
#[wasm_bindgen]
pub fn list_all_players() -> Result<String, JsValue> {
    let players = PLAYERS.lock().unwrap();
    let player_list: Vec<serde_json::Value> = players
        .values()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "is_connected": p.is_connected
            })
        })
        .collect();

    Ok(serde_json::to_string(&player_list).unwrap_or_else(|_| "[]".to_string()))
}

// Clean up player
#[wasm_bindgen]
pub fn remove_player(player_name: String) -> Result<(), JsValue> {
    let mut players = PLAYERS.lock().unwrap();
    players.remove(&player_name);
    console_log!("Player {} removed", player_name);
    Ok(())
}
