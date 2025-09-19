# Poker P2P WebAssembly

This project implements peer-to-peer communication for poker games using libp2p and WebAssembly (WASM). It provides a WebRTC-based transport layer that's compatible with web browsers and enables direct communication between poker players without a central server.

## Features

- **WebRTC Transport**: WASM-compatible peer-to-peer connections
- **Gossipsub Protocol**: Efficient message broadcasting and subscription
- **Peer Discovery**: Automatic peer identification and connection management
- **Message Types**: Structured poker game messages (join, leave, card actions, etc.)
- **JavaScript Integration**: Easy-to-use bindings for web applications
- **Real-time Communication**: Low-latency messaging between players

## Architecture

### Core Components

1. **PokerBehaviour**: Combines multiple libp2p protocols:
   - Gossipsub for message broadcasting
   - Identify for peer identification
   - Ping for connection health monitoring

2. **PokerMessage**: Structured message types for poker communication:
   - `JoinGame`: Player joining a game
   - `LeaveGame`: Player leaving a game
   - `CardAction`: Card-related actions (bet, fold, etc.)
   - `GameState`: Game state updates
   - `Chat`: Chat messages between players
   - `Heartbeat`: Connection health checks

3. **WebAssembly Bindings**: JavaScript functions for easy integration:
   - `start_poker_player()`: Initialize a new player
   - `send_message_to_peer()`: Send direct message to specific peer
   - `broadcast_message()`: Broadcast message to all connected peers
   - `get_connected_peers()`: Get list of connected peers
   - `create_poker_message()`: Create structured poker messages

## Prerequisites

- Rust 1.70+
- wasm-pack
- Node.js (for serving the example)

## Installation

1. Install wasm-pack:
```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

2. Install dependencies:
```bash
cd p2p-web-assembly
cargo install wasm-pack
```

## Building

Build the WebAssembly module:

```bash
wasm-pack build --target web --out-dir pkg
```

This will create the compiled WASM files in the `pkg/` directory.

## Usage

### Basic Setup

1. Include the generated JavaScript module in your HTML:

```html
<script type="module">
    import init, { 
        start_poker_player, 
        send_message_to_peer, 
        broadcast_message, 
        get_connected_peers 
    } from './pkg/p2p_web_assembly.js';

    // Initialize the module
    await init();

    // Start a poker player
    start_poker_player("Alice");
</script>
```

### Player Management

```javascript
// Start a new player
start_poker_player("PlayerName");

// Get connected peers
const peers = get_connected_peers("PlayerName");
console.log("Connected peers:", JSON.parse(peers));
```

### Message Communication

```javascript
// Send message to specific peer
send_message_to_peer("SenderName", "TargetPeerId", "Hello!");

// Broadcast message to all peers
broadcast_message("SenderName", "Game update message");

// Create structured poker message
const pokerMsg = create_poker_message("join", "PlayerName");
```

### Example Implementation

See `example.html` for a complete working example that demonstrates:
- Starting multiple players
- Peer discovery and connection
- Message sending and broadcasting
- Real-time communication between players

## Running the Example

1. Build the project:
```bash
wasm-pack build --target web --out-dir pkg
```

2. Serve the example (requires a local server due to CORS):
```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx serve .

# Using any other static file server
```

3. Open `http://localhost:8000/example.html` in your browser

## WebRTC Configuration

The implementation uses WebRTC for peer-to-peer connections, which requires:

1. **HTTPS or localhost**: WebRTC requires a secure context
2. **STUN/TURN servers**: For NAT traversal (optional for local testing)
3. **Browser compatibility**: Modern browsers with WebRTC support

### STUN Server Configuration

To enable connections across different networks, configure STUN servers:

```rust
let webrtc_config = webrtc::Config {
    stun_servers: vec!["stun:stun.l.google.com:19302".parse()?],
    ..Default::default()
};
```

## Message Protocol

### PokerMessage Structure

```rust
pub enum PokerMessage {
    JoinGame { player_name: String },
    LeaveGame,
    CardAction { action: String, data: String },
    GameState { state: String },
    Chat { message: String },
    Heartbeat,
}
```

### Gossipsub Topics

- `poker-game`: Main game communication channel
- Messages are automatically signed and verified
- Supports message deduplication and ordering

## Limitations and Considerations

### WebAssembly Limitations

1. **No direct file system access**: Use browser APIs for persistence
2. **Limited threading**: Single-threaded execution model
3. **Memory constraints**: Limited heap size in browsers
4. **Network restrictions**: CORS and security policies apply

### libp2p WASM Compatibility

Not all libp2p features are available in WASM:
- ✅ WebRTC transport
- ✅ Gossipsub protocol
- ✅ Identify protocol
- ✅ Ping protocol
- ❌ TCP transport (not available in browsers)
- ❌ MDNS discovery (limited browser support)
- ❌ QUIC transport (experimental)

### Performance Considerations

1. **Message size**: Keep messages small for better performance
2. **Connection limits**: Browsers limit concurrent WebRTC connections
3. **Memory usage**: Monitor memory consumption in long-running games
4. **Network latency**: WebRTC adds overhead compared to direct TCP

## Troubleshooting

### Common Issues

1. **Connection failures**: Ensure HTTPS or localhost environment
2. **STUN server errors**: Check network connectivity and firewall settings
3. **Memory errors**: Reduce message frequency or size
4. **Build errors**: Ensure all dependencies are properly installed

### Debug Mode

Enable debug logging by setting the log level:

```javascript
// In browser console
localStorage.setItem('debug', 'libp2p:*');
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- libp2p team for the excellent P2P networking library
- WebAssembly community for WASM support
- Rust community for the amazing ecosystem
