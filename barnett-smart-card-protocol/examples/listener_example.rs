// use std::collections::HashMap;
// struct EventEmitter {
//     listeners: HashMap<String, Vec<Box<dyn Fn(&str)>>>,
// }

// impl EventEmitter {
//     fn new() -> Self {
//         Self {
//             listeners: HashMap::new(),
//         }
//     }

//     fn on<F>(&mut self, event: &str, callback: F)
//     where
//         F: Fn(&str) + 'static,
//     {
//         self.listeners
//             .entry(event.to_string())
//             .or_default()
//             .push(Box::new(callback));
//     }

//     fn emit(&self, event: &str, data: &str) {
//         if let Some(callbacks) = self.listeners.get(event) {
//             for callback in callbacks {
//                 callback(data);
//             }
//         }
//     }
// }


// fn main() {
//     let mut emitter = EventEmitter::new();

//     emitter.on("mensaje", |data| {
//         println!("Listener 1 recibió: {}", data);
//     });

//     emitter.on("mensaje", |data| {
//         println!("Listener 2 recibió: {}", data);
//     });

//     emitter.emit("mensaje", "¡Hola, Rust!");
// }
