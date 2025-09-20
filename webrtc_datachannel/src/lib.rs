use js_sys::Reflect;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    HtmlButtonElement, MessageEvent, RtcDataChannelEvent, RtcPeerConnection,
    RtcPeerConnectionIceEvent, RtcSdpType, RtcSessionDescriptionInit,
};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console)]
    fn warn(s: &str);
}

// Simple demo that creates two clients sequentially
#[wasm_bindgen(start)]
pub async fn start() -> Result<(), JsValue> {
    log("WebRTC Sequential Demo Started");
    setup_ui()?;
    Ok(())
}

#[wasm_bindgen]
pub async fn run_sequential_demo() -> Result<(), JsValue> {
    log("Starting sequential WebRTC demo...");

    // Step 1: Initialize Client 1 (Offerer)
    log("Step 1: Initializing Client 1 (Offerer)");
    let pc1 = RtcPeerConnection::new()?;
    log(&format!("pc1 created: state {:?}", pc1.signaling_state()));

    // Create DataChannel on pc1
    let dc1 = pc1.create_data_channel("my-data-channel");
    log(&format!("dc1 created: label {:?}", dc1.label()));

    // Set up message handler for dc1
    let dc1_clone = dc1.clone();
    let onmessage_callback = Closure::<dyn FnMut(_)>::new(move |ev: MessageEvent| {
        if let Some(message) = ev.data().as_string() {
            warn(&format!("pc1 received: {:?}", message));
            let _ = dc1_clone.send_with_str("Pong from pc1.dc!");
        }
    });
    dc1.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    onmessage_callback.forget();

    // Step 2: Initialize Client 2 (Answerer)
    log("Step 2: Initializing Client 2 (Answerer)");
    let pc2 = RtcPeerConnection::new()?;
    log(&format!("pc2 created: state {:?}", pc2.signaling_state()));

    // Set up data channel handler for pc2
    let ondatachannel_callback = Closure::<dyn FnMut(_)>::new(move |ev: RtcDataChannelEvent| {
        let dc2 = ev.channel();
        log(&format!("pc2.ondatachannel!: {:?}", dc2.label()));

        let onmessage_callback = Closure::<dyn FnMut(_)>::new(move |ev: MessageEvent| {
            if let Some(message) = ev.data().as_string() {
                warn(&format!("pc2 received: {:?}", message));
            }
        });
        dc2.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
        onmessage_callback.forget();

        let dc2_clone = dc2.clone();
        let onopen_callback = Closure::<dyn FnMut()>::new(move || {
            log("Data channel opened on pc2!");
            let _ = dc2_clone.send_with_str("Ping from pc2.dc!");
        });
        dc2.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
        onopen_callback.forget();
    });
    pc2.set_ondatachannel(Some(ondatachannel_callback.as_ref().unchecked_ref()));
    ondatachannel_callback.forget();

    // Step 3: Establish Connection
    log("Step 3: Establishing WebRTC connection...");

    // Set up ICE candidate handling
    let pc2_clone = pc2.clone();
    let onicecandidate_callback1 =
        Closure::<dyn FnMut(_)>::new(move |ev: RtcPeerConnectionIceEvent| {
            if let Some(candidate) = ev.candidate() {
                log(&format!("pc1.onicecandidate: {:#?}", candidate.candidate()));
                let _ = pc2_clone.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&candidate));
            }
        });
    pc1.set_onicecandidate(Some(onicecandidate_callback1.as_ref().unchecked_ref()));
    onicecandidate_callback1.forget();

    let pc1_clone = pc1.clone();
    let onicecandidate_callback2 =
        Closure::<dyn FnMut(_)>::new(move |ev: RtcPeerConnectionIceEvent| {
            if let Some(candidate) = ev.candidate() {
                log(&format!("pc2.onicecandidate: {:#?}", candidate.candidate()));
                let _ = pc1_clone.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&candidate));
            }
        });
    pc2.set_onicecandidate(Some(onicecandidate_callback2.as_ref().unchecked_ref()));
    onicecandidate_callback2.forget();

    // Create and send offer from pc1
    let offer = JsFuture::from(pc1.create_offer()).await?;
    let offer_sdp = Reflect::get(&offer, &JsValue::from_str("sdp"))?
        .as_string()
        .unwrap();
    log("pc1: offer created");

    let offer_obj = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    offer_obj.set_sdp(&offer_sdp);
    let sld_promise = pc1.set_local_description(&offer_obj);
    JsFuture::from(sld_promise).await?;
    log(&format!(
        "pc1: local description set, state {:?}",
        pc1.signaling_state()
    ));

    // Set remote description on pc2
    let offer_obj = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    offer_obj.set_sdp(&offer_sdp);
    let srd_promise = pc2.set_remote_description(&offer_obj);
    JsFuture::from(srd_promise).await?;
    log(&format!(
        "pc2: remote description set, state {:?}",
        pc2.signaling_state()
    ));

    // Create and send answer from pc2
    let answer = JsFuture::from(pc2.create_answer()).await?;
    let answer_sdp = Reflect::get(&answer, &JsValue::from_str("sdp"))?
        .as_string()
        .unwrap();
    log("pc2: answer created");

    let answer_obj = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    answer_obj.set_sdp(&answer_sdp);
    let sld_promise = pc2.set_local_description(&answer_obj);
    JsFuture::from(sld_promise).await?;
    log(&format!(
        "pc2: local description set, state {:?}",
        pc2.signaling_state()
    ));

    // Set remote description on pc1
    let answer_obj = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    answer_obj.set_sdp(&answer_sdp);
    let srd_promise = pc1.set_remote_description(&answer_obj);
    JsFuture::from(srd_promise).await?;
    log(&format!(
        "pc1: remote description set, state {:?}",
        pc1.signaling_state()
    ));

    log("WebRTC connection established successfully!");
    log("Sequential demo completed! Check the console for message exchanges.");

    Ok(())
}

fn setup_ui() -> Result<(), JsValue> {
    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();
    let body = document.body().unwrap();

    // Create container
    let container = document.create_element("div")?;
    container.set_attribute("style", "padding: 20px; font-family: Arial, sans-serif;")?;

    // Create title
    let title = document.create_element("h1")?;
    title.set_text_content(Some("WebRTC Sequential Initialization Demo"));
    container.append_child(&title)?;

    // Create instructions
    let instructions = document.create_element("p")?;
    instructions.set_text_content(Some(
        "This demo initializes two WebRTC clients sequentially:",
    ));
    container.append_child(&instructions)?;

    let steps = document.create_element("ol")?;
    let step1 = document.create_element("li")?;
    step1.set_text_content(Some(
        "Initialize Client 1 (Offerer) - creates peer connection and data channel",
    ));
    let step2 = document.create_element("li")?;
    step2.set_text_content(Some(
        "Initialize Client 2 (Answerer) - creates peer connection and sets up handlers",
    ));
    let step3 = document.create_element("li")?;
    step3.set_text_content(Some(
        "Establish Connection - performs offer/answer exchange and ICE negotiation",
    ));
    steps.append_child(&step1)?;
    steps.append_child(&step2)?;
    steps.append_child(&step3)?;
    container.append_child(&steps)?;

    // Create run button
    let button = document
        .create_element("button")?
        .dyn_into::<HtmlButtonElement>()?;
    button.set_text_content(Some("🚀 Run Sequential Demo"));
    button.set_attribute("style", "margin: 20px 0; padding: 15px 30px; background: linear-gradient(45deg, #4CAF50, #45a049); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; box-shadow: 0 4px 8px rgba(0,0,0,0.2);")?;

    let onclick = Closure::<dyn FnMut()>::new(move || {
        wasm_bindgen_futures::spawn_local(async move {
            match run_sequential_demo().await {
                Ok(_) => log("Sequential demo completed successfully!"),
                Err(e) => warn(&format!("Demo failed: {:?}", e)),
            }
        });
    });
    button.set_onclick(Some(onclick.as_ref().unchecked_ref()));
    onclick.forget();

    container.append_child(&button)?;

    // Add status area
    let status = document.create_element("div")?;
    status.set_attribute("style", "margin-top: 20px; padding: 15px; background: #f8f9fa; border-left: 4px solid #007bff; border-radius: 4px;")?;
    status.set_text_content(Some("ℹ️ Status: Ready to start. Open DevTools (F12) and check the Console for detailed logs during execution."));
    container.append_child(&status)?;

    body.append_child(&container)?;
    Ok(())
}
