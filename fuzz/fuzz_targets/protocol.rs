#![no_main]
use libfuzzer_sys::fuzz_target;
use vlmcsd_protocol::{
    ActivationRequest, HostConfig, PreparedHost, Version, respond_into,
    rpc::{ClientSession, ServerSession, frame_len},
};

fn mutate(frame: &mut [u8], data: &[u8]) {
    if data.len() >= 2 {
        let length = frame.len();
        let offset = usize::from(u16::from_le_bytes([data[0], data[1]])) % length;
        for (index, byte) in data[2..].iter().enumerate() {
            frame[(offset + index) % length] ^= byte;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let host = PreparedHost::new(&HostConfig::default()).unwrap();
    let mut output = Vec::new();
    let _ = respond_into(data, &host, &mut output, [6; 16], [7; 16]);
    if let Some(header) = data.get(..16) {
        let _ = frame_len(header.try_into().unwrap());
    }
    let mut unbound = ServerSession::new(1688);
    let _ = unbound.receive(data, &host, [6; 16], [7; 16]);
    for ndr64 in [false, true] {
        let mut server = ServerSession::new(1688);
        let mut client = ClientSession::new(ndr64);
        let bind = client.start_bind().unwrap();
        let reply = server
            .receive(&bind, &host, [6; 16], [7; 16])
            .unwrap()
            .unwrap();
        // Exercise arbitrary bind acknowledgements as well as bound server calls.
        let mut malformed_client = ClientSession::new(ndr64);
        malformed_client.start_bind().unwrap();
        let _ = malformed_client.finish_bind(data);
        client.finish_bind(&reply).unwrap();
        let request =
            ActivationRequest::new([1; 16], [2; 16], [3; 16], [4; 16], 133_000_000_000_000_000);
        let mut frame = client.start_request(&request, [5; 16]).unwrap();
        let mut response = server
            .receive(&frame, &host, [6; 16], [7; 16])
            .unwrap()
            .unwrap();
        mutate(&mut response, data);
        let _ = client.receive_response(&response);
        mutate(&mut frame, data);
        let _ = server.receive(&frame, &host, [6; 16], [7; 16]);
        let _ = server.receive(data, &host, [6; 16], [7; 16]);
        // Feed multiple fragments to the same association to exercise state transitions.
        for frame in data.chunks(128).take(32) {
            let _ = server.receive(frame, &host, [6; 16], [7; 16]);
        }
        for version in [Version::V4, Version::V5, Version::V6] {
            let mut request =
                ActivationRequest::new([1; 16], [2; 16], [3; 16], [4; 16], 133_000_000_000_000_000);
            request.version = version;
            let encoded = request.encode([5; 16]).unwrap();
            let _ = encoded.verify_response(data);
        }
        let request =
            ActivationRequest::new([1; 16], [2; 16], [3; 16], [4; 16], 133_000_000_000_000_000);
        if client.is_ready() {
            client.start_request(&request, [5; 16]).unwrap();
            let _ = client.receive_response(data);
        }
    }
});
