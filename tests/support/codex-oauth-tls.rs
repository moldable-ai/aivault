#[test]
fn e2e_codex_401_refresh_retries_buffered_and_streaming_without_other_accounts() {
    for raw in [false, true] {
        let server = LocalTlsEchoServer::start("chatgpt.com");
        let mut envs = server.env_pairs();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        envs.push(("AIVAULT_DEV_ALLOW_HTTP_LOCAL".to_string(), "1".to_string()));
        envs.push((
            "AIVAULT_DEV_CODEX_OAUTH_TOKEN_ENDPOINT".to_string(),
            format!("http://{}/oauth/token", listener.local_addr().unwrap()),
        ));
        let token_server = thread::spawn(move || {
            let start = Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            start.elapsed() < Duration::from_secs(10),
                            "refresh never arrived"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            let body = r#"{"access_token":"at-2","refresh_token":"rt-2","expires_in":3600}"#;
            std::io::Write::write_all(&mut stream, format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
        });
        let dir = TempDir::new().unwrap();
        let valid_until = chrono::Utc::now().timestamp_millis() + 3_600_000;
        create_secret(
            &dir,
            &envs,
            "CODEX_OAUTH_JSON",
            &format!(
                r#"{{"access_token":"at-1","refresh_token":"rt-1","expires_at":{valid_until},"account_id":"account"}}"#
            ),
        );
        run_ok_json(
            &dir,
            &[
                "secrets",
                "create",
                "--name",
                "CODEX_OAUTH_JSON",
                "--value",
                r#"{"access_token":"broken","expires_at":0,"account_id":"other"}"#,
                "--scope",
                "group",
                "--workspace-id",
                "other",
                "--group-id",
                "broken",
            ],
            &envs,
        );
        let mut args = vec![
            "invoke",
            "openai/codex-usage",
            "--credential",
            "openai:codex-oauth-usage",
            "--method",
            "GET",
            "--path",
            "/wham/usage",
        ];
        if raw {
            args.push("--stream");
            let result = run_aivault_raw(&dir, &args, &envs);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let response: Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(response["headers"]["authorization"], "Bearer at-2");
        } else {
            let response = run_ok_json(&dir, &args, &envs);
            assert_eq!(response["response"]["status"], 200);
            assert_eq!(
                response["response"]["json"]["headers"]["authorization"],
                "Bearer at-2"
            );
        }
        token_server.join().unwrap();
        let captured = server.captured_requests();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].headers["authorization"], "Bearer at-1");
        assert_eq!(captured[1].headers["authorization"], "Bearer at-2");
    }
}
