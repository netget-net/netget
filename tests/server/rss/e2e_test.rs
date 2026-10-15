//! E2E tests for RSS protocol
//!
//! These tests verify RSS server functionality by starting NetGet with RSS prompts
//! and using reqwest HTTP client to fetch and parse RSS feeds.


use crate::server::helpers::*;
use std::time::Duration;

#[tokio::test]
async fn test_rss_comprehensive() -> E2EResult<()> {
    // Single comprehensive server that serves multiple RSS feeds
    let config = NetGetConfig::new(
        r#"listen on port 0 via rss

You are an RSS feed server. Generate RSS 2.0 XML feeds dynamically for each request.

FEEDS TO SERVE:

/tech-news.xml - Technology News Feed
- Title: "Tech News Daily"
- Link: "https://technews.example.com"
- Description: "Latest technology news and updates"
- Language: "en-us"
- TTL: "60"
- Items (3):
  1. Title: "New AI Model Released"
     Link: "https://technews.example.com/ai-model"
     Description: "Company X released groundbreaking AI model"
     Author: "editor@technews.example.com (Tech Editor)"
     Pub Date: "Mon, 09 Nov 2025 10:00:00 GMT"
     Categories: ["AI", "Machine Learning", {"name": "Deep Learning", "domain": "ai.example.com"}]

  2. Title: "Cloud Computing Trends 2025"
     Link: "https://technews.example.com/cloud-trends"
     Description: "Analysis of cloud computing market trends"
     Pub Date: "Mon, 09 Nov 2025 09:00:00 GMT"
     Categories: ["Cloud", "Infrastructure"]

  3. Title: "Quantum Computing Breakthrough"
     Link: "https://technews.example.com/quantum"
     Description: "Researchers achieve quantum supremacy milestone"
     Pub Date: "Mon, 09 Nov 2025 08:00:00 GMT"
     Categories: ["Quantum", "Research", "Science"]

/sports.xml - Sports Feed
- Title: "Sports Headlines"
- Link: "https://sports.example.com"
- Description: "Latest sports news"
- Items (2):
  1. Title: "Championship Game Results"
     Link: "https://sports.example.com/championship"
     Description: "Final score and game highlights"
     Pub Date: "Mon, 09 Nov 2025 11:00:00 GMT"
     Categories: ["Football", "Championships"]

  2. Title: "Transfer News Update"
     Link: "https://sports.example.com/transfers"
     Description: "Latest player transfer announcements"
     Pub Date: "Mon, 09 Nov 2025 10:30:00 GMT"
     Categories: ["Soccer", "Transfers"]

/blog.xml - Personal Blog Feed
- Title: "My Dev Blog"
- Link: "https://myblog.example.com"
- Description: "Software development tutorials and insights"
- Items (2):
  1. Title: "Getting Started with Rust"
     Link: "https://myblog.example.com/rust-intro"
     Description: "A beginner's guide to Rust programming"
     Author: "john@example.com (John Doe)"
     Pub Date: "Sun, 08 Nov 2025 15:00:00 GMT"
     GUID: "https://myblog.example.com/rust-intro"
     Categories: ["Rust", "Programming", "Tutorial"]

  2. Title: "Understanding RSS Feeds"
     Link: "https://myblog.example.com/rss-guide"
     Description: "How RSS feeds work and why they matter"
     Pub Date: "Sat, 07 Nov 2025 12:00:00 GMT"
     GUID: "https://myblog.example.com/rss-guide"
     Categories: ["Web", "RSS"]

For any other path: Return 404 Not Found

IMPORTANT: Respond with the generate_rss_feed action containing all the feed data as structured JSON.
"#,
    )
    .with_log_level("debug") // Use debug to see LLM interactions
    .with_mock(|mock| {
        mock
            // Mock 1: GET /tech-news.xml - MUST BE FIRST (most specific)
            .on_event("rss_feed_requested")
            .and_event_data_contains("path", "/tech-news.xml")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "generate_rss_feed",
                    "title": "Tech News Daily",
                    "link": "https://technews.example.com",
                    "description": "Latest technology news and updates",
                    "language": "en-us",
                    "ttl": 60,
                    "items": [
                        {
                            "title": "New AI Model Released",
                            "link": "https://technews.example.com/ai-model",
                            "description": "Company X released groundbreaking AI model",
                            "author": "editor@technews.example.com (Tech Editor)",
                            "pub_date": "Mon, 09 Nov 2025 10:00:00 GMT",
                            "categories": ["AI", "Machine Learning", "Deep Learning"]
                        },
                        {
                            "title": "Cloud Computing Trends 2025",
                            "link": "https://technews.example.com/cloud-trends",
                            "description": "Analysis of cloud computing market trends",
                            "pub_date": "Mon, 09 Nov 2025 09:00:00 GMT",
                            "categories": ["Cloud", "Infrastructure"]
                        },
                        {
                            "title": "Quantum Computing Breakthrough",
                            "link": "https://technews.example.com/quantum",
                            "description": "Researchers achieve quantum supremacy milestone",
                            "pub_date": "Mon, 09 Nov 2025 08:00:00 GMT",
                            "categories": ["Quantum", "Research", "Science"]
                        }
                    ]
                }
            ]))
            .expect_calls(2)
            .and()
            // Mock 2: GET /sports.xml - MUST BE SECOND (most specific)
            .on_event("rss_feed_requested")
            .and_event_data_contains("path", "/sports.xml")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "generate_rss_feed",
                    "title": "Sports Headlines",
                    "link": "https://sports.example.com",
                    "description": "Latest sports news",
                    "items": [
                        {
                            "title": "Championship Game Results",
                            "link": "https://sports.example.com/championship",
                            "description": "Final score and game highlights",
                            "pub_date": "Mon, 09 Nov 2025 11:00:00 GMT",
                            "categories": ["Football", "Championships"]
                        },
                        {
                            "title": "Transfer News Update",
                            "link": "https://sports.example.com/transfers",
                            "description": "Latest player transfer announcements",
                            "pub_date": "Mon, 09 Nov 2025 10:30:00 GMT",
                            "categories": ["Soccer", "Transfers"]
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: GET /blog.xml - MUST BE THIRD (most specific)
            .on_event("rss_feed_requested")
            .and_event_data_contains("path", "/blog.xml")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "generate_rss_feed",
                    "title": "My Dev Blog",
                    "link": "https://myblog.example.com",
                    "description": "Software development tutorials and insights",
                    "items": [
                        {
                            "title": "Getting Started with Rust",
                            "link": "https://myblog.example.com/rust-intro",
                            "description": "A beginner's guide to Rust programming",
                            "author": "john@example.com (John Doe)",
                            "pub_date": "Sun, 08 Nov 2025 15:00:00 GMT",
                            "guid": "https://myblog.example.com/rust-intro",
                            "categories": ["Rust", "Programming", "Tutorial"]
                        },
                        {
                            "title": "Understanding RSS Feeds",
                            "link": "https://myblog.example.com/rss-guide",
                            "description": "How RSS feeds work and why they matter",
                            "pub_date": "Sat, 07 Nov 2025 12:00:00 GMT",
                            "guid": "https://myblog.example.com/rss-guide",
                            "categories": ["Web", "RSS"]
                        }
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: GET /nonexistent.xml (404) - MUST BE FOURTH (most specific)
            .on_event("rss_feed_requested")
            .and_event_data_contains("path", "/nonexistent.xml")
            // RSS has one verb, `generate_rss_feed`, and no error action — "not found" is
            // expressed by producing no feed, which the server answers with 404. That fallback
            // is the fail-closed direction (it withholds a feed rather than inventing one), so
            // unlike the S3 empty-200 case it is the right answer rather than a gap.
            //
            // This used to answer `send_http_response`, which RSS cannot execute:
            // tests/helpers/mock_action_names.rs rejects it, so the test failed before the
            // server was ever reached.
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            // Mock 5: Server startup - MUST BE LAST (less specific)
            .on_instruction_containing("listen")
            .and_instruction_containing("rss")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "RSS",
                    "instruction": "RSS feed server - generate feeds dynamically"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let test_state = start_netget_server(config).await?;

    // `start_netget_server` returns when startup has been *parsed*, not when the socket is
    // bound, so something has to wait. A fixed two-second sleep is enough when this test runs
    // alone and is not when a hundred run together; wait for the listener instead.
    let base_url = format!("http://127.0.0.1:{}", test_state.port);
    wait_until_listening(test_state.port).await?;

    println!("✓ RSS server started on port {}", test_state.port);
    println!("  Base URL: {}", base_url);

    // Test 1: Fetch tech-news.xml feed
    println!("\n[Test 1] Fetch tech news feed (/tech-news.xml)");
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/tech-news.xml", base_url))
        .send()
        .await?;

    assert_eq!(response.status(), 200, "Expected 200 OK for tech-news.xml");
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("application/rss+xml; charset=utf-8"),
        "Expected RSS XML content type"
    );

    let body = response.text().await?;
    println!("Response length: {} bytes", body.len());
    println!(
        "First 500 chars:\n{}",
        &body.chars().take(500).collect::<String>()
    );

    // Verify RSS structure
    assert!(body.contains("<rss"), "Expected <rss tag");
    assert!(body.contains("version=\"2.0\""), "Expected RSS 2.0 version");
    assert!(body.contains("Tech News Daily"), "Expected feed title");
    assert!(
        body.contains("https://technews.example.com"),
        "Expected feed link"
    );
    assert!(
        body.contains("New AI Model Released"),
        "Expected first item title"
    );
    assert!(
        body.contains("Cloud Computing Trends"),
        "Expected second item"
    );
    assert!(body.contains("Quantum Computing"), "Expected third item");

    // Verify categories
    assert!(
        body.contains("<category>AI</category>")
            || body.contains("<category domain=\"\">AI</category>"),
        "Expected AI category"
    );
    assert!(body.contains("Machine Learning"), "Expected ML category");
    assert!(
        body.contains("Deep Learning"),
        "Expected Deep Learning category"
    );

    println!("✓ Tech news feed structure valid");
    println!("✓ Contains 3 items with categories");

    // Test 2: Fetch sports.xml feed
    println!("\n[Test 2] Fetch sports feed (/sports.xml)");
    let response = client
        .get(format!("{}/sports.xml", base_url))
        .send()
        .await?;

    assert_eq!(response.status(), 200, "Expected 200 OK for sports.xml");

    let body = response.text().await?;
    println!("Response length: {} bytes", body.len());

    assert!(
        body.contains("Sports Headlines"),
        "Expected sports feed title"
    );
    assert!(
        body.contains("Championship Game"),
        "Expected championship item"
    );
    assert!(body.contains("Transfer News"), "Expected transfer item");
    assert!(
        body.contains("<category>Football</category>") || body.contains("Football"),
        "Expected Football category"
    );

    println!("✓ Sports feed structure valid");
    println!("✓ Contains 2 items with categories");

    // Test 3: Fetch blog.xml feed
    println!("\n[Test 3] Fetch blog feed (/blog.xml)");
    let response = client.get(format!("{}/blog.xml", base_url)).send().await?;

    assert_eq!(response.status(), 200, "Expected 200 OK for blog.xml");

    let body = response.text().await?;
    println!("Response length: {} bytes", body.len());

    assert!(body.contains("My Dev Blog"), "Expected blog title");
    assert!(
        body.contains("Getting Started with Rust"),
        "Expected Rust post"
    );
    assert!(
        body.contains("Understanding RSS Feeds"),
        "Expected RSS post"
    );
    assert!(body.contains("<guid"), "Expected GUID tags");
    assert!(body.contains("john@example.com"), "Expected author");
    assert!(
        body.contains("<category>Rust</category>") || body.contains("Rust"),
        "Expected Rust category"
    );

    println!("✓ Blog feed structure valid");
    println!("✓ Contains author and GUID fields");
    println!("✓ Contains categories");

    // Test 4: Try to fetch non-existent feed (should return 404)
    println!("\n[Test 4] Fetch non-existent feed (/nonexistent.xml)");
    let response = client
        .get(format!("{}/nonexistent.xml", base_url))
        .send()
        .await?;

    assert_eq!(response.status(), 404, "Expected 404 for non-existent feed");
    println!("✓ Non-existent feed returns 404");

    // Test 5: Parse the served feed with an INDEPENDENT parser.
    //
    // This used to parse with `rss::Channel::read_from`, which proved nothing: the server
    // builds the XML with that same crate's `ChannelBuilder`, so the assertion was that one
    // crate round-trips through itself. Any RSS 2.0 element the server omits, mislabels or
    // nests wrongly would survive such a round trip as long as `rss` was self-consistent.
    //
    // `feed-rs` is a separate implementation with its own normalised model (it reads RSS 0.9x,
    // RSS 1.0/2.0, Atom and JSON Feed into one `Feed` type), so what it accepts is evidence
    // about the bytes on the wire rather than about the `rss` crate.
    println!("\n[Test 5] Verify feeds parse with feed-rs, an independent parser");
    let response = client
        .get(format!("{}/tech-news.xml", base_url))
        .send()
        .await?;

    let body = response.text().await?;
    let feed = feed_rs::parser::parse(body.as_bytes())
        .map_err(|e| format!("feed-rs rejected the served feed: {e}\n---\n{body}"))?;

    assert_eq!(
        feed.feed_type,
        feed_rs::model::FeedType::RSS2,
        "feed-rs must recognise this as RSS 2.0, not fall back to another dialect"
    );
    assert_eq!(
        feed.title.as_ref().map(|t| t.content.as_str()),
        Some("Tech News Daily"),
        "channel title"
    );
    assert_eq!(
        feed.description.as_ref().map(|t| t.content.as_str()),
        Some("Latest technology news and updates"),
        "channel description"
    );
    assert_eq!(
        feed.language.as_deref(),
        Some("en-us"),
        "channel language must survive as an element feed-rs can read"
    );
    assert_eq!(feed.entries.len(), 3, "expected 3 items");

    let first = &feed.entries[0];
    assert_eq!(
        first.title.as_ref().map(|t| t.content.as_str()),
        Some("New AI Model Released"),
        "first item title"
    );
    assert_eq!(
        first.links.first().map(|l| l.href.as_str()),
        Some("https://technews.example.com/ai-model"),
        "first item link"
    );
    assert!(
        first.published.is_some(),
        "first item pub_date must be an RFC 2822 date a foreign parser can read; \
         feed-rs drops dates it cannot parse rather than erroring"
    );
    let categories: Vec<&str> = first.categories.iter().map(|c| c.term.as_str()).collect();
    assert!(
        categories.contains(&"AI") && categories.contains(&"Machine Learning"),
        "categories must be readable by an independent parser, got {categories:?}"
    );

    println!("✓ feed-rs parsed the served XML as RSS 2.0");
    println!("✓ Channel metadata, item links, dates and categories all readable");

    println!("\n✅ All RSS tests passed!");
    println!("   Total LLM calls: ~6 (3 successful feeds + 1 404 + 2 repeat fetches)");
    println!("   All feeds generated dynamically by LLM");
    println!("   Categories properly rendered");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    test_state.wait_for_mocks(30).await;
    test_state.verify_mocks().await?;

    Ok(())
}

/// Poll until the RSS server's TCP port accepts a connection.
///
/// A condition, not a duration: the deadline is generous because it only ever expires when
/// something is actually wrong, and the loop exits the moment the socket is up.
async fn wait_until_listening(port: u16) -> E2EResult<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(_) => return Ok(()),
            Err(e) if std::time::Instant::now() >= deadline => {
                return Err(format!("RSS server never bound port {port}: {e}").into())
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
}
