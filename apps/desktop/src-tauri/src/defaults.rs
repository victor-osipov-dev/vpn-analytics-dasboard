//! Built-in target list used on first launch and by "restore defaults".

use netscope_core::models::{Target, TargetCategory};

struct Seed {
    label: &'static str,
    category: TargetCategory,
    check_url: &'static str,
    host: &'static str,
    port: u16,
    priority: u8,
}

pub fn default_targets() -> Vec<Target> {
    let seeds = [
        Seed {
            label: "YouTube",
            category: TargetCategory::Video,
            check_url: "https://www.youtube.com/generate_204",
            host: "www.youtube.com",
            port: 443,
            priority: 0,
        },
        Seed {
            label: "GitHub",
            category: TargetCategory::Web,
            check_url: "https://github.com/robots.txt",
            host: "github.com",
            port: 443,
            priority: 1,
        },
        Seed {
            label: "Google",
            category: TargetCategory::Search,
            check_url: "https://www.google.com/generate_204",
            host: "www.google.com",
            port: 443,
            priority: 1,
        },
        Seed {
            label: "Cloudflare",
            category: TargetCategory::Api,
            check_url: "https://1.1.1.1/cdn-cgi/trace",
            host: "1.1.1.1",
            port: 443,
            priority: 2,
        },
        Seed {
            label: "Discord",
            category: TargetCategory::Messenger,
            check_url: "https://discord.com/api/v9/gateway",
            host: "discord.com",
            port: 443,
            priority: 2,
        },
        Seed {
            label: "Telegram",
            category: TargetCategory::Messenger,
            check_url: "https://core.telegram.org",
            host: "core.telegram.org",
            port: 443,
            priority: 3,
        },
        Seed {
            label: "Instagram",
            category: TargetCategory::Social,
            check_url: "https://www.instagram.com/favicon.ico",
            host: "www.instagram.com",
            port: 443,
            priority: 3,
        },
        Seed {
            label: "X (Twitter)",
            category: TargetCategory::Social,
            check_url: "https://x.com/favicon.ico",
            host: "x.com",
            port: 443,
            priority: 4,
        },
        Seed {
            label: "ChatGPT",
            category: TargetCategory::Ai,
            check_url: "https://chat.openai.com/favicon.ico",
            host: "chat.openai.com",
            port: 443,
            priority: 4,
        },
        Seed {
            label: "Netflix",
            category: TargetCategory::Streaming,
            check_url: "https://www.netflix.com/title/70143836",
            host: "www.netflix.com",
            port: 443,
            priority: 5,
        },
        Seed {
            label: "Steam",
            category: TargetCategory::Gaming,
            check_url: "https://store.steampowered.com/robots.txt",
            host: "store.steampowered.com",
            port: 443,
            priority: 5,
        },
        Seed {
            label: "Wikipedia",
            category: TargetCategory::Web,
            check_url: "https://en.wikipedia.org/robots.txt",
            host: "en.wikipedia.org",
            port: 443,
            priority: 6,
        },
    ];

    seeds
        .into_iter()
        .map(|s| {
            Target::single(
                s.label,
                s.category,
                s.check_url,
                s.host,
                s.port,
                s.priority,
            )
        })
        .collect()
}
