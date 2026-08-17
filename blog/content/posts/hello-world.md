---
title: "Setting up the lab blog"
date: 2026-08-09
draft: false
tags: ["meta", "hugo"]
summary: "How this blog is built and published — markdown in GitHub, Hugo in Docker, Cloudflare Tunnel out front."
---

First post. This blog is written as markdown files in a public GitHub repository and
published automatically — no CMS, no database, no admin panel to log into.

## How publishing works

```text
write post.md  ->  git push
                     |
     host pulls the repo every 5 minutes
                     |
              hugo rebuilds the site
                     |
        nginx  ->  Cloudflare Tunnel  ->  blog.dksec.org
```

The whole site is static HTML. Nothing on the host is reachable from the internet
except through an outbound-only tunnel, and the blog itself is deliberately public —
no authentication in front of it.

## Writing a post

Drop a markdown file into `content/posts/` with front-matter:

```yaml
---
title: "Your title"
date: 2026-08-09
draft: false
tags: ["malware", "elastic"]
summary: "One line shown on the index page."
---
```

Set `draft: true` while writing — drafts are not built into the published site.

## What to expect here

Write-ups from a home malware lab: detonating samples in an isolated Windows VM,
reconstructing behaviour from Sysmon and Elastic Defend telemetry, and the detection
engineering that follows.
