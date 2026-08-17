# dksec blog

Source for <https://blog.dksec.org> — a Hugo site published from markdown.

## Writing a post

Create `content/posts/<slug>.md`:

```yaml
---
title: "Your title"
date: 2026-08-09
draft: false
tags: ["malware", "elastic"]
summary: "One line shown on the index page."
---
```

Then `git push`. The host polls this repo every 5 minutes, rebuilds with Hugo, and
serves the result. Use `draft: true` to keep a post unpublished.

## Local preview (optional)

```bash
hugo server -D
```

## Layout

| Path | Purpose |
|---|---|
| `content/posts/` | blog posts (markdown) |
| `hugo.toml` | site config |
| `themes/PaperMod/` | vendored theme — do not edit |
| `static/` | images and files served as-is |
