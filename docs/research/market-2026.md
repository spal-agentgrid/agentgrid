# AI-agent tool / API / MCP market — Sep 30, 2026 snapshot

Estimates are marked **(est.)**. Everything else has a source URL. Checked Sep 30, 2026.

## 1. Supply: MCP registries & directories
| Directory | Reported size | Source |
|---|---|---|
| Official MCP Registry (preview) | 36,932 servers (Sep 29); a full walk on Sep 24 found 35,491 servers from 20,581 publishers | https://agenteconomy.to/stats/how-many-mcp-servers-are-there , https://specialeventclub.com/2026/09/27/we-analyzed-the-mcp-registry-most-servers-stop-updating/ |
| Glama | 88,162 servers / 820,840 tools (indexed Sep 16) | https://glama.ai/ |
| Smithery | 17,598 servers | https://agenteconomy.to/stats/how-many-mcp-servers-are-there |
| PulseMCP | 16,998 servers | https://www.pulsemcp.com/servers/ |
| x402 paid endpoints | 782 listed, 687 payment-ready, 11 delivery-verified (Sep 17) | https://x402-list.com/state-of-x402 |

**Takeaways**
- Supply is flooded, and the directories overlap. Of the servers listed for at least 90 days, 54.5% have published only one version ([source](https://specialeventclub.com/2026/09/27/we-analyzed-the-mcp-registry-most-servers-stop-updating/)).
- Being listed does not show that a server works. Discovery is now the harder problem ([Agenstry](https://agenstry.com/blog/mcp-discovery-fragmentation)).
- Agents paying per call without an account (x402) is real but small. One live endpoint got about 1 paid transaction every 2–3 days in its first month ([Stacktree](https://stacktr.ee/blog/x402-in-production)).
- Publishing to the official registry needs a GitHub or DNS namespace plus a package (npm/PyPI) or a remote URL ([quickstart](https://modelcontextprotocol.io/registry/quickstart)). Smithery accepts a remote Streamable-HTTP URL ([docs](https://smithery.ai/docs/build/publish)).

## 2. Agent frameworks (the buyers' toolchains)
| Framework | GitHub stars (Aug 2026) |
|---|---|
| CrewAI | ~57.4k |
| LangGraph | ~40.2k |
| OpenAI Agents SDK | ~28.8k |
| Mastra (TS) | ~27.3k |
| AutoGen (maintenance mode) | ~60.6k |

Source: https://dreaming.press/posts/ai-agent-frameworks-github-ranked-by-stars-2026.html. All of them consume tools through function calling or MCP, so an MCP tool plus a REST API reaches every one.

## 3. Pricing of existing tool APIs
| Vendor | Free tier | Paid entry / unit price | Source |
|---|---|---|---|
| Firecrawl | 1,000 credits/mo | Hobby $16/mo (annual) for 5k credits; 1 credit = 1 page; JSON format adds +4 credits/page | https://www.firecrawl.dev/pricing |
| Tavily | 1,000 credits/mo | $0.008/credit pay-as-you-go | https://tavily.com/pricing |
| Exa | $10 credit/mo | Search from $4/1k; Contents $1/1k pages; Deep $12–15/1k | https://exa.ai/pricing |
| Browserbase | 1 browser-hr, 1k fetch | Dev $20/mo; $0.12/browser-hr; Fetch $1/1k | https://www.browserbase.com/pricing |
| Apify | $5 usage/mo | Starter $19/mo; $0.2/CU (1 GB-hr) | https://apify.com/pricing |
| Jina Reader | 20 RPM with no key | Token-based; ReaderLM models are CC-BY-NC (commercial use needs a license) | https://jina.ai/reader/ |
| Unstructured | 10k pages one-time | $0.015/page | https://unstructured.io/pricing |
| LlamaParse | 10k credits/mo | 1,000 credits = $1.25; Starter $50/mo | https://www.llamaindex.ai/pricing |
| E2B | $100 one-time credit | Pro $150/mo + $0.000014/vCPU-s | https://e2b.dev/pricing |
| ScrapingBee | 1,000 credits trial | Freelance $49/mo for 250k credits; JS render = 5 credits | https://hproxy.com/blog/scrapingbee-pricing , https://help.scrapingbee.com/en/article/available-plans-explained-kbinm/ |
| DataForSEO On-Page | none ($50 min deposit) | $0.000125/page base; $0.00425/page with Lighthouse | https://nextgrowth.ai/dataforseo-on-page-api/ |
| Google PageSpeed Insights API | 25k req/day free | free | https://unlighthouse.dev/learn-lighthouse/pagespeed-insights-api/rate-limits |
| Microlink (metadata) | 25 req/day | Pro from $49/mo | https://microlink.io/pricing |
| Prufa (QA MCP) | free anonymous audits | Pro $99/mo | https://prufa.dev/mcp/ |

**Price band:** commodity web and data calls clear at roughly **$0.001–$0.01 per call** (above). Deterministic compute costs a small fraction of that (see decision/first-capability.md).

## 4. Pain points with evidence
| Pain | Evidence |
|---|---|
| Scrapers fail silently, and agents have no confidence signal about what they got | r/LangChain thread: https://www.reddit.com/r/LangChain/comments/1tll558/what_in_your_opinion_is_the_biggest_pain_when/ ; https://kasharkk.hashnode.dev/from-scraper-scripts-to-access-aware-pipelines-a-developer-s-guide-to-reliable-web-data |
| Output schemas are inconsistent, and agents hallucinate fields | same r/LangChain thread; paper: https://exa.ai/library/publication/zsns9zr4h5x |
| JS pages come back empty or partial | Firecrawl issue #2691: https://github.com/firecrawl/firecrawl/issues/2691 ; https://www.reddit.com/r/AgentsOfAI/comments/1s18mii/anyone_here_using_a_browser_layer_instead_of/ |
| Scrapers break every few weeks | https://www.reddit.com/r/AI_Agents/comments/1qjkotq/what_are_people_actually_using_for_web_scraping/ |
| Agent traffic is being walled off: Cloudflare defaults block AI agent traffic on new ad-monetized domains (Sep 15, 2026) | https://www.joinmassive.com/blog/cloudflare-ai-crawler-defaults , https://fastcrw.com/blog/cloudflare-ai-crawler-block-september-2026 |
| MCP security is weak: 30 CVEs in 60 days; 147 unauthenticated servers found exposed | https://news.ycombinator.com/item?id=47356600 , https://pluto.security/blog/wide-open-hundreds-of-mcps-exposing-root-shells-production-data-and-citizen-records-one-call-away/ , https://thehackernews.com/2026/09/official-mcp-python-sdk-flaw-can-let.html |
| Tool definitions bloat the context window | https://mcp.directory/blog/mcp-context-bloat-fix-2026-tool-search-code-mode-progressive-disclosure |
| Coding agents ship broken sites. 78% of 49 Show HN launches had a critical bug on day one; 89–99% of vibe-coded apps lack CSP/HSTS | https://prufa.dev/mcp/ , https://reeve.page/research/vibe-coded-app-security-2026 |

## 5. Implications for AgentGrid
1. Avoid categories that need proxies, headless-browser fleets or paid LLM calls. Incumbents win there on scale.
2. Differentiate on **verifiable, deterministic output** (evidence plus a signed hash) and small, sharp tools (one tool with a tight schema).
3. Prefer targets the caller owns (their own site or API). That avoids the anti-bot walls and the legal gray zones.
