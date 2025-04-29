import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

test('POST /config/update', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'secret_tokens', 'insecure_tls_configuration', 'osi', 'unvalidated_redirect'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/config/update`,
      body: {
        "RAG_TEMPLATE": "example_template",
        "TOP_K": 5,
        "BYPASS_EMBEDDING_AND_RETRIEVAL": false,
        "RAG_FULL_CONTEXT": true,
        "ENABLE_RAG_HYBRID_SEARCH": true,
        "TOP_K_RERANKER": 5,
        "RELEVANCE_THRESHOLD": 0.5,
        "CONTENT_EXTRACTION_ENGINE": "example_engine",
        "PDF_EXTRACT_IMAGES": true,
        "TIKA_SERVER_URL": "https://example.com/tika",
        "DOCLING_SERVER_URL": "https://example.com/docling",
        "DOCUMENT_INTELLIGENCE_ENDPOINT": "https://example.com/intelligence",
        "DOCUMENT_INTELLIGENCE_KEY": "example_key",
        "MISTRAL_OCR_API_KEY": "example_key",
        "TEXT_SPLITTER": "example_splitter",
        "CHUNK_SIZE": 1000,
        "CHUNK_OVERLAP": 100,
        "FILE_MAX_SIZE": 10485760,
        "FILE_MAX_COUNT": 10,
        "ENABLE_GOOGLE_DRIVE_INTEGRATION": true,
        "ENABLE_ONEDRIVE_INTEGRATION": true,
        "web": {
          "ENABLE_WEB_SEARCH": true,
          "WEB_SEARCH_ENGINE": "example_engine",
          "WEB_SEARCH_TRUST_ENV": true,
          "WEB_SEARCH_RESULT_COUNT": 10,
          "WEB_SEARCH_CONCURRENT_REQUESTS": 5,
          "WEB_SEARCH_DOMAIN_FILTER_LIST": ["example.com"],
          "BYPASS_WEB_SEARCH_EMBEDDING_AND_RETRIEVAL": false,
          "SEARXNG_QUERY_URL": "https://example.com/searxng",
          "GOOGLE_PSE_API_KEY": "example_key",
          "GOOGLE_PSE_ENGINE_ID": "example_id",
          "BRAVE_SEARCH_API_KEY": "example_key",
          "KAGI_SEARCH_API_KEY": "example_key",
          "MOJEEK_SEARCH_API_KEY": "example_key",
          "BOCHA_SEARCH_API_KEY": "example_key",
          "SERPSTACK_API_KEY": "example_key",
          "SERPSTACK_HTTPS": true,
          "SERPER_API_KEY": "example_key",
          "SERPLY_API_KEY": "example_key",
          "TAVILY_API_KEY": "example_key",
          "SEARCHAPI_API_KEY": "example_key",
          "SEARCHAPI_ENGINE": "example_engine",
          "SERPAPI_API_KEY": "example_key",
          "SERPAPI_ENGINE": "example_engine",
          "JINA_API_KEY": "example_key",
          "BING_SEARCH_V7_ENDPOINT": "https://example.com/bing",
          "BING_SEARCH_V7_SUBSCRIPTION_KEY": "example_key",
          "EXA_API_KEY": "example_key",
          "PERPLEXITY_API_KEY": "example_key",
          "SOUGOU_API_SID": "example_sid",
          "SOUGOU_API_SK": "example_sk",
          "WEB_LOADER_ENGINE": "example_engine",
          "ENABLE_WEB_LOADER_SSL_VERIFICATION": true,
          "PLAYWRIGHT_WS_URL": "https://example.com/playwright",
          "PLAYWRIGHT_TIMEOUT": 30000,
          "FIRECRAWL_API_KEY": "example_key",
          "FIRECRAWL_API_BASE_URL": "https://example.com/firecrawl",
          "TAVILY_EXTRACT_DEPTH": "example_depth",
          "YOUTUBE_LOADER_LANGUAGE": ["en"],
          "YOUTUBE_LOADER_PROXY_URL": "https://example.com/proxy",
          "YOUTUBE_LOADER_TRANSLATION": "example_translation"
        }
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
