# Go adoption strategy
Principle: add Go only where profiling or operational needs justify it. Python stays the system of record.

Candidate services (in likely order):
1. market-collector  - high-fanout price/candle ingestion (Phase 2/3+)
2. exchange-sync     - concurrent read-only exchange polling
3. alert-evaluator   - evaluates thousands of rules against price streams (Phase 4+)
4. backtest-engine   - CPU-bound simulations (Phase 6)

Seams we keep from day 1:
- Provider interfaces (MarketDataProvider, ExchangeAdapter) with documented contracts
- Event contracts in /contracts/events (JSON Schema) over Redis Streams
- Go services never write to Python-owned tables; they publish events or call internal API
- OpenAPI exported to /contracts/openapi
