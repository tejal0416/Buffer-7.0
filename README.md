# Buffer-7.0
The theme for Buffer 7.0 is -
Open Innovation

IRIS THE SMART CYBER SUIT
The Local Guard
Autonomous Cyber Incident Response Agent
Buffer Hackathon 2026
Problem Statement
IRIS is designed to solve a multi-faceted challenge in modern Security Operations Centers (SOCs): the overwhelming volume of security alerts, lack of automated correlation, analyst fatigue, and the risk of sensitive data exfiltration through cloud-based tooling.

Specifically, IRIS must:
•	Ingest and index security alerts (SIEM logs, EDR events) and structured/unstructured log data efficiently.
•	Correlate incidents across systems using graph-based entity modeling (cross-source, cross-entity, time-based).
•	Produce step-by-step incident response playbooks through agentic orchestration.
•	Run fully offline with locally hosted LLMs, with zero external data transfer.
•	Prioritize incidents via a fidelity ranking algorithm to reduce noise and analyst fatigue.
•	Incorporate behavioral analytics (UEBA) using anomaly detection algorithms to surface novel threats.
•	Remain reusable and extensible across new log formats and environments.
•	Detect external device connections (USB, OneDrive) as an additional threat vector.

Solution
Summary
IRIS (Intelligent Response & Investigation System) — branded as IRIS THE SMART CYBER SUIT, the local guard — is an evidence-first, offline Incident Triage and Response Agent built on a foundation of classical DSA: graph traversal, priority queues, sliding-window aggregations, and inverted index search, combined with UEBA/anomaly analytics and a local LLM used exclusively for summarization, investigation guidance, and playbook drafting (never as the source of truth).

DSA at the Core
The system's correctness and performance are rooted in well-known algorithmic constructs:

Component	DSA Concept
Entity correlation engine	Weighted directed graph (adjacency list), BFS/DFS traversal, union-find for incident clustering
Alert-to-incident grouping	Sliding window (time-based), interval merging
Incident ranking	Priority queue (max-heap) with composite fidelity scores
Log indexing	Inverted index (tsvector/GIN), trigram index for fuzzy match
UEBA feature extraction	Rolling window aggregations, Z-score / IQR for anomaly detection
Evidence retrieval	Hash map for O(1) event lookup by ID, B-tree index for range queries
Telemetry coverage	Bitset / set difference for detecting missing log sources
Playbook template selection	Trie for prefix-based template matching; decision tree for incident classification
Feedback loop	Online weighted averaging (contextual bandit) over ranked incident features
Audit trail integrity	Hash chaining (SHA-256 linking of ordered audit entries)

How It Solves the Problem
•	Ingestion + normalization converts heterogeneous logs into a canonical event schema using adapter-pattern parsing.
•	Correlation engine links alerts/events into coherent incidents using an entity graph (nodes: user/host/ip/process; edges: co-occurrence within time windows) and a union-find structure for efficient incident cluster merging.
•	Fidelity ranking scores incidents using a max-heap priority queue over composite signals: rule hits, cross-source corroboration count, UEBA/anomaly Z-scores, and asset criticality weights.
•	Agentic workflow (offline) validates evidence, identifies gaps using set difference on expected vs. observed telemetry sources, and drafts a response playbook with citations to underlying events.
•	Audit trail records every query, evidence item, and model output, linked via hash chaining so analysts can trust, reproduce, and defend decisions.
•	External device detection surfaces USB, pen drive, and OneDrive connection events as an additional threat and exfiltration vector.

Key Capabilities
•	Alert-to-incident compression using sliding-window grouping and union-find clustering (100 alerts to a small number of coherent incidents).
•	Cross-system correlation via entity graph traversal (SIEM + EDR + IAM + network + application logs).
•	UEBA-based anomaly scoring with 5-minute bucket windows (bucket_seconds: 300), rolling EWMA baselines, cold-start tolerant.
•	Missing-log awareness via set-difference telemetry coverage scoring; incident detail pages explicitly show missing sources (e.g., missing sources: siem, iam).
•	Consistent playbooks generated from trie-matched local YAML templates plus evidence context.
•	External device monitoring panel (USB, OneDrive) for exfiltration detection.

Methodology
Concept and Principles
Concept: Treat incident response as an evidence-driven pipeline where each stage maps to a concrete algorithmic building block: ingest, index, correlate (graph), score (heap), validate (set ops), retrieve (inverted index), and draft (LLM, offline).

Principles:
•	Deterministic-first: Graph traversal, heap ranking, and set operations are predictable and auditable — not probabilistic black boxes.
•	Algorithmic transparency: Every ranking decision can be traced back to edge weights, rule hits, or anomaly scores.
•	Offline-first and privacy-preserving: No external network calls; all computation is local.
•	Human-in-the-loop: No blind remediation; analyst approves every playbook.
•	Graceful degradation: Coverage scoring (set difference) makes missing data explicit, never silently ignored.

Core Algorithmic Components
1. Entity Graph and Incident Clustering
All parsed events emit entity tuples (type, value) — e.g., (user, alice), (host, WKS-12), (ip, 10.0.0.5). These become nodes in a weighted directed graph:
•	Edges connect entities that co-appear in the same event.
•	Edge weight = co-occurrence frequency within a configurable time window.
•	BFS/DFS traversal over this graph identifies connected components (related entities under investigation).
•	Union-Find (Disjoint Set Union) merges overlapping incident clusters efficiently in near-linear time as new events arrive.

Time complexity:
•	Insert event + update graph: O(k²) per event (k = number of entities per event, typically small)
•	Cluster merge: O(α(n)) per union operation (inverse Ackermann — effectively O(1))

2. Sliding Window and Interval Merging
Raw alerts are temporally grouped using a sliding window algorithm. A deque of events sorted by timestamp is maintained, evicting events outside the window boundary in O(1) amortized time. Overlapping windows from different sources are merged using a sweep-line / interval merge algorithm (sort by start, merge overlapping intervals). UEBA feature aggregation uses 5-minute bucket windows (bucket_seconds: 300).

3. Priority Queue for Incident Ranking
Every incident is scored with a composite fidelity score:

fidelity = w1 * rule_hits
         + w2 * cross_source_count
         + w3 * ueba_anomaly_score
         + w4 * asset_criticality
         - w5 * coverage_penalty

Incidents are maintained in a max-heap priority queue keyed on fidelity, enabling O(1) retrieval of the highest-priority incident, O(log n) insertion/update as new evidence arrives, and lazy deletion via a version counter for stale entries.

4. Inverted Index and Full-Text Search
Event storage uses an inverted index (implemented via PostgreSQL's tsvector + GIN index) for fast keyword and entity lookup. Log tokens are stemmed and indexed at ingest time. Query at O(log n + k) for k results. A trigram index (pg_trgm) adds fuzzy matching for noisy entity names. Optional pgvector enables semantic nearest-neighbor retrieval using cosine similarity over local embeddings.

5. UEBA: Rolling Window Baselines and Anomaly Scoring
For each (user, feature) or (host, feature) pair, the system maintains an Exponentially Weighted Moving Average (EWMA) for the baseline, rolling variance for adaptive threshold computation, and a Z-score for each new observation relative to the baseline. UEBA features are extracted over 5-minute bucket windows (bucket_seconds: 300). The evidence JSON includes ueba_meta with rows, enabled, entities, and features sub-fields alongside the ueba_score and anomaly_score fields. Optionally, IsolationForest or ECOD (via PyOD) is applied to multidimensional feature vectors extracted with tsfresh.

6. Set Operations for Telemetry Coverage
For each incident, expected telemetry sources (e.g., {SIEM, EDR, IAM, NET}) are compared against observed sources using set difference:

missing = expected_sources - observed_sources
coverage_score = |observed_sources| / |expected_sources|

This is O(k) and gives analysts an explicit blind-spot signal. The incident detail page explicitly shows missing sources (e.g., missing sources: siem, iam) for incidents with low coverage. The Telemetry Blind-Spot Detector (SOC Health Monitor) dashboard section shows Hosts Missing EDR, Users Missing IAM, and Heartbeat Drops by source/host.

7. Hash Chaining for Audit Integrity
Each audit entry is linked to the previous one via SHA-256:

entry_hash[i] = SHA256(entry_content[i] + entry_hash[i-1])

This forms a tamper-evident chain (analogous to a blockchain structure), ensuring that no audit record can be silently modified or deleted.

Architecture
Architecture Overview
IRIS follows a layered pipeline: log sources feed into a FastAPI ingestion layer, which normalizes events and stores them in PostgreSQL with GIN full-text indexes and entity graph tables. The correlation engine runs BFS/DFS and union-find over the entity graph, merges sliding-window time intervals, and feeds anomaly scores from the UEBA pipeline into a composite fidelity max-heap. The LangGraph orchestrator drives triage, validation, and playbook drafting via the local LLM (Ollama/HuggingFace), with all steps appended to the hash-chained audit log.

End-to-End Flow
1.	Receive logs/alerts from SIEM, EDR, IAM, Network, Application, and External Device sources.
2.	Parse + normalize using adapter pattern; store events and update GIN inverted index.
3.	Extract entities; update entity graph nodes and weighted edges.
4.	Union-Find: merge events into incident clusters.
5.	Sliding window + interval merge: build coherent time windows; apply 5-minute UEBA buckets.
6.	UEBA: EWMA baseline update + Z-score computation; output ueba_meta and anomaly_score.
7.	Compute fidelity score (rule_hits, cross_source_count, ueba_anomaly_score, asset_criticality, coverage_penalty); push to max-heap.
8.	Set difference: coverage scoring per incident; annotate missing sources on incident detail.
9.	Top-K from heap: route high-priority incidents to validation; queue the rest for monitoring.
10.	Validate evidence + find telemetry gaps; retrieve evidence via inverted index (+ optional pgvector).
11.	POST /incidents/{id}/investigate: agentic investigation step.
12.	POST /incidents/{id}/playbook: draft playbook + narrative via Local LLM, offline, with event_id citations.
13.	Analyst edits/approves via ranked incident UI.
14.	Export case bundle; append hash-chained audit entry.

Runbook Templates (YAML)
IRIS ships with four YAML-based runbook templates, accessible via the /runbooks API endpoint and matched using a trie for prefix-based template selection:

Template ID	File	Incident Type
rb_c2_v1	command_and_control.yml	C2 / Suspicious Outbound Communication
rb_credential_abuse_v1	credential_abuse.yml	Credential Abuse (Brute Force / Stuffing / ATO)
rb_malware_execution_v1	malware_execution.yml	Malware Execution / Living-off-the-Land
rb_suspicious_activity_v1	suspicious_activity_v1.yml	Generic Suspicious Activity

All templates are YAML only (.yml). Each generated playbook cites underlying event_ids in every step and is reviewed/approved by the analyst before execution.

Complexity Analysis
Operation	Data Structure	Time	Space
Event insert + entity update	Hash map + adjacency list	O(k) per event	O(n + e)
Incident cluster merge	Union-Find (path compression)	O(α(n))	O(n)
Sliding window eviction	Deque	O(1) amortized	O(w)
Interval merge (alert grouping)	Sort + sweep	O(m log m)	O(m)
Incident heap insert/update	Max-heap	O(log n)	O(n)
Top-K incident retrieval	Max-heap	O(K log n)	O(1) per query
Full-text event search	GIN inverted index	O(log n + k)	O(n · t)
Coverage scoring	Set difference	O(k)	O(k)
UEBA baseline update	EWMA	O(1) per observation	O(f · u)
Audit chain verification	Hash chain (SHA-256)	O(n)	O(n)

n = total incidents/events; e = entity graph edges; k = entities per event; m = alerts in batch; w = window size; f = features; u = unique users/hosts; t = tokens per event

Frameworks / Tools / Tech Stack
Core
•	Python 3.11+
•	FastAPI (ingestion + REST APIs)
•	PostgreSQL (system of record — GIN index, B-tree, optional pgvector)
•	SQLAlchemy / asyncpg (async data access)

API Endpoints
Method	Endpoint	Purpose
POST	/ingest	Ingest single normalized event
POST	/ingest/raw	Ingest raw log string
POST	/ingest/batch	Batch ingest multiple events
POST	/correlate	Trigger correlation engine run
GET	/incidents	List ranked incidents (heap order)
GET	/incidents/{incident_id}	Get incident detail + missing sources
POST	/incidents/{incident_id}/investigate	Run agentic investigation step
POST	/incidents/{incident_id}/playbook	Generate YAML-templated playbook via LLM
GET	/events/search	Full-text search over indexed events
GET	/runbooks	List available YAML runbook templates

DSA Implementations
•	networkx — entity graph construction, BFS/DFS traversal, connected components
•	Custom Union-Find — Python dataclass with path compression + union by rank
•	sortedcontainers.SortedList — sliding window and interval management
•	heapq — max-heap priority queue for fidelity ranking
•	PostgreSQL GIN (tsvector) — inverted index for full-text search
•	PostgreSQL pg_trgm — trigram index for fuzzy entity matching
•	hashlib (SHA-256) — audit chain integrity

Behavior + Anomaly
•	tsfresh — time-series feature extraction for UEBA
•	PyOD — anomaly detectors (ECOD, HBOS, IsolationForest)
•	Custom EWMA with 5-minute bucketing (bucket_seconds: 300) for rolling baselines

Agentic Orchestration + Offline LLM
•	LangChain / LangGraph — workflow orchestration, tool calling
•	Ollama (local LLM runtime) or HuggingFace Transformers (local models)
•	sentence-transformers — local embedding model (optional pgvector path)

Optional Utilities
•	Pydantic — schemas and validation
•	Docker Compose — local deployment

UI Wireframes (Low-Fidelity)
1. Incident Dashboard
Includes max-heap ranked incident list (fidelity / conf / cov columns), Incident Category charts (malware_execution, suspicious_activity, command_and_control), 7-day frequency breakdown, alert banner, Telemetry Blind-Spot Detector (SOC Health Monitor) with Hosts Missing EDR / Users Missing IAM / Heartbeat Drops, and External Devices Attached panel (OneDrive/USB/pen drive).

+--------------------------------------------------------------+
| IRIS THE SMART CYBER SUIT  —  Incident Queue (heap ranked)  |
| Search: [ user:alice host:WKS-12 ip:10.0.0.5 ]  [Filter]    |
|--------------------------------------------------------------|
| Rank | Fidelity | Conf | Coverage | Type       | Last Seen   |
|  1   |  100.0   | 1.00 | 1.00     | malware    | 10:41:12    |
|  2   |   87.5   | 0.44 | 0.50     | suspicious | 10:39:02    |
|  3   |   74.0   | 0.66 | 0.88     | c2         | 10:35:48    |
|--------------------------------------------------------------|
| Telemetry Blind-Spot Detector (SOC Health Monitor)           |
| Hosts Missing EDR: 3  |  Users Missing IAM: 1                |
| External Devices Attached: USB x2, OneDrive x1               |
+--------------------------------------------------------------+

2. Incident Detail + Entity Graph
+--------------------------------------------------------------+
| Incident #123  Fidelity 100  Coverage 1.00  Missing: none   |
| Incident #456  Fidelity 87   Coverage 0.50  Missing: siem,  |
|                                                        iam   |
| Entities: user alice | host WKS-12 | ip 10.0.0.5            |
|--------------------------------------------------------------|
| Timeline (evidence - sorted by timestamp)                    |
| 10:12 EDR: suspicious powershell spawn (event_id=...)        |
| 10:14 IAM: 7 failed logins (event_id=...)                    |
| 10:18 NET: new domain contacted (event_id=...)               |
|--------------------------------------------------------------|
| Entity Graph View | Evidence Queries | Generate Playbook     |
+--------------------------------------------------------------+

3. Playbook Editor + Audit Chain
+--------------------------------------------------------------+
| Playbook Draft (Local LLM, YAML template: rb_malware_v1)    |
| Step 1: Contain host WKS-12 (ref: event_id=..., query=...)  |
| Step 2: Collect triage artifacts (ref: ...)                 |
| Step 3: Block IOCs (ref: ...)                                |
| Step 4: Eradicate / recover (ref: ...)                       |
|--------------------------------------------------------------|
| Audit: hash chain entries | model version | query log        |
| [Approve] [Export PDF/MD]                                    |
+--------------------------------------------------------------+

Impact Metrics
Operational Metrics
•	Mean Time To Detect (MTTD)
•	Mean Time To Respond (MTTR)
•	Alert-to-incident compression ratio (alerts per incident)
•	Analyst touch time per incident (minutes)
•	Precision@K for highest-ranked incidents (heap correctness)
•	False positive reduction percentage (before vs after fidelity ranking)

Algorithmic Correctness Metrics
•	Union-Find cluster purity (overlap with ground-truth incident groupings)
•	Heap rank correlation with analyst-confirmed true positives
•	Coverage score accuracy (set difference vs actual missing sources)
•	Anomaly Z-score calibration (precision/recall at various thresholds)

System Performance Metrics
•	Ingestion throughput (events/sec)
•	Correlation engine latency (ms per batch)
•	Heap top-K query latency
•	LLM playbook generation latency (async job time)

Validation Plan
Demo dataset with known scenarios:
•	Credential stuffing + account takeover (tests sliding window + union-find clustering)
•	Malware execution chain (tests entity graph traversal + UEBA anomaly scoring; runs rb_malware_execution_v1 playbook)
•	Lateral movement signals (tests cross-source fidelity ranking via heap; runs rb_suspicious_activity_v1 playbook)
•	C2 outbound communication (tests rb_c2_v1 playbook selection via trie)

Verification:
•	Measure Precision@K and alert-to-incident compression ratio.
•	Show union-find correctness by verifying cluster membership.
•	Demonstrate coverage set-difference by removing one log source and showing fidelity drop + missing source annotation on incident detail.
•	Verify hash-chain integrity by replaying audit log.
•	Confirm ueba_meta bucket_seconds = 300 in evidence JSON for all UEBA-scored incidents.

Security and Safety Controls
•	Offline-only execution with strict network egress blocked.
•	Role-based access control for UI actions (analyst vs lead) — enforced at login.
•	Audit logs protected by SHA-256 hash chaining (tamper-evident).
•	Data minimization options: masking/redaction at ingest for sensitive fields.
•	External device events (USB, OneDrive) are logged and surfaced in the dashboard for exfiltration awareness.

Assumptions, Constraints, Decision Points
Assumptions
•	Logs contain timestamps that are roughly time-synchronized across sources.
•	At least two log sources are available in the demo (SIEM-style alerts and EDR-style events).
•	The system runs inside a controlled offline environment with no outbound network.

Constraints
•	Zero external data transfer; fully offline processing.
•	Must handle missing fields and partial telemetry without fabricating certainty.
•	Must operate within local compute and memory limits.

Decision Rationale
•	PostgreSQL over Elasticsearch: Lower operational cost, simpler local deployment, native GIN + pgvector support.
•	Union-Find for clustering: Near-linear time incremental merging is far more efficient than repeated full-graph scans.
•	Max-heap for ranking: O(log n) updates allow real-time re-scoring as new evidence arrives without a full sort.
•	YAML-only runbook templates: Consistent with actual implementation; four concrete templates ship by default.
•	Deterministic DSA core first, LLM last: Ensures ranking and correlation are reproducible and auditable; LLM is only used for human-readable synthesis.

Scalability / Usability
Scalability
•	PostgreSQL B-tree and GIN indexes + time-based partitioning support large event volumes.
•	Union-Find and heap are incremental — O(α(n)) and O(log n) per update regardless of total incident count.
•	Async workers for UEBA feature extraction, embedding generation, and LLM playbook jobs.
•	Horizontal scaling by adding ingestion replicas and worker processes; DB scales vertically or via managed offline-compatible deployments.

Usability
•	Analyst-centric UI for heap-ranked incidents, evidence timelines, and one-click playbook drafting.
•	Explainability by design: top contributing fidelity signals visible per incident; missing sources explicitly shown on incident detail.
•	External device panel gives immediate visibility into potential data exfiltration vectors.
•	Case bundles exportable for reporting and audits.

Continuous Learning (Contextual Bandit)
Full RL is not recommended for raw detection (high-stakes, delayed rewards, adversarial non-stationarity). Instead, a contextual bandit is applied to the decision policy layer.

Context / Features
•	Rule hit vector, anomaly Z-scores, corroboration count, asset criticality, coverage score.

Actions
•	Fidelity weight adjustment bucket, next-evidence query selection, playbook template selection.

Reward
•	Analyst confirmation (confirmed/dismissed), time-to-resolution, quality rating.

Safety Controls
•	Feedback accepted only from trusted roles; multi-analyst confirmation for high-impact updates.
•	Outlier feedback detection (possible poisoning) triggers quarantine.
•	Fallback to deterministic baseline if learner confidence is below threshold or coverage is low.
•	Gated updates: model updates only if offline evaluation improves Precision@K and stays within safety bounds.

Future Scope
•	Automated containment integrations (SOAR) behind human approvals.
•	Federated multi-tenant deployments across multiple business units.
•	Continual learning using feedback (locally stored) with distribution drift checks.
•	MITRE ATT&CK mapping for standardized playbook reporting.
•	Replacement of contextual bandit with offline RL over logged interaction data for ranking policy improvement.
•	Extended external device telemetry: DLP integration for USB write-volume alerting.

