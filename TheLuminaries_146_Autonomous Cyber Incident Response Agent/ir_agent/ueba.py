from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class UEBAResult:
    user_scores: dict[str, float]
    host_scores: dict[str, float]
    meta: dict[str, Any]


def _minmax(scores: list[float]) -> list[float]:
    if not scores:
        return []
    lo = min(scores)
    hi = max(scores)
    if hi <= lo:
        return [0.0 for _ in scores]
    return [(s - lo) / (hi - lo) for s in scores]


def _compute_scores_for_entity(
    db: Session,
    *,
    since_ts: datetime,
    bucket_seconds: int,
    entity_col: str,
) -> tuple[dict[str, float], dict[str, Any]]:
    # We compute per-entity time series of event "kinds" and use:
    # - tsfresh to extract features
    # - PyOD to compute anomaly score across entities
    #
    # If optional deps are missing, we return empty scores and meta explains why.
    try:
        import pandas as pd  # type: ignore
        from pyod.models.ecod import ECOD  # type: ignore
        from tsfresh.feature_extraction import MinimalFCParameters, extract_features  # type: ignore
    except Exception as e:  # pragma: no cover
        return {}, {"enabled": False, "reason": f"missing_optional_deps: {e!r}"}

    q = text(
        f"""
        SELECT
          {entity_col} AS entity,
          floor(extract(epoch from ts) / :bucket_seconds)::bigint AS t,
          CASE
            WHEN event_type IN ('auth_failed','auth_success') THEN 'auth'
            WHEN event_type IN ('process_start','process_create') THEN 'proc'
            WHEN event_type IN ('dns_query','http_request','net_connection') THEN 'net'
            WHEN event_type IN ('siem_alert') THEN 'alert'
            ELSE 'other'
          END AS kind,
          count(*)::bigint AS v
        FROM events
        WHERE ts >= :since_ts AND {entity_col} IS NOT NULL AND {entity_col} <> ''
        GROUP BY entity, t, kind
        ORDER BY entity, t, kind
        """
    )
    rows = list(db.execute(q, {"since_ts": since_ts, "bucket_seconds": int(bucket_seconds)}).mappings())
    if not rows:
        return {}, {"enabled": True, "entities": 0, "rows": 0}

    df = pd.DataFrame(rows)
    # tsfresh expects these column names
    df.rename(columns={"entity": "id", "t": "time", "kind": "kind", "v": "value"}, inplace=True)

    # For small datasets, avoid unstable anomaly scoring.
    entity_count = int(df["id"].nunique())
    if entity_count < 3:
        return {str(e): 0.0 for e in df["id"].unique().tolist()}, {"enabled": True, "entities": entity_count, "rows": len(df)}

    fc_params = MinimalFCParameters()
    feats = extract_features(
        df,
        column_id="id",
        column_sort="time",
        column_kind="kind",
        column_value="value",
        default_fc_parameters=fc_params,
        disable_progressbar=True,
        n_jobs=1,
    )

    feats = feats.replace([float("inf"), float("-inf")], 0.0).fillna(0.0)
    model = ECOD()
    model.fit(feats.values)
    raw_scores = model.decision_scores_.tolist()
    norm = _minmax([float(s) for s in raw_scores])

    # Map back to entity id (index)
    out: dict[str, float] = {}
    for ent, score in zip(feats.index.tolist(), norm, strict=True):
        out[str(ent)] = float(score)

    return out, {"enabled": True, "entities": entity_count, "rows": len(df), "features": int(feats.shape[1])}


def compute_ueba(
    db: Session,
    *,
    since_ts: datetime,
    bucket_seconds: int = 300,
) -> UEBAResult:
    user_scores, user_meta = _compute_scores_for_entity(
        db, since_ts=since_ts, bucket_seconds=bucket_seconds, entity_col="username"
    )
    host_scores, host_meta = _compute_scores_for_entity(
        db, since_ts=since_ts, bucket_seconds=bucket_seconds, entity_col="host"
    )
    return UEBAResult(
        user_scores=user_scores,
        host_scores=host_scores,
        meta={"user": user_meta, "host": host_meta, "bucket_seconds": int(bucket_seconds)},
    )
