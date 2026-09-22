"use strict";

const MAX_LEASE_SECONDS = 30;
const MAX_HEARTBEAT_GAP_MS = 10000;
let fallback_id = 0;

function random_uuid() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  fallback_id += 1;
  const tail = `${Date.now().toString(16)}${fallback_id.toString(16)}`.padStart(12, "0").slice(-12);
  return `00000000-0000-4000-8000-${tail}`;
}

function iso_at(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function response_result(response) {
  return response && response.ok && response.result ? response.result : null;
}

/**
 * Browser-agnostic lease-backed foreground usage tracker.
 *
 * Adapters update the active tab, focus, idle, and matching-rule inputs. The
 * tracker never counts without an issued service lease and keeps unsent
 * reports queued until the service acknowledges their unique identity.
 */
export class AllowanceTracker {
  constructor({
    request_lease,
    report_usage,
    now = () => Date.now(),
    on_exhausted = () => {},
    on_unavailable = () => {},
    on_available = () => {},
    on_pending_changed = () => {},
  }) {
    this.request_lease = request_lease;
    this.report_usage = report_usage;
    this.now = now;
    this.on_exhausted = on_exhausted;
    this.on_unavailable = on_unavailable;
    this.on_available = on_available;
    this.on_pending_changed = on_pending_changed;
    this.exhausted_rules = new Set();
    this.active_tab_id = null;
    this.focused = false;
    this.idle = true;
    this.match = null;
    this.lease = null;
    this.last_ms = null;
    this.pending = [];
    this.busy = false;
  }

  is_exhausted(rule_id) {
    return this.exhausted_rules.has(rule_id);
  }

  has_lease(rule_id) {
    return this.lease?.rule_id === rule_id;
  }

  get active() {
    return this._eligible();
  }

  restore_pending(reports) {
    if (!Array.isArray(reports)) {
      return;
    }
    const seen = new Set(this.pending.map((report) => report.report_id));
    let discarded = false;
    for (const report of reports) {
      if (
        report &&
        typeof report === "object" &&
        typeof report.report_id === "string" &&
        typeof report.rule_id === "string" &&
        typeof report.lease_id === "string" &&
        typeof report.start_utc === "string" &&
        typeof report.end_utc === "string" &&
        !seen.has(report.report_id)
      ) {
        this.pending.push({ ...report });
        seen.add(report.report_id);
      } else {
        // Reports created before lease IDs were persisted cannot be submitted.
        discarded = true;
      }
    }
    if (discarded) {
      this.on_pending_changed(this.pending);
    }
  }

  get needs_pulse() {
    return this.active || this.pending_count > 0;
  }

  get leased() {
    return this.lease !== null;
  }
  get pending_count() {
    return this.pending.length;
  }

  _eligible() {
    return this.active_tab_id !== null && this.focused && !this.idle && this.match !== null;
  }
  _advance(at_ms) {
    const now = Number(at_ms);
    if (!Number.isFinite(now)) {
      return;
    }
    if (this.last_ms === null) {
      this.last_ms = now;
      return;
    }
    if (now < this.last_ms || now - this.last_ms > MAX_HEARTBEAT_GAP_MS) {
      // A suspended worker cannot prove foreground time. Abandoning the lease
      // is fail-closed; the queued prefix remains retryable.
      const abandoned_rule_id = this.lease?.rule_id;
      this.lease = null;
      this.last_ms = now;
      if (abandoned_rule_id !== undefined) {
        this.on_unavailable(abandoned_rule_id);
      }
      return;
    }
    if (this._eligible() && this.lease !== null) {
      const end_ms = Math.min(now, this.lease.end_ms);
      if (end_ms > this.last_ms && end_ms > this.lease.start_ms) {
        const start_ms = Math.max(this.last_ms, this.lease.start_ms);
        if (end_ms > start_ms) {
          this.pending.push({
            report_id: random_uuid(),
            rule_id: this.lease.rule_id,
            lease_id: this.lease.lease_id,
            start_utc: start_ms <= this.lease.start_ms
              ? this.lease.start_utc
              : iso_at(start_ms),
            end_utc: iso_at(end_ms),
          });
          this.on_pending_changed(this.pending);
        }
      }
      this.last_ms = now;
      if (now >= this.lease.end_ms) {
        const expired_rule_id = this.lease.rule_id;
        this.lease = null;
        this.on_unavailable(expired_rule_id);
      }
      return;
    }
    const abandoned_rule_id = this.lease?.rule_id;
    this.last_ms = now;
    this.lease = null;
    if (abandoned_rule_id !== undefined) {
      this.on_unavailable(abandoned_rule_id);
    }
  }

  reset() {
    this._advance(this.now());
    this.lease = null;
    this.exhausted_rules.clear();
  }

  _touch() {
    this._advance(this.now());
    return this.pump();
  }

  set_active_tab(tab_id, match) {
    this._advance(this.now());
    this.active_tab_id = Number.isInteger(tab_id) && tab_id >= 0 ? tab_id : null;
    this.match = match ?? null;
    this.last_ms = this.now();
    return this.pump();
  }

  set_tab_match(tab_id, match) {
    if (tab_id !== this.active_tab_id) {
      return Promise.resolve(false);
    }
    this._advance(this.now());
    this.match = match ?? null;
    return this.pump();
  }

  set_focused(focused) {
    this._advance(this.now());
    this.focused = focused === true;
    return this.pump();
  }

  set_idle(idle) {
    this._advance(this.now());
    this.idle = idle === true;
    return this.pump();
  }

  pulse(at_ms = this.now()) {
    this._advance(at_ms);
    return this.pump();
  }

  async pump() {
    if (this.busy) {
      return false;
    }
    this.busy = true;
    try {
      while (this.pending.length > 0) {
        const report = this.pending[0];
        let response;
        try {
          response = await this.report_usage(report);
        } catch {
          this.lease = null;
          this.on_unavailable(report.rule_id);
          return false;
        }
        if (!response || response.ok !== true) {
          // Lease state is in-memory at the service. A restart invalidates
          // reports queued under the old lease; discard only that stale
          // prefix so a new lease can be requested.
          if (response?.error?.code === "not_found") {
            this.pending.shift();
            this.on_pending_changed(this.pending);
            continue;
          }
          this.lease = null;
          this.on_unavailable(report.rule_id);
          return false;
        }
        this.pending.shift();
        this.on_pending_changed(this.pending);
      }
      if (!this._eligible() || this.lease !== null) {
        return true;
      }
      const requested_rule_id = this.match.rule_id;
      let lease_response;
      try {
        lease_response = await this.request_lease(
          requested_rule_id,
          MAX_LEASE_SECONDS,
        );
      } catch {
        this.on_unavailable(requested_rule_id);
        return false;
      }
      if (this.match?.rule_id !== requested_rule_id || !this._eligible()) {
        this.lease = null;
        this.on_unavailable(requested_rule_id);
        return false;
      }
      const lease = response_result(lease_response);
      if (
        !lease ||
        lease.rule_id !== requested_rule_id ||
        typeof lease.lease_id !== "string"
      ) {
        if (lease_response?.error?.code === "allowance_exhausted") {
          this.exhausted_rules.add(requested_rule_id);
          this.lease = null;
          this.on_exhausted(requested_rule_id);
        } else {
          this.on_unavailable(requested_rule_id);
        }
        return false;
      }
      const start_ms = Date.parse(lease.start_utc);
      const end_ms = Date.parse(lease.end_utc);
      if (
        !Number.isFinite(start_ms) ||
        !Number.isFinite(end_ms) ||
        end_ms <= start_ms ||
        end_ms - start_ms > MAX_LEASE_SECONDS * 1000
      ) {
        this.on_unavailable(requested_rule_id);
        return false;
      }
      this.exhausted_rules.delete(requested_rule_id);
      this.lease = {
        rule_id: requested_rule_id,
        lease_id: lease.lease_id,
        start_ms,
        end_ms,
        start_utc: lease.start_utc,
      };
      this.last_ms = Math.max(this.last_ms ?? this.now(), start_ms);
      this.on_available(requested_rule_id);
      return true;
    } finally {
      this.busy = false;
    }
  }
}

export { MAX_HEARTBEAT_GAP_MS, MAX_LEASE_SECONDS };
