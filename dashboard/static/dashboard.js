(function () {
  const $ = (id) => document.getElementById(id);
  let lastSummary = null;
  let workspaceSlug = "lab";
  let ws = null;
  let wsRetryTimer = null;

  function fmtInt(v) {
    return Number(v || 0).toLocaleString("ja-JP");
  }
  function fmtPct(v) {
    return `${(Number(v || 0) * 100).toFixed(1)}%`;
  }
  function fmtMs(v) {
    if (v === null || v === undefined || Number.isNaN(Number(v))) return "--";
    return `${Number(v).toFixed(1)}ms`;
  }
  function compactPairs(obj) {
    if (!obj || typeof obj !== "object") return "--";
    const keys = Object.keys(obj);
    if (!keys.length) return "--";
    return keys.slice(0, 6).map((k) => `${k}:${obj[k]}`).join(" | ");
  }

  function drawLine(canvas, seriesList, colors) {
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const W = rect.width;
    const H = rect.height;
    const pad = { top: 12, left: 42, right: 16, bottom: 28 };
    const cW = W - pad.left - pad.right;
    const cH = H - pad.top - pad.bottom;
    ctx.clearRect(0, 0, W, H);
    if (!seriesList.length || !seriesList[0].length) {
      ctx.fillStyle = "#91a3bf";
      ctx.textAlign = "center";
      ctx.fillText("No data", W / 2, H / 2);
      return;
    }
    const maxVal = Math.max(1, ...seriesList.flat().map((p) => p.value));
    ctx.strokeStyle = "rgba(34,52,82,0.7)";
    ctx.fillStyle = "#91a3bf";
    ctx.font = "10px sans-serif";
    for (let i = 0; i <= 4; i += 1) {
      const y = pad.top + cH - (cH * i / 4);
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(W - pad.right, y);
      ctx.stroke();
      ctx.fillText(String(Math.round(maxVal * i / 4)), 8, y + 3);
    }
    seriesList.forEach((series, idx) => {
      ctx.strokeStyle = colors[idx];
      ctx.lineWidth = 2;
      ctx.beginPath();
      series.forEach((point, i) => {
        const x = pad.left + (cW * i / Math.max(series.length - 1, 1));
        const y = pad.top + cH - ((point.value / maxVal) * cH);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    });
  }

  function drawBars(canvas, series, color) {
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const W = rect.width;
    const H = rect.height;
    const pad = { top: 12, left: 42, right: 16, bottom: 28 };
    const cW = W - pad.left - pad.right;
    const cH = H - pad.top - pad.bottom;
    ctx.clearRect(0, 0, W, H);
    if (!series.length) return;
    const maxVal = Math.max(1, ...series.map((p) => p.value));
    const step = cW / series.length;
    const barW = Math.max(2, step - 1);
    ctx.fillStyle = color;
    series.forEach((point, i) => {
      const h = (point.value / maxVal) * cH;
      const x = pad.left + i * step;
      const y = pad.top + cH - h;
      ctx.fillRect(x, y, barW, h);
    });
  }

  function fillRows(bodyId, emptyId, rows, mapper) {
    const body = $(bodyId);
    const empty = $(emptyId);
    body.innerHTML = "";
    if (!rows.length) {
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    rows.forEach((row) => {
      body.insertAdjacentHTML("beforeend", mapper(row));
    });
  }

  function incidentActions(row) {
    const st = String(row.status || "open");
    if (st === "open") return `<button data-act="triage" data-id="${row.id}">triage</button> <button data-act="close" data-id="${row.id}">close</button>`;
    if (st === "triaged") return `<button data-act="reopen" data-id="${row.id}">reopen</button> <button data-act="close" data-id="${row.id}">close</button>`;
    return `<button data-act="reopen" data-id="${row.id}">reopen</button>`;
  }

  function fmtWindow(row) {
    const first = row.first_seen_at ? new Date(row.first_seen_at).toLocaleTimeString("ja-JP") : "--";
    const last = row.last_seen_at ? new Date(row.last_seen_at).toLocaleTimeString("ja-JP") : "--";
    return `${first} - ${last}`;
  }

  function getTestIpAdminContext() {
    const token = String(($("testIpAdminToken") && $("testIpAdminToken").value) || "").trim();
    const actor = String(($("testIpActor") && $("testIpActor").value) || "soc_operator").trim() || "soc_operator";
    return { token, actor };
  }

  function getRuleEditorContext() {
    const token = String(($("adminToken") && $("adminToken").value) || "").trim();
    const actor = String(($("adminActor") && $("adminActor").value) || "soc_operator").trim() || "soc_operator";
    return { token, actor };
  }

  async function loadRuleEditor() {
    const { token } = getRuleEditorContext();
    if (!token) {
      fillRows("ruleOverridesBody", "ruleOverridesEmpty", [], () => "");
      fillRows("ruleFeedbackBody", "ruleFeedbackEmpty", [], () => "");
      $("ruleEditorMsg").textContent = "admin token required";
      return;
    }
    const [ovResp, fbResp] = await Promise.all([
      fetch(`/api/v1/admin/rules/overrides/?workspace_slug=${encodeURIComponent(workspaceSlug)}&active_only=1&limit=100`, {
        headers: { Authorization: `Bearer ${token}` },
      }),
      fetch(`/api/v1/admin/rules/feedback/stats/?workspace_slug=${encodeURIComponent(workspaceSlug)}&limit=100`, {
        headers: { Authorization: `Bearer ${token}` },
      }),
    ]);
    const ovBody = await ovResp.json();
    const fbBody = await fbResp.json();
    if (!ovResp.ok || !ovBody.ok) {
      $("ruleEditorMsg").textContent = `override load failed: ${ovBody.error || ovResp.status}`;
      return;
    }
    if (!fbResp.ok || !fbBody.ok) {
      $("ruleEditorMsg").textContent = `feedback load failed: ${fbBody.error || fbResp.status}`;
      return;
    }
    fillRows(
      "ruleOverridesBody",
      "ruleOverridesEmpty",
      ovBody.overrides || [],
      (row) => `<tr>
        <td class="num">${row.id}</td>
        <td>${row.rule_key || ""}</td>
        <td>${row.action || ""}</td>
        <td>${row.reason || ""}</td>
        <td>${row.actor || ""}</td>
        <td>${row.expires_at ? new Date(row.expires_at).toLocaleString("ja-JP") : "--"}</td>
        <td>${row.updated_at ? new Date(row.updated_at).toLocaleString("ja-JP") : "--"}</td>
      </tr>`
    );
    fillRows(
      "ruleFeedbackBody",
      "ruleFeedbackEmpty",
      fbBody.stats || [],
      (row) => `<tr>
        <td>${row.rule_key || ""}</td>
        <td class="num">${fmtInt(row.total_feedback)}</td>
        <td class="num">${fmtInt(row.false_positive_count)}</td>
        <td class="num">${fmtInt(row.true_positive_count)}</td>
        <td class="num">${Number((row.false_positive_rate || 0) * 100).toFixed(1)}%</td>
        <td>${row.last_feedback_at ? new Date(row.last_feedback_at).toLocaleString("ja-JP") : "--"}</td>
      </tr>`
    );
    $("ruleEditorMsg").textContent = `loaded overrides=${(ovBody.overrides || []).length}, feedback=${(fbBody.stats || []).length}`;
  }

  async function saveRuleOverride() {
    const { token, actor } = getRuleEditorContext();
    if (!token) {
      $("ruleEditorMsg").textContent = "admin token required";
      return;
    }
    const ruleKey = String(($("ruleKeyInput") && $("ruleKeyInput").value) || "").trim();
    const action = String(($("ruleActionInput") && $("ruleActionInput").value) || "observe").trim();
    const ttlHours = Number(($("ruleTtlInput") && $("ruleTtlInput").value) || 24);
    const reason = String(($("ruleReasonInput") && $("ruleReasonInput").value) || "").trim();
    if (!ruleKey) {
      $("ruleEditorMsg").textContent = "rule key is required";
      return;
    }
    const resp = await fetch("/api/v1/admin/rules/overrides/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "X-Admin-Actor": actor,
      },
      body: JSON.stringify({
        workspace_slug: workspaceSlug,
        rule_key: ruleKey,
        action,
        ttl_hours: Math.max(1, Math.min(Number.isFinite(ttlHours) ? ttlHours : 24, 720)),
        reason,
        actor,
      }),
    });
    const body = await resp.json();
    if (!resp.ok || !body.ok) {
      $("ruleEditorMsg").textContent = `save failed: ${body.error || resp.status}`;
      return;
    }
    $("ruleEditorMsg").textContent = `override saved: ${body.override.rule_key} -> ${body.override.action}`;
    await loadRuleEditor();
  }

  async function submitRuleFeedback(verdict) {
    const { token, actor } = getRuleEditorContext();
    if (!token) {
      $("ruleEditorMsg").textContent = "admin token required";
      return;
    }
    const ruleKey = String(($("ruleKeyInput") && $("ruleKeyInput").value) || "").trim();
    const note = String(($("ruleReasonInput") && $("ruleReasonInput").value) || "").trim();
    if (!ruleKey) {
      $("ruleEditorMsg").textContent = "rule key is required";
      return;
    }
    const resp = await fetch("/api/v1/admin/rules/feedback/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "X-Admin-Actor": actor,
      },
      body: JSON.stringify({
        workspace_slug: workspaceSlug,
        rule_key: ruleKey,
        verdict,
        actor,
        note,
      }),
    });
    const body = await resp.json();
    if (!resp.ok || !body.ok) {
      $("ruleEditorMsg").textContent = `feedback failed: ${body.error || resp.status}`;
      return;
    }
    $("ruleEditorMsg").textContent = `feedback accepted: ${ruleKey} (${verdict})`;
    await loadRuleEditor();
  }

  async function loadTestIpEntries() {
    const { token } = getTestIpAdminContext();
    if (!token) {
      fillRows("testIpBody", "testIpEmpty", [], () => "");
      $("testIpOpsMsg").textContent = "admin token required to load/edit";
      return;
    }
    const resp = await fetch(`/api/v1/admin/workspaces/test-ips/?workspace_slug=${encodeURIComponent(workspaceSlug)}&include_expired=1&limit=200`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await resp.json();
    if (!resp.ok || !body.ok) {
      $("testIpOpsMsg").textContent = `load failed: ${body.error || resp.status}`;
      return;
    }
    const rows = body.entries || [];
    fillRows(
      "testIpBody",
      "testIpEmpty",
      rows,
      (row) => `<tr>
        <td class="num">${row.id}</td>
        <td>${row.ip_cidr}</td>
        <td>${row.status}${row.is_expired ? " (expired)" : ""}</td>
        <td>${row.expires_at ? new Date(row.expires_at).toLocaleString("ja-JP") : "--"}</td>
        <td>${row.updated_at ? new Date(row.updated_at).toLocaleString("ja-JP") : "--"}</td>
        <td>${row.created_by || ""}</td>
        <td>${row.note || ""}</td>
        <td>${row.status === "active" ? `<button data-testip-deactivate="${row.id}">deactivate</button>` : ""}</td>
      </tr>`
    );
    document.querySelectorAll("button[data-testip-deactivate]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const { token: t } = getTestIpAdminContext();
        if (!t) {
          $("testIpOpsMsg").textContent = "admin token required";
          return;
        }
        const id = Number(btn.getAttribute("data-testip-deactivate"));
        const r = await fetch(`/api/v1/admin/workspaces/test-ips/${id}/deactivate/`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${t}`,
          },
          body: JSON.stringify({ workspace_slug: workspaceSlug }),
        });
        const b = await r.json();
        if (!r.ok || !b.ok) {
          $("testIpOpsMsg").textContent = `deactivate failed: ${b.error || r.status}`;
          return;
        }
        $("testIpOpsMsg").textContent = `deactivated test-ip id=${id}`;
        await load();
      });
    });
    $("testIpOpsMsg").textContent = `loaded ${rows.length} test-ip rules`;
  }

  function renderIncidents(data) {
    const filter = ($("incidentFilter") && $("incidentFilter").value) || "all";
    const allRows = data.soc_incidents_recent || [];
    const rows = filter === "all" ? allRows : allRows.filter((x) => String(x.status || "") === filter);
    fillRows(
      "incidentsBody",
      "incidentsEmpty",
      rows,
      (row) => `<tr>
        <td>${new Date(row.updated_at).toLocaleString("ja-JP")}</td>
        <td>${row.title}<div style="color:#91a3bf;font-size:0.75rem;">${row.correlation_key || ""}</div></td>
        <td>${row.severity}</td>
        <td>${row.status}</td>
        <td class="num">${fmtInt(row.event_count)}</td>
        <td>${fmtWindow(row)}</td>
        <td>${incidentActions(row)}</td>
      </tr>`
    );
    document.querySelectorAll("#incidentsBody button[data-id][data-act]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const token = String(($("adminToken") && $("adminToken").value) || "").trim();
        if (!token) {
          $("incidentMsg").textContent = "admin token required";
          return;
        }
        const actor = String(($("adminActor") && $("adminActor").value) || "soc_operator").trim() || "soc_operator";
        const incidentId = Number(btn.getAttribute("data-id"));
        const action = String(btn.getAttribute("data-act") || "triage");
        try {
          const resp = await fetch(`/api/v1/admin/soc/incidents/${incidentId}/triage/`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
              "X-Admin-Actor": actor,
            },
            body: JSON.stringify({ workspace_slug: workspaceSlug, action, note: "incident-first-ui" }),
          });
          const body = await resp.json();
          if (!resp.ok || !body.ok) {
            $("incidentMsg").textContent = `triage failed: ${body.error || resp.status}`;
            return;
          }
          $("incidentMsg").textContent = `updated incident #${incidentId} -> ${body.incident.status}`;
          await load();
        } catch (err) {
          $("incidentMsg").textContent = `triage failed: ${err}`;
        }
      });
    });
  }

  async function renderSummary(data, refreshAdmin) {
    lastSummary = data;
    workspaceSlug = (data.waf && data.waf.workspace_slug) || "lab";
    $("lastUpdate").textContent = `Updated ${new Date(data.generated_at).toLocaleString("ja-JP")}`;
    $("kpiTotal").textContent = fmtInt(data.kpis.total_requests_24h);
    $("kpiBlocked").textContent = fmtInt(data.kpis.blocked_429_24h);
    $("kpiRate").textContent = `${Number(data.kpis.block_rate_24h || 0).toFixed(2)}%`;
    $("kpiRt").textContent = `${Number(data.kpis.avg_response_time_ms_24h || 0).toFixed(1)}ms`;
    const modeSummary = data.mode_summary || {};
    $("kpiWaf").textContent = modeSummary.edge_enforcement_mode || (data.waf && data.waf.enabled ? `ON (${data.waf.mode})` : "OFF");
    $("kpiSensorMode").textContent = modeSummary.sensor_scoring_mode || "--";
    $("kpiEffectiveMode").textContent = modeSummary.effective_response_mode || "--";
    $("kpiNotify").textContent = fmtInt((data.integration && data.integration.enabled_channel_count) || 0);
    if ($("excludeTestIpToggle")) {
      $("excludeTestIpToggle").checked = Boolean(data.definitions && data.definitions.exclude_test_ip_on_kpi);
    }

    drawBars(
      $("chartBlocked"),
      data.blocked_series_24h.map((p) => ({ label: p.bucket, value: p.count })),
      "#f87171"
    );
    drawLine(
      $("chartRt"),
      [
        data.response_time_series_24h.map((p) => ({ label: p.bucket, value: p.p50_ms })),
        data.response_time_series_24h.map((p) => ({ label: p.bucket, value: p.p95_ms })),
        data.response_time_series_24h.map((p) => ({ label: p.bucket, value: p.p99_ms })),
      ],
      ["#75b6ff", "#f59e0b", "#f87171"]
    );

    fillRows("ipsBody", "ipsEmpty", data.top_blocked_ips_48h, (row) => `<tr><td>${row.label}</td><td class="num">${fmtInt(row.count)}</td></tr>`);
    fillRows("urisBody", "urisEmpty", data.high_activity_uris_24h, (row) => `<tr><td>${row.label}</td><td class="num">${fmtInt(row.count)}</td></tr>`);
    fillRows("reasonsBody", "reasonsEmpty", data.block_reasons_24h, (row) => `<tr><td>${row.label}</td><td class="num">${fmtInt(row.count)}</td></tr>`);
    fillRows("rulesBody", "rulesEmpty", data.detected_rules_24h, (row) => `<tr><td>${row.rule}</td><td>${row.severity}</td><td class="num">${fmtInt(row.hits)}</td></tr>`);
    fillRows(
      "latencyAlertsBody",
      "latencyAlertsEmpty",
      data.action_latency_alerts_recent || [],
      (row) => `<tr>
        <td>${new Date(row.created_at).toLocaleString("ja-JP")}</td>
        <td>${row.action || ""}</td>
        <td>${row.bucket || ""}</td>
        <td class="num">${Number(row.p95_ms || 0).toFixed(1)}</td>
        <td class="num">${Number(row.p99_ms || 0).toFixed(1)}</td>
        <td class="num">${Number(row.threshold_p95_ms || 0).toFixed(1)}</td>
        <td class="num">${Number(row.threshold_p99_ms || 0).toFixed(1)}</td>
      </tr>`
    );
    const chain = data.soc_chain_24h || {};
    const multi = data.soc_multi_sensor_24h || {};
    const chainRows = [
      { stage: "rule_hits", count: chain.rule_hits || 0, rate: 1.0 },
      { stage: "events", count: chain.events || 0, rate: chain.rule_to_event_rate || 0 },
      { stage: "incidents", count: chain.incidents || 0, rate: chain.event_to_incident_rate || 0 },
      { stage: "triaged_incidents", count: chain.triaged_incidents || 0, rate: chain.incident_to_triage_rate || 0 },
      { stage: "multi_sensor_incidents", count: multi.recent_multi_sensor_incidents || 0, rate: multi.recent_multi_sensor_rate || 0 },
    ];
    fillRows("socChainBody", "socChainEmpty", chainRows, (row) => `<tr><td>${row.stage}</td><td class="num">${fmtInt(row.count)}</td><td class="num">${fmtPct(row.rate)}</td></tr>`);
    const stack = (data.integration && data.integration.stack) || {};
    const remoteStatus = stack.xdr_remote_action_status || {};
    const stackRows = [
      { item: "xdr_event_links_24h", value: stack.xdr_event_links_24h || 0, note: "IPS events linked into XDR incidents" },
      { item: "xdr_link_pending", value: stack.xdr_link_pending || 0, note: "waiting for export/link completion" },
      { item: "xdr_remote_actions_24h", value: stack.xdr_remote_actions_24h || 0, note: "actions requested from XDR" },
      { item: "xdr_remote_status_requested", value: remoteStatus.requested || 0, note: "request queued on IPS side" },
      { item: "xdr_remote_status_completed", value: remoteStatus.completed || 0, note: "execution ack completed" },
      { item: "soc_open_incidents", value: stack.soc_open_incidents || 0, note: "approve/close in Incident Triage Queue" },
      { item: "soc_triaged_incidents_24h", value: stack.soc_triaged_incidents_24h || 0, note: "handled within 24h window" },
    ];
    fillRows(
      "stackStatusBody",
      "stackStatusEmpty",
      stackRows,
      (row) => `<tr><td>${row.item}</td><td class="num">${fmtInt(row.value)}</td><td>${row.note}</td></tr>`
    );
    fillRows(
      "stackSensorHealthBody",
      "stackSensorHealthEmpty",
      stack.sensor_type_health || [],
      (row) => `<tr><td>${row.sensor_type}</td><td class="num">${fmtInt(row.total)}</td><td class="num">${fmtInt(row.active)}</td><td class="num">${fmtInt(row.healthy_recent)}</td></tr>`
    );
    const livePanel = (data.integration && data.integration.live_panel) || {};
    const liveServices = Array.isArray(livePanel.services) ? livePanel.services : [];
    const liveSummary = livePanel.summary || {};
    $("stackLiveSummary").textContent =
      `configured=${fmtInt(liveSummary.configured_services || 0)} / reachable=${fmtInt(liveSummary.reachable_services || 0)} / cache=${fmtInt(livePanel.cache_sec || 0)}s`;
    fillRows(
      "stackLiveBody",
      "stackLiveEmpty",
      liveServices,
      (row) => {
        const status = String(row.status || "unknown");
        const healthText = compactPairs(row.health);
        const metricsText = compactPairs(row.metrics);
        const dashboardUrl = String(row.dashboard_url || "").trim();
        const dashboardCell = dashboardUrl ? `<a href="${dashboardUrl}" target="_blank" rel="noopener">open</a>` : "--";
        const error = String(row.error || "").trim();
        const statusText = error ? `${status} (${error})` : status;
        return `<tr>
          <td>${String(row.service || "").toUpperCase()}</td>
          <td>${statusText}</td>
          <td class="num">${fmtMs(row.latency_ms)}</td>
          <td>${healthText}</td>
          <td>${metricsText}</td>
          <td>${dashboardCell}</td>
        </tr>`;
      }
    );
    fillRows("uasBody", "uasEmpty", data.monitored_uas_24h, (row) => `<tr><td>${row.label}</td><td class="num">${fmtInt(row.count)}</td></tr>`);
    fillRows("uaClassBody", "uaClassEmpty", data.ua_classification_24h || [], (row) => `<tr><td>${row.label}</td><td class="num">${fmtInt(row.count)}</td></tr>`);
    renderIncidents(data);
    const tiRows = ((data.threat_intel || {}).recent_matches || []);
    fillRows(
      "tiMatchesBody",
      "tiMatchesEmpty",
      tiRows,
      (row) => `<tr>
        <td>${new Date(row.detected_at).toLocaleString("ja-JP")}</td>
        <td>${row.src_ip || ""}</td>
        <td>${row.rule || ""}</td>
        <td>${row.provider || ""}</td>
        <td class="num">${Number(row.score || 0).toFixed(1)}</td>
        <td class="num">${Number(row.confidence || 0).toFixed(2)}</td>
        <td>${row.detail || ""}</td>
      </tr>`
    );
    fillRows(
      "flowSignalsBody",
      "flowSignalsEmpty",
      data.flow_analysis_24h || [],
      (row) => `<tr><td>${row.signal || ""}</td><td class="num">${fmtInt(row.hits || 0)}</td></tr>`
    );
    fillRows(
      "notifyBody",
      "notifyEmpty",
      data.notification_recent || [],
      (row) => `<tr><td>${new Date(row.created_at).toLocaleString("ja-JP")}</td><td>${row.workspace_slug}</td><td>${row.channel_type}</td><td>${row.event_type}</td><td>${row.status}</td><td>${row.detail || ""}</td></tr>`
    );
    if (refreshAdmin) {
      await loadTestIpEntries();
      await loadRuleEditor();
    }
  }

  async function load() {
    const resp = await fetch("/api/v1/dashboard/summary/");
    const data = await resp.json();
    await renderSummary(data, true);
  }

  function connectWs() {
    if (ws) {
      try { ws.close(); } catch (_) {}
      ws = null;
    }
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const path = `/ws/secops/workspaces/${encodeURIComponent(workspaceSlug)}/`;
    ws = new WebSocket(`${proto}://${location.host}${path}`);
    ws.onopen = () => {
      if (wsRetryTimer) {
        clearTimeout(wsRetryTimer);
        wsRetryTimer = null;
      }
      const base = $("lastUpdate").textContent || "";
      $("lastUpdate").textContent = base.includes("WS:") ? base : `${base} | WS: connected`;
    };
    ws.onmessage = async (ev) => {
      try {
        const msg = JSON.parse(ev.data || "{}");
        if (msg && msg.type === "summary" && msg.summary) {
          await renderSummary(msg.summary, false);
        }
      } catch (_) {}
    };
    ws.onclose = () => {
      const base = $("lastUpdate").textContent || "";
      $("lastUpdate").textContent = base.includes("WS:") ? base.replace(/WS:\s*\w+/g, "WS: disconnected") : `${base} | WS: disconnected`;
      wsRetryTimer = setTimeout(() => {
        load().then(connectWs).catch(() => connectWs());
      }, 5000);
    };
    ws.onerror = () => {
      try { ws.close(); } catch (_) {}
    };
  }

  load().catch((err) => {
    $("lastUpdate").textContent = `load failed: ${err}`;
  }).then(() => {
    connectWs();
  });
  $("incidentFilter").addEventListener("change", () => { if (lastSummary) renderIncidents(lastSummary); });
  $("incidentRefreshBtn").addEventListener("click", () => { load().catch(() => {}); });
  $("refreshTestIpBtn").addEventListener("click", () => { loadTestIpEntries().catch(() => {}); });
  $("saveExcludeToggleBtn").addEventListener("click", async () => {
    const { token } = getTestIpAdminContext();
    if (!token) {
      $("testIpOpsMsg").textContent = "admin token required";
      return;
    }
    const exclude = Boolean(($("excludeTestIpToggle") && $("excludeTestIpToggle").checked) || false);
    const resp = await fetch("/api/v1/admin/workspaces/kpi-settings/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ workspace_slug: workspaceSlug, exclude_test_ip_on_kpi: exclude }),
    });
    const body = await resp.json();
    if (!resp.ok || !body.ok) {
      $("testIpOpsMsg").textContent = `save failed: ${body.error || resp.status}`;
      return;
    }
    $("testIpOpsMsg").textContent = `exclude_test_ip_on_kpi=${body.settings.exclude_test_ip_on_kpi}`;
    await load();
  });
  $("addTestIpBtn").addEventListener("click", async () => {
    const { token, actor } = getTestIpAdminContext();
    if (!token) {
      $("testIpOpsMsg").textContent = "admin token required";
      return;
    }
    const ipCidr = String(($("testIpValue") && $("testIpValue").value) || "").trim();
    if (!ipCidr) {
      $("testIpOpsMsg").textContent = "ip/cidr is required";
      return;
    }
    const expiresAt = String(($("testIpExpiresAt") && $("testIpExpiresAt").value) || "").trim();
    const note = String(($("testIpNote") && $("testIpNote").value) || "").trim();
    const resp = await fetch("/api/v1/admin/workspaces/test-ips/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "X-Admin-Actor": actor,
      },
      body: JSON.stringify({
        workspace_slug: workspaceSlug,
        ip_cidr: ipCidr,
        expires_at: expiresAt || null,
        note,
        actor,
      }),
    });
    const body = await resp.json();
    if (!resp.ok || !body.ok) {
      $("testIpOpsMsg").textContent = `add failed: ${body.error || resp.status}`;
      return;
    }
    $("testIpOpsMsg").textContent = `upserted ${body.entry.ip_cidr}`;
    await load();
  });
  $("ruleRefreshBtn").addEventListener("click", () => { loadRuleEditor().catch(() => {}); });
  $("ruleOverrideSaveBtn").addEventListener("click", () => { saveRuleOverride().catch(() => {}); });
  $("ruleFeedbackFpBtn").addEventListener("click", () => { submitRuleFeedback("false_positive").catch(() => {}); });
  $("ruleFeedbackTpBtn").addEventListener("click", () => { submitRuleFeedback("true_positive").catch(() => {}); });
})();
