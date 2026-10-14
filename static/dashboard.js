(function () {
  const $ = (id) => document.getElementById(id);
  let outcomeChart, riskChart;

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function renderFeed(feed) {
    const body = $("feed");
    body.replaceChildren();
    if (!feed.length) {
      const tr = el("tr"); const td = el("td", "text-muted", "No downloads yet. Run simulate.py or download a file.");
      td.colSpan = 6; tr.appendChild(td); body.appendChild(tr); return;
    }
    feed.forEach((e) => {
      const tr = el("tr");
      tr.appendChild(el("td", "", e.ts));
      tr.appendChild(el("td", "", e.user));
      tr.appendChild(el("td", "", e.file));
      const tdo = el("td"); tdo.appendChild(el("span", "chip badge-" + e.outcome, e.outcome)); tr.appendChild(tdo);
      tr.appendChild(el("td", "score", e.score === null ? "-" : e.score));
      const why = el("td");
      if (e.reasons.length) {
        const d = el("details"); d.appendChild(el("summary", "", "Why"));
        const ul = el("ul", "reasons");
        e.reasons.forEach((r) => ul.appendChild(el("li", "", (r.points ? "+" + r.points + "  " : "") + r.text)));
        d.appendChild(ul); why.appendChild(d);
      }
      tr.appendChild(why); body.appendChild(tr);
    });
  }

  function renderCharts(data) {
    const c = data.counts;
    const labels = ["allowed", "warned", "blocked", "denied"];
    const vals = labels.map((k) => c[k]);
    const colors = ["#15803d", "#b45309", "#b91c1c", "#9ca3af"];
    if (!outcomeChart) {
      outcomeChart = new Chart($("outcomeChart"), { type: "bar",
        data: { labels, datasets: [{ data: vals, backgroundColor: colors }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });
    } else { outcomeChart.data.datasets[0].data = vals; outcomeChart.update(); }

    const pts = data.feed.filter((e) => e.score !== null).slice().reverse();
    const rl = pts.map((e) => e.ts), rv = pts.map((e) => e.score);
    const rc = pts.map((e) => (e.score >= 71 ? "#b91c1c" : e.score >= 31 ? "#b45309" : "#15803d"));
    if (!riskChart) {
      riskChart = new Chart($("riskChart"), { type: "line",
        data: { labels: rl, datasets: [{ data: rv, borderColor: "#1b2430", pointBackgroundColor: rc, pointRadius: 4, tension: .25 }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { min: 0, max: 100 } } } });
    } else { riskChart.data.labels = rl; riskChart.data.datasets[0].data = rv;
             riskChart.data.datasets[0].pointBackgroundColor = rc; riskChart.update(); }
  }

  async function refresh() {
    try {
      const r = await fetch("/api/stats", { credentials: "same-origin" });
      if (!r.ok) return;
      const d = await r.json();
      $("n-allowed").textContent = d.counts.allowed; $("n-warned").textContent = d.counts.warned;
      $("n-blocked").textContent = d.counts.blocked; $("n-incidents").textContent = d.open_incidents;
      renderFeed(d.feed); renderCharts(d);
    } catch (e) { /* keep last view */ }
  }
  refresh(); setInterval(refresh, 5000);
})();
