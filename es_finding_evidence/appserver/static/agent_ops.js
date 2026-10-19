require(["jquery", "splunkjs/mvc", "splunkjs/mvc/simplexml/ready!"], function ($, mvc) {
  function formKey() {
    var match = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  function restUrl(path) {
    var prefix = window.location.pathname.split("/app/")[0] || "";
    return prefix + "/splunkd/__raw/services" + path;
  }

  function token(name, fallback) {
    var submitted = mvc.Components.get("submitted") || mvc.Components.get("default");
    if (!submitted) {
      return fallback;
    }
    var value = submitted.get(name);
    return value == null || value === "" ? fallback : value;
  }

  function setStatus(text, kind) {
    var el = document.getElementById("fea-agent-status");
    if (!el) {
      return;
    }
    el.textContent = text || "";
    el.className = "fea-judge-status" + (kind ? " fea-" + kind : "");
  }

  $("#fea-run-agent").on("click", function () {
    var body = {
      mode: token("mode", "demo"),
      run_searches: token("run_searches", "true"),
      limit: token("limit", "12"),
      tasks: "gather_evidence,score,enrich,persist,emit",
    };
    setStatus("Running agent cycle…");
    $.ajax({
      url: restUrl("/es_finding_evidence/agent/run"),
      type: "POST",
      contentType: "application/json",
      data: JSON.stringify(body),
      headers: {
        "X-Requested-With": "XMLHttpRequest",
        "X-Splunk-Form-Key": formKey(),
      },
    })
      .done(function (data) {
        var count = data && data.count != null ? data.count : "?";
        var errors = data && data.errors ? data.errors.length : 0;
        setStatus("Cycle finished. Findings=" + count + " errors=" + errors + ". Enrichment was posted onto each finding (and stored for this dashboard).", "ok");
      })
      .fail(function (xhr) {
        var msg = (xhr.responseJSON && xhr.responseJSON.error) || xhr.responseText || "agent run failed";
        setStatus(String(msg), "err");
      });
  });
});
