require(["jquery", "splunkjs/mvc", "splunkjs/mvc/simplexml/ready!"], function ($, mvc) {
  function formKey() {
    var match = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  function restUrl(path) {
    var prefix = window.location.pathname.split("/app/")[0] || "";
    return prefix + "/splunkd/__raw/services" + path;
  }

  function setStatus(text, kind) {
    var el = document.getElementById("fea-judge-status");
    if (!el) {
      return;
    }
    el.textContent = text || "";
    el.className = "fea-judge-status" + (kind ? " fea-" + kind : "");
  }

  function payloadFromForm() {
    return {
      name: $("#fea-name").val(),
      type: $("#fea-type").val(),
      mode: $("#fea-mode").val(),
      weight: $("#fea-weight").val(),
      enabled: $("#fea-enabled").val(),
      decision: $("#fea-decision").val(),
      score: $("#fea-score").val(),
      adjustment: $("#fea-adjustment").val(),
      rationale: $("#fea-rationale").val(),
      when_urgency: $("#fea-when_urgency").val(),
      when_status: $("#fea-when_status").val(),
      when_disposition: $("#fea-when_disposition").val(),
      when_triage_disposition: $("#fea-when_triage_disposition").val(),
      when_min_risk: $("#fea-when_min_risk").val(),
      when_title_contains: $("#fea-when_title_contains").val(),
      when_user_in: $("#fea-when_user_in").val(),
      python: $("#fea-python").val(),
    };
  }

  function call(method, path, body) {
    return $.ajax({
      url: restUrl(path),
      type: method,
      contentType: "application/json",
      data: body ? JSON.stringify(body) : undefined,
      headers: {
        "X-Requested-With": "XMLHttpRequest",
        "X-Splunk-Form-Key": formKey(),
      },
    });
  }

  function reloadJudgesTable() {
    var submitted = mvc.Components.get("submitted");
    if (submitted) {
      submitted.set("fea_reload", String(Date.now()));
    }
    $("body").trigger("click");
  }

  $("#fea-save").on("click", function () {
    var payload = payloadFromForm();
    setStatus("Saving " + payload.name + "…");
    call("POST", "/es_finding_evidence/judges", payload)
      .done(function () {
        setStatus("Saved judge " + payload.name + ". Reload the table if it does not refresh.", "ok");
        reloadJudgesTable();
      })
      .fail(function (xhr) {
        var msg = (xhr.responseJSON && xhr.responseJSON.error) || xhr.responseText || "save failed";
        setStatus(String(msg), "err");
      });
  });

  $("#fea-delete").on("click", function () {
    var name = $("#fea-name").val();
    if (!name) {
      setStatus("Name is required to delete.", "err");
      return;
    }
    setStatus("Deleting " + name + "…");
    call("DELETE", "/es_finding_evidence/judges?name=" + encodeURIComponent(name))
      .done(function () {
        setStatus("Deleted UI judge " + name + ".", "ok");
        reloadJudgesTable();
      })
      .fail(function (xhr) {
        var msg = (xhr.responseJSON && xhr.responseJSON.error) || xhr.responseText || "delete failed";
        setStatus(String(msg), "err");
      });
  });
});
