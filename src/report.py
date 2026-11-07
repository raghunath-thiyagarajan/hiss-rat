"""Write every output file: CSV tables, results.json and the self contained HTML dashboard.

Runs score, impact, standards mapping and sensitivity in memory (so it also works on its own)
and then exports to outputs/. No raw identifiers are ever present in the inputs, so none can
reach the outputs. The dashboard has inline CSS and JavaScript and no external libraries.
"""
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import impact  # noqa: E402
import map_standards  # noqa: E402
import score  # noqa: E402
import sensitivity  # noqa: E402
from common import DATA_DIR, OUT_DIR, load_config, read_csv, write_csv, write_json  # noqa: E402


def build_results():
    cfg = load_config()
    systems = score.load_systems()
    sc = score.compute(systems, cfg)
    im = impact.compute(cfg)
    fam_map = map_standards.load_map()
    mp = map_standards.compute(fam_map=fam_map, cfg=cfg)
    tops = map_standards.top_findings(mp["findings"], sc["register"], cfg)
    sens = sensitivity.run(systems, cfg)
    sens_text, sens_summary = sensitivity.summarise(sens, cfg)
    totals = {k: sum(s[k.lower()] for s in systems) for k in ("Critical", "High", "Medium", "Low", "Info")}
    parse_summary = {}
    ps = os.path.join(DATA_DIR, "parse_summary.json")
    if os.path.exists(ps):
        with open(ps, encoding="utf-8") as fh:
            parse_summary = json.load(fh)
    return {
        "cfg": cfg, "systems": systems, "score": sc, "impact": im, "map": mp, "top": tops,
        "sens": sens, "sens_text": sens_text, "sens_summary": sens_summary, "totals": totals,
        "parse_summary": parse_summary,
    }


def results_json(r):
    cfg = r["cfg"]
    return {
        "note": "Findings are evidence from Nessus Essentials exports. Downtime values, tiers, size classes "
                "and revenue dependence are ASSUMED modelling inputs. No raw identifiers are included.",
        "reconciliation": {
            "html_files": r["parse_summary"].get("html_files_read"),
            "distinct_systems": len(r["systems"]),
            "severity_totals": r["totals"],
            "low_or_above": sum(s["low_plus"] for s in r["systems"]),
            "files_dropped_byte_identical": r["parse_summary"].get("byte_identical_files_dropped"),
            "files_dropped_alternative_export": r["parse_summary"].get("alternative_exports_dropped"),
        },
        "scoring": {"formula": "TS = 10C + 6H + 3M + 1L; R = TS x tier weight; index = 100 x R / max R",
                    "severity_weights": cfg["severity_weights"],
                    "tier_weights": {str(t): v["weight"] for t, v in cfg["tiers"].items()},
                    "risk_bands": cfg["risk_bands"]},
        "group": r["score"]["group"],
        "properties": r["score"]["properties"],
        "role_groups": r["score"]["roles"],
        "risk_register_top10": [{k: s[k] for k in ("rank", "system_id", "technical_score", "tier_weight",
                                                    "risk_score", "system_index", "risk_band")}
                                for s in r["score"]["register"][:10]],
        "impact_group_totals": r["impact"]["group"],
        "impact_by_property": r["impact"]["rows"],
        "guest_impact": r["impact"]["guest"],
        "standards_families": r["map"]["families"],
        "top_findings": r["top"][:15],
        "sensitivity": r["sens_summary"],
    }


def dashboard_payload(r):
    reg = [{k: s[k] for k in ("rank", "system_id", "property", "role", "tier", "critical", "high", "medium", "low",
                              "technical_score", "risk_score", "system_index", "risk_band")}
           for s in r["score"]["register"]]
    cfg = r["cfg"]
    labels = {code: p["label"] for code, p in cfg["properties"].items()}
    return {
        "totals": r["totals"], "systems": len(r["systems"]), "group": r["score"]["group"],
        "properties": r["score"]["properties"], "register": reg, "top": r["top"],
        "impactGroup": r["impact"]["group"], "impactRows": r["impact"]["rows"], "guest": r["impact"]["guest"],
        "standards": r["map"]["families"], "labels": labels, "sens": r["sens_summary"],
        "bands": cfg["risk_bands"],
    }


HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HISS-RAT Dashboard</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2430;--mute:#5b6675;--line:#d9dee5;--accent:#1f5f8b;
--c:#8a1f3d;--h:#d1453b;--m:#e08a2e;--l:#e7bf4a;--n:#9aa5b1;--warn:#fff4d6;--warnb:#e2b93b}
@media (prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1b212a;--ink:#e6eaf0;--mute:#9aa6b5;--line:#2c3541;
--accent:#6fb1de;--warn:#3a3217;--warnb:#a98a22}}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,Segoe UI,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:16px}
h1{font-size:1.5rem;margin:.2rem 0}
h2{font-size:1.15rem;margin:1.6rem 0 .5rem}
p.sub{color:var(--mute);margin:.1rem 0 .8rem}
.note{background:var(--warn);border:1px solid var(--warnb);border-radius:6px;padding:10px 12px;margin:10px 0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:12px 0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px}
.kpi b{display:block;font-size:1.35rem;overflow-wrap:anywhere}
.kpi span{color:var(--mute);font-size:.82rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px;margin:8px 0}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.88rem}
th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;white-space:nowrap}
td.wrapcell{white-space:normal;min-width:220px}
th{font-weight:600;color:var(--mute);position:sticky;top:0;background:var(--card)}
td.n,th.n{text-align:right}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:.78rem}
.Critical{background:var(--c)}.High{background:var(--h)}.Medium{background:var(--m)}.Low{background:var(--l);color:#222}.None{background:var(--n)}
.bar{display:inline-block;height:9px;background:var(--accent);border-radius:3px;vertical-align:middle}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0}
select,input{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink)}
.small{color:var(--mute);font-size:.82rem}
.lvl-High{color:var(--h);font-weight:600}.lvl-Medium{color:var(--m);font-weight:600}.lvl-Low{color:#8a7a1d;font-weight:600}.lvl-None{color:var(--mute)}
pre{white-space:pre-wrap;font-size:.82rem;margin:0}
</style></head><body><div class="wrap">
<h1>HISS-RAT dashboard</h1>
<p class="sub">Hotel Information Security Risk Assessment Toolkit: Nessus scan evidence for a multi property hotel group, scored by role criticality. The bundled sample data is synthetic.</p>
<div class="note"><b>Assumed values.</b> Downtime costs, asset tiers, property size classes, occupancy, ADR and revenue dependence are assumptions
(register A01 to A05) and have not been measured or validated with hotel management. Scan findings are evidence from Nessus
scans; scans run without credentials do not assess missing patches or local settings.</div>
<div class="kpis" id="kpis"></div>

<h2>Property totals</h2>
<div class="card scroll"><table id="tProps"></table></div>
<p class="small">Property risk index: sum of risk scores for the property, scaled so the highest property is 100.
Mean system index: average of the 0 to 100 system indices.</p>

<h2>Ranked risk register</h2>
<div class="filters">
<select id="fProp"><option value="">All properties</option></select>
<select id="fBand"><option value="">All bands</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>None</option></select>
<input id="fText" placeholder="Filter by role or id" aria-label="Filter">
</div>
<div class="card scroll"><table id="tReg"></table></div>
<p class="small" id="bandNote"></p>

<h2>Top findings</h2>
<div class="card scroll"><table id="tTop"></table></div>

<h2>Downtime impact (assumed)</h2>
<div class="note">Assumed values only. Cost = rooms x occupancy x ADR / 24 x (1 + food and beverage uplift) x revenue dependence x duration. Low, base and high use occupancy 55, 65 and 75 percent. Amounts in INR.</div>
<div class="card scroll"><table id="tImpG"></table></div>
<div class="filters"><select id="fImp"></select></div>
<div class="card scroll"><table id="tImpP"></table></div>

<h2>Guest impact by scenario (assumed, qualitative)</h2>
<div class="card scroll"><table id="tGuest"></table></div>

<h2>Standards mapping</h2>
<div class="card scroll"><table id="tStd"></table></div>
<p class="small">PCI DSS numbers marked "to be verified" were not confirmed against the standard text.</p>

<h2>Sensitivity</h2>
<div class="card"><pre id="sens"></pre></div>
</div>
<script id="payload" type="application/json">__PAYLOAD__</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('payload').textContent);
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
function fmt(n){return Number(n).toLocaleString('en-IN')}
function table(id,heads,rows,numCols,wrapCols){
  var t=document.getElementById(id);t.innerHTML='';
  var h=el('tr');heads.forEach(function(x,i){var th=el('th',numCols.indexOf(i)>=0?'n':'',x);h.appendChild(th)});
  var th=el('thead');th.appendChild(h);t.appendChild(th);
  var tb=el('tbody');
  rows.forEach(function(r){var tr=el('tr');
    r.forEach(function(c,i){var td=el('td',(numCols.indexOf(i)>=0?'n ':'')+((wrapCols||[]).indexOf(i)>=0?'wrapcell':''));
      if(c&&c.pill){td.appendChild(el('span','pill '+c.pill,c.pill))}
      else if(c&&c.lvl){td.appendChild(el('span','lvl-'+c.lvl,c.lvl))}
      else if(c&&c.bar!==undefined){td.appendChild(el('span','bar'));td.lastChild.style.width=Math.max(2,c.bar*1.2)+'px';td.appendChild(document.createTextNode(' '+c.txt))}
      else td.textContent=c;
      tr.appendChild(td)});
    tb.appendChild(tr)});
  t.appendChild(tb)}
var T=D.totals;
var k=document.getElementById('kpis');
[[D.systems,'systems scanned'],[T.Critical,'Critical'],[T.High,'High'],[T.Medium,'Medium'],[T.Low,'Low'],[T.Info,'Info'],
 [D.group.group_index,'group index (0 to 100)'],[D.group.worst_system,'highest risk system']].forEach(function(x){
  var d=el('div','kpi');d.appendChild(el('b','',x[0]));d.appendChild(el('span','',x[1]));k.appendChild(d)});
table('tProps',['Property','Systems','Critical','High','Medium','Low','Info','Risk index','Mean system index'],
 D.properties.map(function(p){return [p.property_label,p.systems_scanned,p.critical,p.high,p.medium,p.low,p.info,
  {bar:p.property_risk_index,txt:p.property_risk_index},p.mean_system_index]}),[1,2,3,4,5,6,8]);
var fp=document.getElementById('fProp');
Object.keys(D.labels).forEach(function(c){var o=el('option','',D.labels[c]);o.value=c;fp.appendChild(o)});
function renderReg(){
  var p=fp.value,b=document.getElementById('fBand').value,q=document.getElementById('fText').value.toLowerCase();
  var rows=D.register.filter(function(s){return (!p||s.property===p)&&(!b||s.risk_band===b)&&
    (!q||(s.system_id+' '+s.role).toLowerCase().indexOf(q)>=0)});
  table('tReg',['Rank','System','Role','Tier','C','H','M','L','TS','Risk score','Index','Band'],
   rows.map(function(s){return [s.rank,s.system_id,s.role,s.tier,s.critical,s.high,s.medium,s.low,s.technical_score,
    s.risk_score,s.system_index,{pill:s.risk_band}]}),[0,3,4,5,6,7,8,9,10]);}
['fProp','fBand'].forEach(function(i){document.getElementById(i).onchange=renderReg});
document.getElementById('fText').oninput=renderReg;renderReg();
var B=D.bands;document.getElementById('bandNote').textContent='Bands on risk score R = technical score x tier weight: Critical '+B.Critical+' or more, High '+B.High+' to '+(B.Critical-1)+', Medium '+B.Medium+' to '+(B.High-1)+', Low '+B.Low+' to '+(B.Medium-1)+'.';
table('tTop',['Rank','Finding','Family','Severity','Systems','Properties','Risk contribution'],
 D.top.slice(0,15).map(function(f){return [f.rank,f.finding,f.family.replace(/_/g,' '),{pill:f.severity},f.systems_affected,f.properties_affected,f.risk_contribution]}),[0,4,5,6],[1]);
table('tImpG',['Scenario','Duration h','Revenue dependence','Low','Base','High','Assumed RTO h'],
 D.impactGroup.map(function(g){return [g.scenario_id+' '+g.scenario,g.duration_hours,g.revenue_dependence,fmt(g.cost_low_inr),fmt(g.cost_base_inr),fmt(g.cost_high_inr),g.assumed_rto_hours]}),[1,2,3,4,5,6]);
var fi=document.getElementById('fImp');
Object.keys(D.labels).forEach(function(c){var o=el('option','',D.labels[c]);o.value=c;fi.appendChild(o)});
function renderImp(){var c=fi.value;
 table('tImpP',['Scenario','Rooms','ADR','Low','Base','High'],
  D.impactRows.filter(function(r){return r.property===c}).map(function(r){return [r.scenario_id+' '+r.scenario,r.rooms,fmt(r.adr_inr),fmt(r.cost_low_inr),fmt(r.cost_base_inr),fmt(r.cost_high_inr)]}),[1,2,3,4,5]);}
fi.onchange=renderImp;renderImp();
table('tGuest',['Scenario','Check in delay','Billing errors','Key card failure','Payment failure','Privacy exposure','Note'],
 D.guest.map(function(g){return [g.scenario_id+' '+g.scenario,{lvl:g.check_in_delay},{lvl:g.billing_errors},{lvl:g.key_card_failure},{lvl:g.payment_failure},{lvl:g.privacy_exposure},g.note]}),[],[6]);
table('tStd',['Finding family','Systems','ISO 27001:2022','PCI DSS v4.0.x','GDPR','Rationale'],
 D.standards.map(function(s){return [s.family,s.systems_affected,s.iso_27001_2022_control+' '+s.iso_control_title,s.pci_dss_v4_requirement+(s.pci_status!=='verified'?' (to be verified)':''),s.gdpr_article,s.rationale]}),[1],[0,2,5]);
var S=D.sens;
document.getElementById('sens').textContent=
 'Perturbations tested: '+S.perturbations+' (severity weights +/-20 percent, tier weights +/-1 level)\n'+
 'Spearman rho against base: min '+S.rho_min.toFixed(3)+', mean '+S.rho_mean.toFixed(3)+', max '+S.rho_max.toFixed(3)+'\n'+
 'Top 5 set unchanged in '+S.top5_set_stable_cases+' of '+S.perturbations+' cases; rank 1 unchanged in '+S.rank1_stable_cases+' of '+S.perturbations+'\n'+
 'Base top 5: '+S.base_top5.join(', ')+'\n\nDowntime cost range for the group, INR (ADR +/-20 percent, occupancy 55 to 75 percent; assumed)\n'+
 Object.keys(S.cost_range).map(function(s){return s+': '+fmt(S.cost_range[s].min)+' to '+fmt(S.cost_range[s].max)}).join('\n');
})();
</script></body></html>
"""


def write_dashboard(r, path):
    payload = json.dumps(dashboard_payload(r), ensure_ascii=True).replace("</", "<\\/")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(HTML.replace("__PAYLOAD__", payload))


def main():
    r = build_results()
    os.makedirs(OUT_DIR, exist_ok=True)
    shutil.copyfile(os.path.join(DATA_DIR, "systems_normalised.csv"), os.path.join(OUT_DIR, "systems_normalised.csv"))
    score.write_outputs(r["score"])
    impact.write_outputs(r["impact"])
    map_standards.write_outputs(r["map"])
    write_csv(os.path.join(OUT_DIR, "top_findings.csv"), r["top"], map_standards.TOP_FIELDS)
    sensitivity.write_outputs(r["sens"], r["cfg"])
    write_json(os.path.join(OUT_DIR, "results.json"), results_json(r))
    write_dashboard(r, os.path.join(OUT_DIR, "dashboard.html"))
    print("Wrote outputs to", os.path.relpath(OUT_DIR, os.getcwd()))
    for fn in sorted(os.listdir(OUT_DIR)):
        print("  ", fn)


if __name__ == "__main__":
    main()
