const fetch = require("node-fetch");
const DEPS_DEV_ADVISORY = "https://api.deps.dev/v3alpha/advisories/";
const NVD_BASEURL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

// return id, summary, severity
async function handlePYSEC(element) {
    const githubAlias = element.aliases.find(alias => alias.startsWith("GHSA"));
    const nvdAlias = element.aliases.find(alias => alias.startsWith("CVE"));

    let githubAdvisory, nvd, cvss;    

    const endpoints = [];
    if (githubAlias) endpoints.push({url: DEPS_DEV_ADVISORY + githubAlias});
    if (nvdAlias) endpoints.push({url: NVD_BASEURL + nvdAlias, apiKey: process.env.NVD_APIKEY});

    // Maps each URL into a fetch() Promise
    var requests = endpoints.map(function (ep) {
        return fetch(ep.url, {headers: {'apiKey': ep.apiKey}})
            .then(function (response) {
                return response.json();
            })
    });
    
    // Resolve all the promises
    const responses = await Promise.all(requests);
    if (githubAlias) {
        githubAdvisory = responses[0];
    }
    if (nvdAlias) {
        // because we won't always have both ghsa and nvd
        nvd = githubAlias ? responses[1] : responses[0];
        const metrics = nvd.vulnerabilities[0].cve.metrics;
        if (metrics.cvssMetricV2) {
            cvss = metrics.cvssMetricV2[0].baseSeverity
        } else if (metrics.cvssMetricV30) {
            cvss = metrics.cvssMetricV30[0].cvssData.baseSeverity
        } else {
            cvss = metrics.cvssMetricV31[0].cvssData.baseSeverity
        }
    }
    return {
        id: element.id,
        summary: githubAdvisory?.title || "",
        severity: cvss?.toLowerCase() || ""
    }
}



module.exports = handlePYSEC;