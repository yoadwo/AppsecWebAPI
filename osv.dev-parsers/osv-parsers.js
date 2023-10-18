const handlePYSEC = require("../osv.dev-parsers/pysec");
const handleGHSA = require("../osv.dev-parsers/ghsa");
const handleMalware = require("../osv.dev-parsers/mal");

const OSV_DB_PATTERN = /(?<DB>[A-Z]+)-(?<EntryId>[\w\-]+)/;
const PYPI_DB = "PYSEC";
const GITHUB_SECURITY_ADVISORY_DB = "GHSA";
const GITHUB_MALWARE = "MAL";

async function handleApiResponse(osvScannerData) {
    const elementsWithSeverity = [];
    // https://www.freecodecamp.org/news/javascript-async-and-await-in-loops-30ecc5fb3939/
    // because await does not work properly with "for-each", just use regular for
    for (let index = 0; index < osvScannerData.vulns.length; index++) {
        let vulnerability = osvScannerData.vulns[index];
        const { DB } = OSV_DB_PATTERN.exec(vulnerability.id).groups;
        let vulnWithSeverity = {};
        switch (DB) {
            case PYPI_DB:
                // element has no severity, requires api call to nvd to get cvss
                vulnWithSeverity = await handlePYSEC(vulnerability);
                console.log("pysec success", vulnWithSeverity);
                break;
            case GITHUB_SECURITY_ADVISORY_DB:
                // element has github advisory rating
                vulnWithSeverity = handleGHSA(vulnerability);
                console.log("ghsa success", vulnWithSeverity);
                break;
            case GITHUB_MALWARE:
                // element won't have a rating, think just mark critical
                vulnWithSeverity = handleMalware(vulnerability);
                break;
            default:
                // Handle cases for other prefixes if needed
                vulnWithSeverity = defaultHandler(vulnerability);
                break;
        }
        elementsWithSeverity.push(vulnWithSeverity)
    };
    return elementsWithSeverity;
}

function defaultHandler(element) {
    console.log("default handler", element);
    return element;
}

module.exports = handleApiResponse;