const fetch = require("node-fetch");
const cheerio = require('cheerio');
const Responses = require("../common/responses");

const SNYK_VULNS_TABLE = '.vue--table.vulns-table__table';
const SNYK_SEVERITY_ICON = '.vue--severity__item';
const SEVERITY_PATTERN = /vue--severity__item--(.*)/;

exports.handler = async (event) => {
  console.log("query string params: ", event.queryStringParameters);

  if (!event.queryStringParameters) {
    return Responses._400({ message: "missing request parameters" });
  }

  const packageName = event.queryStringParameters.packageName; //case sensitive
  const repo = event.queryStringParameters.repo;

  console.log('package name and repo: ', packageName, repo);

  const html = await fetch(`https://security.snyk.io/vuln/?search=${packageName}`, {
    method: 'GET',
    redirect: 'follow',
  }).then((r) => r.text());

  const packagesInfo = extractPackagesInfoFromTable(html);
  console.log("packages found: ", packagesInfo);

  const filteredPackages = packagesInfo.filter(pi => {
    return pi.repo.toLowerCase() == repo.toLowerCase() &&
      pi.name.toLowerCase() == packageName.toLowerCase() &&
      pi.type == "Malicious Package"
  });

  console.log("packages filtered: ", filteredPackages);

  return Responses._200(filteredPackages.map(pkg => {
    return {
      severity: pkg.severity
    }
  }));
}

function extractPackagesInfoFromTable(html) {
  const packagesInfo = [];

  const $ = cheerio.load(html);
  const vulnsTable = $(SNYK_VULNS_TABLE);

  if (vulnsTable.length == 0) {
    console.log('No results found for the search term.');
    return packagesInfo;
  }

  // Enumerate and print the rows
  vulnsTable.find('tbody > tr').each((index, element) => {
    const row = $(element);

    const packageNameElement = extractNameElement(row);
    if (packageNameElement == null) {
      console.warn('Expecting element "a" when looking for package title, but none was found');
      return;
    }

    const vulnerabilityElement = extractVulnerabilityElement(row);
    if (vulnerabilityElement == null) {
      console.warn('Expecting element "a" when looking for row title, but none was found');
      return;
    }

    const packageRepoElement = extractRepoElement(row);
    if (packageRepoElement == null || packageRepoElement.attr('type') === undefined) {
      console.warn('Expecting third column to contain type when looking for severity icon, but none was found');
      return;
    }

    const severityText = extractSeverity(row);
    if (severityText == null) {
      return;
    }

    packagesInfo.push({
      name: packageNameElement.text().trim(),
      type: vulnerabilityElement.text().trim(),
      repo: packageRepoElement.text().trim(),
      severity: severityText
    })
  });
  return packagesInfo;
}

function extractNameElement(row) {
  return row.find('a[data-snyk-test="vuln package"]');
}

function extractVulnerabilityElement(row) {
  return row.find('a[data-snyk-test="vuln table title"]');
}

function extractRepoElement(row) {
  return row.find('td:nth-child(3) span');
}

function extractSeverity(row) {
  const severityItem = row.find(SNYK_SEVERITY_ICON);
  if (severityItem == null) {
    console.warn('Expecting specific class when looking for severity icon, but none was found');
    return;
  }
  const classes = severityItem.attr('class').split(' ');
  const severityClass = classes[1];
  const match = new RegExp(SEVERITY_PATTERN).exec(severityClass);
  if (match == null || match.length < 2) {
    console.warn('Expecting specific class when looking for severity text, but none was found');
    return;
  }
  return match[1];

}
