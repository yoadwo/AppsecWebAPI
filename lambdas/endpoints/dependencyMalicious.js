const fetch = require("node-fetch");
const cheerio = require('cheerio');
const Responses = require("../common/responses");

const SNYK_VULNS_TABLE = '.vue--table.vulns-table__table';
const SNYK_SEVERITY_ITEM = '.vue--severity__item';
const SNYK_SEVERITY_PATTERN = /vue--severity__item--(.*)/;
const SNYK_HTML_MODIFIED = 'HTML cannot be parsed, page may have been changed by snyk';

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

  const $ = cheerio.load(html);
  const vulnsTable = $(SNYK_VULNS_TABLE);

  if (vulnsTable.length == 0) {
    console.log('No results found for the search term.');
    return [];
  }

  let packagesInfo = [];
  try {
    packagesInfo = extractPackagesInfoFromTable($, vulnsTable);
    console.log("packages found: ", packagesInfo);
  } catch (e) {
    return Responses._500({error: e.message});
  }

  const filteredPackages = filterPackages(packagesInfo, repo, packageName);
  console.log("packages filtered: ", filteredPackages);

  return Responses._200({
    data: filteredPackages.map(pkg => {
      return {
        severity: pkg.severity
      }
    })
  })
}

function extractPackagesInfoFromTable($, vulnsTable) {
  const packagesInfo = [];

  // Enumerate and print the rows
  vulnsTable.find('tbody > tr').each((index, element) => {
    const row = $(element);

    const packageNameString = extractPackageName(row);

    const vulnerabilityString = extractVulnerability(row);

    const packageRepoString = extractRepo(row);

    const severityString = extractSeverity(row);

    if ([packageNameString, vulnerabilityString, packageRepoString, severityString].includes(undefined)){
      throw new Error(SNYK_HTML_MODIFIED)
    }    

    packagesInfo.push({
      name: packageNameString,
      type: vulnerabilityString,
      repo: packageRepoString,
      severity: severityString
    })
  });
  return packagesInfo;
}

function extractPackageName(row) {
  const packageNameElement = row.find('a[data-snyk-test="vuln package"]');
  if (packageNameElement == null) {
    console.warn('Expecting element "a" when looking for package title, but none was found');
    return undefined;
  } else {
    return packageNameElement.text().trim();
  }
}

function extractVulnerability(row) {
  const vulnerabilityElement = row.find('a[data-snyk-test="vuln table title"]');
  if (vulnerabilityElement == null) {
    console.warn('Expecting element "a" when looking for row title, but none was found');
    return undefined;;
  } else {
    return vulnerabilityElement.text().trim();
  }
}

function extractRepo(row) {
  const packageRepoElement = row.find('td:nth-child(3) span');
  if (packageRepoElement == null) {
    console.warn('Expecting third column to exist, but none was found');
    return undefined;
  }
  const repo = packageRepoElement.attr('type');
  if (repo == null){
    console.warn('Expecting third column to contain type as attribute, but none was found')
    return undefined;
  }
  
  return repo;  
}

function extractSeverity(row) {
  const severityItem = row.find(SNYK_SEVERITY_ITEM);
  if (severityItem == null) {
    console.warn('Expecting specific class when looking for severity, but none was found');
    return undefined;
  }
  console.log('severity item', severityItem);
  let classes = [];
  let match = [];
  try {
    classes = severityItem.attr('class').split(' ');
    const severityClass = classes[1];
    match = new RegExp(SNYK_SEVERITY_PATTERN).exec(severityClass);
    return match[1];
  } catch (e) {
    console.warn('Expecting specific class when looking for severity, but none was found');
    console.error(e);
    return undefined;
  }
}

function filterPackages(packagesInfo, repo, packageName) {
  return packagesInfo.filter(pi => {
    return pi.repo.toLowerCase() == repo.toLowerCase() &&
      pi.name.toLowerCase() == packageName.toLowerCase() &&
      pi.type == "Malicious Package";
  });
}
