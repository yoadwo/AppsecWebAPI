const fetch = require("node-fetch");
const cheerio = require('cheerio');
const Responses = require("../common/responses");

const SNYK_BASEURL = 'https://security.snyk.io';
const SNYK_VULNS_TABLE = '.vue--table.vulns-table__table';
const SNYK_SEVERITY_ITEM = '.vue--severity__item';
const SNYK_SEVERITY_PATTERN = /vue--severity__item--(.*)/;
const SNYK_VULNERABILITY_COLUMN_PATTERN = 'a[data-snyk-test="vuln table title"]';
const SNYK_AFFECTS_COLUMN_PATTERN = 'a[data-snyk-test="vuln package"]';
const SNYK_TYPE_COLUMN_PATTERN = 'td:nth-child(3) span';
const SNYK_HTML_MODIFIED = 'HTML cannot be parsed, page may have been changed by snyk';

exports.handler = async (event) => {
  console.log("query string params: ", event.queryStringParameters);

  if (!event.queryStringParameters) {
    return Responses._400({ message: "missing request parameters" });
  }

  const packageName = event.queryStringParameters.packageName; //case sensitive
  const repo = event.queryStringParameters.repo;

  console.log('package name and repo: ', packageName, repo);

  const html = await fetch(`${SNYK_BASEURL}/vuln/?search=${packageName}`, {
    method: 'GET',
    redirect: 'follow',
  }).then((r) => r.text());

  const $ = cheerio.load(html);
  const vulnsTable = $(SNYK_VULNS_TABLE);

  if (vulnsTable.length == 0) {
    console.log('No results found for the search term.');
    return {
      data: []
    };
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

    const packageHrefString = extractPackageHref(row);

    const vulnerabilityString = extractVulnerability(row);

    const packageRepoString = extractRepo(row);

    const severityString = extractSeverity(row);

    if ([
      packageNameString,
      packageHrefString,
      vulnerabilityString,
      packageRepoString,
      severityString]
      .includes(undefined)){
      throw new Error(SNYK_HTML_MODIFIED)
    }    

    packagesInfo.push({
      name: packageNameString,
      link: SNYK_BASEURL + '/' + packageHrefString,
      type: vulnerabilityString,
      repo: packageRepoString,
      severity: severityString
    })
  });
  return packagesInfo;
}

function extractPackageName(row) {
  const packageNameElement = row.find(SNYK_AFFECTS_COLUMN_PATTERN);
  if (packageNameElement == null) {
    console.warn('Expecting element "a" when looking for package title column, but none was found');
    return undefined;
  } else {
    return packageNameElement.text().trim();
  }
}

function extractPackageHref(row){
  const packageNameElement = row.find(SNYK_VULNERABILITY_COLUMN_PATTERN);
  if (packageNameElement == null) {
    console.warn('Expecting element "a" when looking for package vulnerability column, but none was found');
    return undefined;
  }
  const href = packageNameElement.attr('href');
  if (href == null) {
    console.warn('Expecting href attribute when looking in package vulnerability element, but none was found');
    return undefined;
  }
  return href;
}

function extractVulnerability(row) {
  const vulnerabilityElement = row.find(SNYK_VULNERABILITY_COLUMN_PATTERN);
  if (vulnerabilityElement == null) {
    console.warn('Expecting element "a" when looking for row title, but none was found');
    return undefined;;
  } else {
    return vulnerabilityElement.text().trim();
  }
}

function extractRepo(row) {
  const packageRepoElement = row.find(SNYK_TYPE_COLUMN_PATTERN);
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
