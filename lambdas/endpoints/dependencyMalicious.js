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
  
    let packageName = event.queryStringParameters.packageName; //case sensitive
    let packageVersion = event.queryStringParameters.packageVersion;

    console.log('package name and version: ', packageName, packageVersion);

    const html = await fetch(`https://security.snyk.io/vuln/?search=${packageName}`, {
      method: 'GET',
      redirect: 'follow',
    }).then((r) => r.text());

    const $ = cheerio.load(html);
    const vulnsTable = $(SNYK_VULNS_TABLE);

    if (vulnsTable.length > 0) {
      // Enumerate and print the rows
      vulnsTable.find('tbody > tr').each((index, element) => {
        const row = $(element);
        const title = row.find('a[data-snyk-test="vuln table title"]')
        if (title){
          console.log('Type:', title.text().trim());
          const severityItem = row.find(SNYK_SEVERITY_ICON);
          if (severityItem){
            const classes = severityItem.attr('class').split(' ');
            const severityClass = classes[1];
            const match = new RegExp(SEVERITY_PATTERN).exec(severityClass);
            if (match) {
              const extractedText = match[1];
              console.log(`Extracted Text: ${extractedText}`);
            } else {
              console.log('No match found.');
            }
          }
        }
      });
    } else {
      console.log('No results found for the search term.');
    }
    
    return Responses._200({});
}