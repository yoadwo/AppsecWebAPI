const fetch = require("node-fetch");
//const fetch = require('../common/fetch');

const Responses = require("../common/responses");
const handleApiResponse = require("../../osv.dev-parsers/osv-parsers");

const osvScannerUrl = 'https://api.osv.dev/v1/query';

exports.handler = async (event) => {
  console.log("query string params: ", event.queryStringParameters);

  if (!event.queryStringParameters) {
    return Responses._400({ message: "missing request parameters" });
  }

  let packageName = event.queryStringParameters.packageName; //case sensitive
  let packageVersion = event.queryStringParameters.packageVersion;
  let repo = event.queryStringParameters.repo;

  console.log(`package name: ${packageName}, package version: ${packageVersion}, repository: ${repo}`);

  const osvScannerResponse = await fetch(osvScannerUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      version: packageVersion,
      package: {
        name: packageName,
        ecoSystem: repo,
      },
    }),
  });
  const osvScannerData = await osvScannerResponse.json();
  //console.log('osv.dev response: ', osvScannerData);
  const response = await handleApiResponse(osvScannerData);
  //const mappedOsvScannerData = manipulateOsvScannerData(osvScannerData);

  //console.log("mapped osv scanner data: ", mappedOsvScannerData);  

  return Responses._200(response);
};

function manipulateOsvScannerData(jsonObject){
  if (jsonObject.vulns && Array.isArray(jsonObject.vulns)) {
    const transformedVulns = jsonObject.vulns
    .filter(vuln => vuln.database_specific != null)
    .map((vuln) => {
      const transformedObj = {
        id: vuln.id,
        summary: vuln.summary,
        nist: vuln.aliases, // Rename 'aliases' to 'nist'
        ghSeverity: vuln.database_specific.severity.toLowerCase(),
      };
      return transformedObj;
    });

    // Update the 'vulns' property with the transformed array
    jsonObject.vulns = transformedVulns;
  }
  return jsonObject;
}
