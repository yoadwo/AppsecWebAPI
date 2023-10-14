const fetch = require("node-fetch");
const Responses = require("../common/responses");

exports.handler = async (event) => {
    console.log("query string params: ", event.queryStringParameters);
  
    if (!event.queryStringParameters) {
      return Responses._400({ message: "missing request parameters" });
    }
  
    let packageName = event.queryStringParameters.packageName; //case sensitive
    let packageVersion = event.queryStringParameters.packageVersion;
    
    return Responses._200({});
}