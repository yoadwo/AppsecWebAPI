const fetch = require("node-fetch");

const Responses = require("../common/responses");

exports.handler = async (event) => {
  console.log("event: ", event);

  if (!event.queryStringParameters) {
    return Responses._400({ message: "missing request parameters" });
  }

  let imageName = event.queryStringParameters.imageName.toLowerCase();
  let imageTag = event.queryStringParameters.imageTag.toLowerCase();

  console.log(`image name: ${imageName}, image version: ${imageTag}`);

  let jwtToken = await authenticateUser();
  if (jwtToken == null) {
    return Responses._403({ message: "could not authenticate" });
  }

  // query docker hub for image hash
  console.log("query docker image");
  let images = await readImageInTag(jwtToken, imageName, imageTag);

  // query docker hub graphql for image's cves
  console.log("query docker cve");
  let results = await readCVEsForImage(jwtToken, images);

  return Responses._200({ name: imageName, version: imageTag, results });
};

async function authenticateUser() {
  const loginUrl = "https://hub.docker.com/v2/users/login";
  const username = process.env.DOCKERHUB_USER;
  const password = process.env.DOCKERHUB_PWD;

  // Perform login request to obtain JWT token
  const loginResponse = await fetch(loginUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username: username,
      password: password,
    }),
  });

  if (loginResponse.ok) {
    const loginData = await loginResponse.json();
    const jwtToken = loginData.token;

    console.log("JWT Token received");
    return jwtToken;
  } else {
    return null;
  }
}

async function readImageInTag(jwtToken, imageName, imageTag) {
  // Subsequent request with JWT token in Authorization header
  const readTagsUrl = `https://hub.docker.com/v2/namespaces/library/repositories/${imageName}/tags/${imageTag}`;
  const headers = {
    Authorization: `Bearer ${jwtToken}`,
    "Content-Type": "application/json",
  };

  const tagsResponse = await fetch(readTagsUrl, {
    method: "GET",
    headers,
  });

  if (tagsResponse.ok) {
    const tagsData = await tagsResponse.json();
    const images = tagsData.images;

    console.log("got digest: ", images);
    return images;
  } else {
    console.error("could not read digest image url", tagsResponse);
    return null;
  }
}

async function readCVEsForImage(jwtToken, images) {
  // Subsequent request with JWT token in Authorization header
  const ImageCVEsUrl = "https://api.dso.docker.com/v1/graphql";
  const headers = {
    Authorization: `Bearer ${jwtToken}`,
    "Content-Type": "application/json",
  };
  let graphQuery = {
    query: `
        query baseImagesByDigest($context: Context!, $digest: String!) {
            baseImagesByDigest(context: $context, digest: $digest) {
              images {
                vulnerabilityReport {
                  critical
                  high
                  medium
                  low
                  unspecified
                }
              }
            }
          }
        `,
    variables: {
      digest: "",
      context: {},
    },
  };

  console.log("graph query: ", graphQuery);

  const promises = images.map(async (image) => {
    graphQuery.variables.digest = image.digest;

    try {
      const graphqlQueryResponse = await fetch(ImageCVEsUrl, {
        method: "POST",
        headers,
        body: JSON.stringify({
          query: graphQuery.query,
          variables: graphQuery.variables,
        }),
      });

      if (graphqlQueryResponse.ok) {
        const dockerHubImageData = await graphqlQueryResponse.json();
        return {
          arch: image.architecture,
          os: image.os,
          vulnerabilities: dockerHubImageData.data.baseImagesByDigest[0].images,
        };
      } else {
        console.warn("could not read digest from URL", graphqlQueryResponse);
        return null;
      }
    } catch (error) {
      console.error("An error occurred:", error);
      return null;
    }
  });

  const results = await Promise.all(promises);
  const filteredResults = results.filter((image) => image !== null);

  return filteredResults;
}
