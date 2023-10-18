function handleMalware(element){
    console.log("mal");
    let summary;
    if (element.database_specific.cwes){
        summary = element.database_specific.cwes[0].name
    } else {
        summary = "Malicious Package"
    }
    return {
        id: element.id,
        summary: summary
    };
}

module.exports = handleMalware;