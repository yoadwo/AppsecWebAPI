function handleGHSA(element) {
    console.log("ghsa");
    return {
        id: element.id,
        summary: element.summary,
        severity: element.database_specific.severity.toLowerCase(),
    }
}

module.exports = handleGHSA;