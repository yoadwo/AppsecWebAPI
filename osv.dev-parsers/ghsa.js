function handleGHSA(element) {
    return {
        id: element.id,
        summary: element.summary,
        severity: element.database_specific.severity.toLowerCase(),
    }
}

module.exports = handleGHSA;