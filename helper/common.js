var uuidv1 = require('uuid/v1');

module.exports = {
    getCurrentDateTimeUtc: getCurrentDateTimeUtc,
    generateUserAuthToken: generateUserAuthToken,
    formatRestApiSuccess: formatRestApiSuccess,
    formatRestApiError: formatRestApiError,
    formatRestApiSqlError: formatRestApiSqlError
};

function getCurrentDateTimeUtc() {
    return new Date().toISOString();
}

function generateUserAuthToken() {
    return uuidv1();
}

function formatRestApiSuccess(data) {
    return {
        data: data,
    };
}

function formatRestApiError(errorCode, errorMessage) {
    return {
        errorCode: errorCode,
        errorMessage: errorMessage
    };
}

function formatRestApiSqlError(error) {
    return {
        errorCode: error.code,
        errorMessage: error.sqlMessage
    }
}