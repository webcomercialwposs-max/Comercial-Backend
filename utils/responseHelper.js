// Función genérica para enviar respuestas
const sendResponse = (res, statusCode, message, data = null, error = null) => {
  const response = {
    success: statusCode >= 200 && statusCode < 400,
    status: statusCode,
    message: message,
  };
  if (data) response.data = data;
  if (error) response.error = error;
  res.status(statusCode).json(response);
};

// Funciones específicas para diferentes tipos de respuestas
const success = (res, statusCode, data, message = 'Success') => {
  sendResponse(res, statusCode, message, data);
};

const badRequest = (res, message, errors = null) => {
  sendResponse(res, 400, message, null, errors);
};

const unauthorized = (res, message) => {
  sendResponse(res, 401, message);
};

const forbidden = (res, message) => {
  sendResponse(res, 403, message);
};

const notFound = (res, message) => {
  sendResponse(res, 404, message);
};

const serverError = (res, message) => {
  sendResponse(res, 500, message);
};

module.exports = {
  success,
  badRequest,
  unauthorized,
  forbidden,
  notFound,
  serverError,
};
