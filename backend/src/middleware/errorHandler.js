/**
 * Central Error Handler
 * Sanitizes errors to prevent Information Disclosure (OWASP A05:2021)
 */
function errorHandler(err, req, res, next) {
  // Log full error internally for security operations and debugging
  console.error(`[ERROR] ${new Date().toISOString()} - ${req.method} ${req.originalUrl}:`, err);

  // Default error message
  const statusCode = err.status || 500;
  const isProduction = process.env.NODE_ENV === 'production';

  res.status(statusCode).json({
    success: false,
    error: isProduction ? 'An unexpected server error occurred.' : (err.message || 'Internal server error'),
    // Never expose stack trace in production
    ...(isProduction ? {} : { stack: err.stack })
  });
}

module.exports = errorHandler;
