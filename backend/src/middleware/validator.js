const Joi = require('joi');

const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required()
});

const loginSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(50).required(),
  password: Joi.string().min(6).max(128).required()
});

const noteSchema = Joi.object({
  title: Joi.string().min(1).max(120).required(),
  content: Joi.string().min(1).max(5000).required(),
  category: Joi.string().alphanum().max(30).default('general'),
  is_confidential: Joi.boolean().default(false)
});

function validateBody(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
    if (error) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: error.details.map((d) => d.message)
      });
    }
    req.validatedBody = value;
    next();
  };
}

module.exports = {
  validateBody,
  registerSchema,
  loginSchema,
  noteSchema
};
