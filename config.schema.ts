import * as Joi from 'joi';

export const configValidationSchema = Joi.object({
  PORT: Joi.number().default(8000),
  JWT_SECRET: Joi.string().required(),
  MONGO_URI: Joi.string().required(),
  STAGE: Joi.string().valid('dev', 'prod').required(),
});
