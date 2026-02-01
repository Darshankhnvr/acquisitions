import { signInSchema, signUpSchema } from '../validations/auth.validation.js';
import logger from '../config/logger.js';

import { formatValidationError } from '../utils/format.js';
import { authenticateUser, createUser } from '../services/auth.service.js';
import { jwttoken } from '../utils/jwt.js';
import { cookies } from '../utils/cookies.js';

export const signUp = async (req, res, next) => {
  try {
    const validationResult = signUpSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'validation failed',
        details: formatValidationError(validationResult.error),
      });
    }

    const { name, email, password, role } = validationResult.data;

    const user = await createUser({ name, email, password, role });

    const token = jwttoken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    logger.info(`User registered successfully ${email}`);
    return res.status(201).json({
      message: 'User registered',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error('SignUp error', error);

    if (
      error instanceof Error &&
      error.message === 'User with this email already exists'
    ) {
      return res.status(409).json({
        error: 'Email already exist',
      });
    }

    return next(error);
  }
};

export const signIn = async (req, res, next) => {
  try {
    const validationResult = signInSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'validation failed',
        details: formatValidationError(validationResult.error),
      });
    }

    const { email, password } = validationResult.data;

    const user = await authenticateUser(email, password);

    const token = jwttoken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    logger.info(`User logged in successfully ${email}`);
    return res.status(200).json({
      message: 'User logged in',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error('SignIn error', error);

    if (
      error instanceof Error &&
      (error.message === 'User not found' ||
        error.message === 'Invalid credentials')
    ) {
      return res.status(401).json({
        error: 'Invalid email or password',
      });
    }

    return next(error);
  }
};

export const signOut = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');

    logger.info('User logged out successfully');
    return res.status(200).json({
      message: 'User logged out',
    });
  } catch (error) {
    logger.error('SignOut error', error);
    return next(error);
  }
};
