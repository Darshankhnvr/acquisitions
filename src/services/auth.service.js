import logger from '../config/logger.js';
import bcrypt from 'bcrypt';
import { db } from '../config/database.js';
import { users } from '../models/user.model.js';
import { eq } from 'drizzle-orm';

export const hashPassword = async password => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (error) {
    logger.error('Error hashing the password: ', error);
    throw new Error('Failed to hash password');
  }
};

export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (error) {
    logger.error('Error comparing the password: ', error);
    throw new Error('Failed to compare password');
  }
};

export const createUser = async ({ name, email, password, role }) => {
  try {
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existingUser.length > 0)
      throw new Error('User with this email already exists');

    const passwordHash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({ name, email, password: passwordHash, role })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
        updated_at: users.updated_at,
      });

    logger.info(`User ${newUser.email} created successfully`);
    return newUser;
  } catch (error) {
    logger.error('Error creating user: ', error);

    if (
      error instanceof Error &&
      error.message === 'User with this email already exists'
    ) {
      throw error;
    }

    throw new Error('Failed to create user');
  }
};

export const authenticateUser = async (email, password) => {
  try {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!user) throw new Error('User not found');

    const isValidPassword = await comparePassword(password, user.password);
    if (!isValidPassword) throw new Error('Invalid credentials');

    // Never return password hash to callers
    // eslint-disable-next-line no-unused-vars
    const { password: _password, ...safeUser } = user;

    return safeUser;
  } catch (error) {
    logger.error('Error authenticating user: ', error);

    if (
      error instanceof Error &&
      (error.message === 'User not found' ||
        error.message === 'Invalid credentials')
    ) {
      throw error;
    }

    throw new Error('Failed to authenticate user');
  }
};
