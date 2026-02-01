import arcjet, { shield, detectBot, slidingWindow } from '@arcjet/node';

if (!process.env.ARCJET_KEY) {
  console.warn('⚠️  WARNING: ARCJET_KEY is not set in environment variables!');
  console.warn('⚠️  Rate limiting and bot detection will not work properly.');
}

const aj = arcjet({
  key: process.env.ARCJET_KEY,
  rules: [
    shield({ mode: 'LIVE' }),
    detectBot({
      mode: process.env.NODE_ENV === 'production' ? 'LIVE' : 'DRY_RUN',
      allow: ['CATEGORY:SEARCH_ENGINE', 'CATEGORY:PREVIEW'],
    }),
    slidingWindow({
      mode: 'LIVE',
      interval: '1m',
      max: 10,
    }),
  ],
});

export default aj;
