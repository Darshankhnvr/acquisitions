import aj from '../config/arcjet.js';
import logger from '../config/logger.js';

const securityMiddleware = async (req, res, next) => {
    try {
        const decision = await aj.protect(req);

        console.log('Arcjet Decision:', {
            isDenied: decision.isDenied(),
            conclusion: decision.conclusion,
            reasons: decision.results.map(r => r.reason),
        });

        if (decision.isDenied()) {
            if (decision.reason.isBot()) {
                logger.warn('Bot request blocked', {
                    ip: req.ip,
                    userAgent: req.get('user-agent'),
                    path: req.path,
                });
                return res.status(403).json({
                    error: 'Forbidden',
                    message: 'Automated requests are not allowed',
                });
            }

            if (decision.reason.isShield()) {
                logger.warn('Shield request blocked', {
                    ip: req.ip,
                    userAgent: req.get('user-agent'),
                    path: req.path,
                });
                return res.status(403).json({
                    error: 'Forbidden',
                    message: 'Shield request blocked',
                });
            }

            if (decision.reason.isRateLimit()) {
                logger.warn('Ratelimit request blocked', {
                    ip: req.ip,
                    userAgent: req.get('user-agent'),
                    path: req.path,
                });
                return res.status(429).json({
                    error: 'Too Many Requests',
                    message: 'Rate limit exceeded. Please try again later',
                });
            }
        }

        next();
    } catch (error) {
        logger.error('Arcjet middleware error', error);
        res.status(500).json({
            error: 'Internal server error',
            message: 'Something went wrong with security middleware',
        });
    }
};

export default securityMiddleware;
