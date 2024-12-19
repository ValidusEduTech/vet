const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

class AuthController {
    constructor() {
        this.router = express.Router();
        this.initializeRoutes();
    }

    initializeRoutes() {
        // User Registration Route
        this.router.post(
            '/register', 
            [
                // Validation middleware
                body('fullName').trim().isLength({ min: 2 }).withMessage('Full name must be at least 2 characters'),
                body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
                body('password')
                    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
                    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
                    .withMessage('Password must include uppercase, lowercase, number, and special character')
            ],
            this.register
        );

        // User Login Route
        this.router.post(
            '/login', 
            [
                body('email').isEmail().normalizeEmail(),
                body('password').notEmpty()
            ],
            this.login
        );

        // Password Reset Route
        this.router.post('/reset-password', this.resetPassword);
    }

    async register(req, res) {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { fullName, email, password } = req.body;

            // Check if user already exists
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(409).json({ message: 'User already exists' });
            }

            // Hash password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Create new user
            const newUser = new User({
                fullName,
                email,
                password: hashedPassword
            });

            await newUser.save();

            // Generate JWT token
            const token = this.generateToken(newUser);

            res.status(201).json({
                message: 'User registered successfully',
                token,
                user: {
                    id: newUser._id,
                    fullName: newUser.fullName,
                    email: newUser.email
                }
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error during registration' });
        }
    }

    async login(req, res) {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { email, password } = req.body;

            // Find user
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Check password
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Generate JWT token
            const token = this.generateToken(user);

            res.json({
                message: 'Login successful',
                token,
                user: {
                    id: user._id,
                    fullName: user.fullName,
                    email: user.email
                }
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error during login' });
        }
    }

    async resetPassword(req, res) {
        try {
            const { email, newPassword, resetToken } = req.body;

            // Verify reset token
            const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
            
            // Find user
            const user = await User.findOne({ 
                email, 
                _id: decoded.userId 
            });

            if (!user) {
                return res.status(400).json({ message: 'Invalid reset token' });
            }

            // Hash new password
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(newPassword, salt);

            await user.save();

            res.json({ message: 'Password reset successful' });
        } catch (error) {
            res.status(500).json({ message: 'Error resetting password' });
        }
    }

    generateToken(user) {
        return jwt.sign(
            { 
                userId: user._id, 
                email: user.email 
            }, 
            process.env.JWT_SECRET, 
            { 
                expiresIn: '24h' 
            }
        );
    }

    // Middleware to protect routes
    authMiddleware(req, res, next) {
        const token = req.header('Authorization')?.replace('Bearer ', '');

        if (!token) {
            return res.status(401).json({ message: 'No token, authorization denied' });
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            next();
        } catch (error) {
            res.status(401).json({ message: 'Token is not valid' });
        }
    }
}

module.exports = new AuthController();