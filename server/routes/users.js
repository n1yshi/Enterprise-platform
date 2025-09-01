const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');
const multer = require('multer');
const sharp = require('sharp');
const path = require('path');

const User = require('../models/User');
const Organization = require('../models/Organization');
const auth = require('../middleware/auth');
const validation = require('../middleware/validation');
const upload = require('../middleware/upload');
const cache = require('../middleware/cache');
const logger = require('../utils/logger');
const emailService = require('../services/email');
const analyticsService = require('../services/analytics');
const auditService = require('../services/audit');
const notificationService = require('../services/notifications');
const fileService = require('../services/files');
const searchService = require('../services/search');

const router = express.Router();

const profileUpdateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many profile update attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

const passwordChangeLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: 'Too many password change attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

router.get('/', 
  auth.authenticate,
  auth.requirePermission('users', 'read'),
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    query('search').optional().isString().trim().isLength({ min: 1, max: 100 }),
    query('role').optional().isIn(['user', 'admin', 'manager', 'developer', 'analyst', 'viewer']),
    query('status').optional().isIn(['active', 'inactive', 'suspended']),
    query('organization').optional().isMongoId(),
    query('sortBy').optional().isIn(['createdAt', 'lastActivity', 'fullName', 'email']),
    query('sortOrder').optional().isIn(['asc', 'desc'])
  ],
  validation.handleValidationErrors,
  cache.middleware(300),
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 20,
        search,
        role,
        status = 'active',
        organization,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      let query = { status };
      
      if (role) query.role = role;
      if (organization) query.organization = organization;
      
      if (req.user.role !== 'admin' && req.user.role !== 'manager') {
        query.organization = req.user.organization;
      }

      if (search) {
        query.$or = [
          { 'profile.firstName': { $regex: search, $options: 'i' } },
          { 'profile.lastName': { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
          { username: { $regex: search, $options: 'i' } },
          { jobTitle: { $regex: search, $options: 'i' } },
          { department: { $regex: search, $options: 'i' } }
        ];
      }

      const skip = (page - 1) * limit;
      const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

      const [users, total] = await Promise.all([
        User.find(query)
          .populate('organization', 'name logo website')
          .populate('manager', 'profile.firstName profile.lastName email avatar')
          .populate('directReports', 'profile.firstName profile.lastName email avatar')
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .select('-password -security -verification -integrations'),
        User.countDocuments(query)
      ]);

      const totalPages = Math.ceil(total / limit);
      const hasNextPage = page < totalPages;
      const hasPrevPage = page > 1;

      await analyticsService.track(req.user.id, 'users_list_viewed', {
        page,
        limit,
        search,
        role,
        organization,
        totalResults: total
      });

      res.json({
        success: true,
        data: {
          users: users.map(user => user.toPublicProfile()),
          pagination: {
            currentPage: page,
            totalPages,
            totalItems: total,
            itemsPerPage: limit,
            hasNextPage,
            hasPrevPage
          }
        }
      });
    } catch (error) {
      logger.error('Error fetching users:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch users',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

router.get('/me',
  auth.authenticate,
  cache.middleware(60),
  async (req, res) => {
    try {
      const user = await User.findById(req.user.id)
        .populate('organization', 'name logo website settings')
        .populate('manager', 'profile.firstName profile.lastName email avatar')
        .populate('directReports', 'profile.firstName profile.lastName email avatar')
        .select('-password -security.passwordHistory -security.sessions');

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      await user.updateLastActivity(req.ip, req.get('User-Agent'));

      res.json({
        success: true,
        data: { user }
      });
    } catch (error) {
      logger.error('Error fetching current user:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch user profile'
      });
    }
  }
);

router.get('/search',
  auth.authenticate,
  [
    query('q').notEmpty().isString().trim().isLength({ min: 2, max: 100 }),
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt()
  ],
  validation.handleValidationErrors,
  cache.middleware(300),
  async (req, res) => {
    try {
      const { q: query, limit = 10 } = req.query;

      const searchResults = await searchService.searchUsers(query, {
        limit,
        organization: req.user.role === 'admin' ? undefined : req.user.organization
      });

      await analyticsService.track(req.user.id, 'users_searched', {
        query,
        resultsCount: searchResults.length
      });

      res.json({
        success: true,
        data: {
          users: searchResults,
          query
        }
      });
    } catch (error) {
      logger.error('Error searching users:', error);
      res.status(500).json({
        success: false,
        message: 'Search failed'
      });
    }
  }
);

router.get('/stats',
  auth.authenticate,
  auth.requireRole(['admin', 'manager']),
  cache.middleware(600),
  async (req, res) => {
    try {
      const [
        totalUsers,
        activeUsers,
        newUsersToday,
        usersByRole,
        usersByDepartment,
        topPerformers
      ] = await Promise.all([
        User.countDocuments({ status: { $ne: 'deleted' } }),
        User.countDocuments({ status: 'active' }),
        User.getUsersRegisteredToday(),
        User.aggregate([
          { $match: { status: 'active' } },
          { $group: { _id: '$role', count: { $sum: 1 } } }
        ]),
        User.aggregate([
          { $match: { status: 'active', department: { $exists: true, $ne: null } } },
          { $group: { _id: '$department', count: { $sum: 1 } } }
        ]),
        User.getTopPerformers(5)
      ]);

      res.json({
        success: true,
        data: {
          overview: {
            totalUsers,
            activeUsers,
            newUsersToday,
            inactiveUsers: totalUsers - activeUsers
          },
          distribution: {
            byRole: usersByRole,
            byDepartment: usersByDepartment
          },
          topPerformers
        }
      });
    } catch (error) {
      logger.error('Error fetching user stats:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch user statistics'
      });
    }
  }
);

router.get('/:id',
  auth.authenticate,
  [
    param('id').isMongoId().withMessage('Invalid user ID')
  ],
  validation.handleValidationErrors,
  cache.middleware(300),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (req.user.id !== id && !req.user.hasPermission('users', 'read')) {
        return res.status(403).json({
          success: false,
          message: 'Access denied'
        });
      }

      const user = await User.findById(id)
        .populate('organization', 'name logo website')
        .populate('manager', 'profile.firstName profile.lastName email avatar')
        .populate('directReports', 'profile.firstName profile.lastName email avatar')
        .select('-password -security -verification');

      if (!user || user.status === 'deleted') {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const isOwnProfile = req.user.id === id;
      const canViewFullProfile = isOwnProfile || req.user.hasPermission('users', 'read');

      const profileData = canViewFullProfile ? user : user.toPublicProfile();

      await analyticsService.track(req.user.id, 'user_profile_viewed', {
        viewedUserId: id,
        isOwnProfile
      });

      res.json({
        success: true,
        data: { user: profileData }
      });
    } catch (error) {
      logger.error('Error fetching user:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch user'
      });
    }
  }
);

router.put('/me',
  auth.authenticate,
  profileUpdateLimit,
  [
    body('profile.firstName').optional().isString().trim().isLength({ min: 1, max: 50 }),
    body('profile.lastName').optional().isString().trim().isLength({ min: 1, max: 50 }),
    body('profile.bio').optional().isString().trim().isLength({ max: 500 }),
    body('profile.phone').optional().isMobilePhone(),
    body('profile.dateOfBirth').optional().isISO8601(),
    body('profile.gender').optional().isIn(['male', 'female', 'other', 'prefer-not-to-say']),
    body('profile.location.country').optional().isString().trim().isLength({ max: 100 }),
    body('profile.location.state').optional().isString().trim().isLength({ max: 100 }),
    body('profile.location.city').optional().isString().trim().isLength({ max: 100 }),
    body('profile.location.timezone').optional().isString(),
    body('jobTitle').optional().isString().trim().isLength({ max: 100 }),
    body('department').optional().isString().trim().isLength({ max: 100 }),
    body('skills').optional().isArray(),
    body('skills.*.name').optional().isString().trim().isLength({ min: 1, max: 50 }),
    body('skills.*.level').optional().isIn(['beginner', 'intermediate', 'advanced', 'expert']),
    body('preferences.theme').optional().isIn(['light', 'dark', 'auto']),
    body('preferences.language').optional().isString().isLength({ min: 2, max: 5 }),
    body('preferences.notifications').optional().isObject(),
    body('preferences.privacy').optional().isObject()
  ],
  validation.handleValidationErrors,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const updates = req.body;

      const allowedUpdates = [
        'profile',
        'jobTitle',
        'department',
        'skills',
        'preferences'
      ];

      const filteredUpdates = {};
      Object.keys(updates).forEach(key => {
        if (allowedUpdates.includes(key)) {
          filteredUpdates[key] = updates[key];
        }
      });

      const user = await User.findByIdAndUpdate(
        userId,
        { $set: filteredUpdates },
        { new: true, runValidators: true }
      ).populate('organization', 'name logo website');

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      await Promise.all([
        auditService.log(userId, 'profile_updated', {
          updatedFields: Object.keys(filteredUpdates),
          timestamp: new Date()
        }),
        analyticsService.track(userId, 'profile_updated', {
          updatedFields: Object.keys(filteredUpdates)
        }),
        cache.invalidate(`user:${userId}`)
      ]);

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: { user }
      });
    } catch (error) {
      logger.error('Error updating profile:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update profile',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

router.post('/me/avatar',
  auth.authenticate,
  avatarUpload.single('avatar'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: 'No image file provided'
        });
      }

      const userId = req.user.id;
      const imageBuffer = req.file.buffer;

      const processedImage = await sharp(imageBuffer)
        .resize(300, 300, {
          fit: 'cover',
          position: 'center'
        })
        .jpeg({ quality: 90 })
        .toBuffer();

      const uploadResult = await fileService.uploadImage(processedImage, {
        folder: 'avatars',
        public_id: `avatar_${userId}`,
        overwrite: true,
        transformation: [
          { width: 300, height: 300, crop: 'fill' },
          { quality: 'auto' },
          { fetch_format: 'auto' }
        ]
      });

      const user = await User.findByIdAndUpdate(
        userId,
        {
          $set: {
            'profile.avatar': {
              url: uploadResult.secure_url,
              publicId: uploadResult.public_id
            }
          }
        },
        { new: true }
      );

      await Promise.all([
        auditService.log(userId, 'avatar_updated', {
          avatarUrl: uploadResult.secure_url,
          timestamp: new Date()
        }),
        analyticsService.track(userId, 'avatar_updated'),
        cache.invalidate(`user:${userId}`)
      ]);

      res.json({
        success: true,
        message: 'Avatar updated successfully',
        data: {
          avatar: user.profile.avatar
        }
      });
    } catch (error) {
      logger.error('Error updating avatar:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update avatar'
      });
    }
  }
);

router.delete('/me/avatar',
  auth.authenticate,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      if (user.profile.avatar?.publicId) {
        await fileService.deleteImage(user.profile.avatar.publicId);
      }

      await User.findByIdAndUpdate(userId, {
        $unset: { 'profile.avatar': 1 }
      });

      await Promise.all([
        auditService.log(userId, 'avatar_removed', { timestamp: new Date() }),
        analyticsService.track(userId, 'avatar_removed'),
        cache.invalidate(`user:${userId}`)
      ]);

      res.json({
        success: true,
        message: 'Avatar removed successfully'
      });
    } catch (error) {
      logger.error('Error removing avatar:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to remove avatar'
      });
    }
  }
);

router.put('/me/password',
  auth.authenticate,
  passwordChangeLimit,
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('New password must be at least 8 characters long')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match');
      }
      return true;
    })
  ],
  validation.handleValidationErrors,
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user.id;

      const user = await User.findById(userId).select('+password');
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const isCurrentPasswordValid = await user.comparePassword(currentPassword);
      if (!isCurrentPasswordValid) {
        await user.incrementLoginAttempts();
        return res.status(400).json({
          success: false,
          message: 'Current password is incorrect'
        });
      }

      const isNewPasswordSameAsCurrent = await user.comparePassword(newPassword);
      if (isNewPasswordSameAsCurrent) {
        return res.status(400).json({
          success: false,
          message: 'New password must be different from current password'
        });
      }

      const isPasswordInHistory = await Promise.all(
        user.security.passwordHistory.map(async (historyEntry) => {
          return bcrypt.compare(newPassword, historyEntry.hash);
        })
      );

      if (isPasswordInHistory.some(Boolean)) {
        return res.status(400).json({
          success: false,
          message: 'Cannot reuse a recent password'
        });
      }

      user.password = newPassword;
      await user.save();

      await Promise.all([
        auditService.log(userId, 'password_changed', {
          timestamp: new Date(),
          ip: req.ip,
          userAgent: req.get('User-Agent')
        }),
        analyticsService.track(userId, 'password_changed'),
        emailService.sendPasswordChangeNotification(user.email, {
          name: user.fullName,
          timestamp: new Date(),
          ip: req.ip,
          device: req.get('User-Agent')
        }),
        notificationService.send(userId, {
          type: 'security',
          title: 'Password Changed',
          message: 'Your password has been successfully changed',
          priority: 'high'
        })
      ]);

      res.json({
        success: true,
        message: 'Password updated successfully'
      });
    } catch (error) {
      logger.error('Error changing password:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to change password'
      });
    }
  }
);

router.post('/me/deactivate',
  auth.authenticate,
  [
    body('password').notEmpty().withMessage('Password is required for account deactivation'),
    body('reason').optional().isString().trim().isLength({ max: 500 })
  ],
  validation.handleValidationErrors,
  async (req, res) => {
    try {
      const { password, reason } = req.body;
      const userId = req.user.id;

      const user = await User.findById(userId).select('+password');
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        return res.status(400).json({
          success: false,
          message: 'Invalid password'
        });
      }

      await User.findByIdAndUpdate(userId, {
        status: 'inactive',
        'metadata.deactivationReason': reason,
        'metadata.deactivatedAt': new Date()
      });

      await Promise.all([
        auditService.log(userId, 'account_deactivated', {
          reason,
          timestamp: new Date()
        }),
        analyticsService.track(userId, 'account_deactivated', { reason }),
        emailService.sendAccountDeactivationNotification(user.email, {
          name: user.fullName,
          reason,
          reactivationUrl: `${process.env.CLIENT_URL}/reactivate`
        })
      ]);

      res.json({
        success: true,
        message: 'Account deactivated successfully'
      });
    } catch (error) {
      logger.error('Error deactivating account:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to deactivate account'
      });
    }
  }
);

router.put('/:id',
  auth.authenticate,
  auth.requirePermission('users', 'update'),
  [
    param('id').isMongoId().withMessage('Invalid user ID'),
    body('role').optional().isIn(['user', 'admin', 'manager', 'developer', 'analyst', 'viewer']),
    body('status').optional().isIn(['active', 'inactive', 'suspended']),
    body('organization').optional().isMongoId(),
    body('manager').optional().isMongoId(),
    body('permissions').optional().isArray()
  ],
  validation.handleValidationErrors,
  async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;

      if (req.user.id === id && updates.role) {
        return res.status(400).json({
          success: false,
          message: 'Cannot change your own role'
        });
      }

      const user = await User.findByIdAndUpdate(
        id,
        { $set: updates },
        { new: true, runValidators: true }
      ).populate('organization', 'name logo');

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      await Promise.all([
        auditService.log(req.user.id, 'user_updated', {
          targetUserId: id,
          updatedFields: Object.keys(updates),
          timestamp: new Date()
        }),
        analyticsService.track(req.user.id, 'user_updated', {
          targetUserId: id,
          updatedFields: Object.keys(updates)
        }),
        cache.invalidate(`user:${id}`)
      ]);

      if (updates.role || updates.status) {
        await notificationService.send(id, {
          type: 'system',
          title: 'Account Updated',
          message: `Your account has been updated by ${req.user.fullName}`,
          priority: 'medium'
        });
      }

      res.json({
        success: true,
        message: 'User updated successfully',
        data: { user }
      });
    } catch (error) {
      logger.error('Error updating user:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update user'
      });
    }
  }
);

router.delete('/:id',
  auth.authenticate,
  auth.requirePermission('users', 'delete'),
  [
    param('id').isMongoId().withMessage('Invalid user ID')
  ],
  validation.handleValidationErrors,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (req.user.id === id) {
        return res.status(400).json({
          success: false,
          message: 'Cannot delete your own account'
        });
      }

      const user = await User.findById(id);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      await User.findByIdAndUpdate(id, {
        status: 'deleted',
        'metadata.deletedAt': new Date(),
        'metadata.deletedBy': req.user.id
      });

      await Promise.all([
        auditService.log(req.user.id, 'user_deleted', {
          targetUserId: id,
          targetUserEmail: user.email,
          timestamp: new Date()
        }),
        analyticsService.track(req.user.id, 'user_deleted', {
          targetUserId: id
        }),
        cache.invalidate(`user:${id}`)
      ]);

      res.json({
        success: true,
        message: 'User deleted successfully'
      });
    } catch (error) {
      logger.error('Error deleting user:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to delete user'
      });
    }
  }
);

module.exports = router;