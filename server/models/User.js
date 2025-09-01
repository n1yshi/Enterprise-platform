const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const validator = require('validator');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
    index: true
  },
  
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    minlength: [3, 'Username must be at least 3 characters long'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'],
    index: true
  },
  
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters long'],
    select: false,
    validate: {
      validator: function(password) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(password);
      },
      message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    }
  },
  
  profile: {
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      maxlength: [50, 'First name cannot exceed 50 characters']
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      maxlength: [50, 'Last name cannot exceed 50 characters']
    },
    avatar: {
      url: String,
      publicId: String
    },
    bio: {
      type: String,
      maxlength: [500, 'Bio cannot exceed 500 characters']
    },
    phone: {
      type: String,
      validate: {
        validator: function(phone) {
          return !phone || validator.isMobilePhone(phone);
        },
        message: 'Please provide a valid phone number'
      }
    },
    dateOfBirth: Date,
    gender: {
      type: String,
      enum: ['male', 'female', 'other', 'prefer-not-to-say']
    },
    location: {
      country: String,
      state: String,
      city: String,
      timezone: {
        type: String,
        default: 'UTC'
      }
    },
    socialLinks: {
      linkedin: String,
      twitter: String,
      github: String,
      website: String
    }
  },
  
  role: {
    type: String,
    enum: ['user', 'admin', 'manager', 'developer', 'analyst', 'viewer'],
    default: 'user',
    index: true
  },
  
  permissions: [{
    resource: {
      type: String,
      required: true
    },
    actions: [{
      type: String,
      enum: ['create', 'read', 'update', 'delete', 'manage']
    }]
  }],
  
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    index: true
  },
  
  department: {
    type: String,
    maxlength: [100, 'Department name cannot exceed 100 characters']
  },
  
  jobTitle: {
    type: String,
    maxlength: [100, 'Job title cannot exceed 100 characters']
  },
  
  employeeId: {
    type: String,
    unique: true,
    sparse: true
  },
  
  manager: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  directReports: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  
  skills: [{
    name: {
      type: String,
      required: true
    },
    level: {
      type: String,
      enum: ['beginner', 'intermediate', 'advanced', 'expert'],
      default: 'beginner'
    },
    verified: {
      type: Boolean,
      default: false
    }
  }],
  
  preferences: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'auto'
    },
    language: {
      type: String,
      default: 'en'
    },
    notifications: {
      email: {
        marketing: { type: Boolean, default: true },
        updates: { type: Boolean, default: true },
        security: { type: Boolean, default: true },
        mentions: { type: Boolean, default: true },
        tasks: { type: Boolean, default: true },
        projects: { type: Boolean, default: true }
      },
      push: {
        enabled: { type: Boolean, default: true },
        mentions: { type: Boolean, default: true },
        tasks: { type: Boolean, default: true },
        projects: { type: Boolean, default: true }
      },
      inApp: {
        mentions: { type: Boolean, default: true },
        tasks: { type: Boolean, default: true },
        projects: { type: Boolean, default: true },
        system: { type: Boolean, default: true }
      }
    },
    dashboard: {
      layout: {
        type: String,
        enum: ['grid', 'list', 'kanban'],
        default: 'grid'
      },
      widgets: [{
        type: String,
        position: Number,
        size: String,
        config: mongoose.Schema.Types.Mixed
      }]
    },
    privacy: {
      profileVisibility: {
        type: String,
        enum: ['public', 'organization', 'private'],
        default: 'organization'
      },
      showEmail: { type: Boolean, default: false },
      showPhone: { type: Boolean, default: false },
      allowDirectMessages: { type: Boolean, default: true }
    }
  },
  
  security: {
    twoFactorAuth: {
      enabled: { type: Boolean, default: false },
      secret: String,
      backupCodes: [String],
      lastUsed: Date
    },
    loginAttempts: {
      count: { type: Number, default: 0 },
      lastAttempt: Date,
      lockedUntil: Date
    },
    sessions: [{
      token: String,
      device: String,
      browser: String,
      ip: String,
      location: String,
      createdAt: { type: Date, default: Date.now },
      lastActivity: { type: Date, default: Date.now },
      isActive: { type: Boolean, default: true }
    }],
    passwordHistory: [{
      hash: String,
      createdAt: { type: Date, default: Date.now }
    }],
    securityQuestions: [{
      question: String,
      answer: String
    }]
  },
  
  verification: {
    email: {
      verified: { type: Boolean, default: false },
      token: String,
      tokenExpires: Date
    },
    phone: {
      verified: { type: Boolean, default: false },
      token: String,
      tokenExpires: Date
    }
  },
  
  subscription: {
    plan: {
      type: String,
      enum: ['free', 'basic', 'premium', 'enterprise'],
      default: 'free'
    },
    status: {
      type: String,
      enum: ['active', 'inactive', 'cancelled', 'past_due'],
      default: 'active'
    },
    stripeCustomerId: String,
    stripeSubscriptionId: String,
    currentPeriodStart: Date,
    currentPeriodEnd: Date,
    cancelAtPeriodEnd: { type: Boolean, default: false }
  },
  
  activity: {
    lastLogin: Date,
    lastActivity: Date,
    loginCount: { type: Number, default: 0 },
    ipAddresses: [String],
    devices: [{
      name: String,
      type: String,
      lastUsed: Date
    }]
  },
  
  analytics: {
    tasksCompleted: { type: Number, default: 0 },
    projectsCreated: { type: Number, default: 0 },
    hoursLogged: { type: Number, default: 0 },
    collaborations: { type: Number, default: 0 },
    achievements: [{
      type: String,
      earnedAt: { type: Date, default: Date.now },
      metadata: mongoose.Schema.Types.Mixed
    }]
  },
  
  integrations: {
    google: {
      id: String,
      email: String,
      connected: { type: Boolean, default: false },
      accessToken: String,
      refreshToken: String,
      scope: [String]
    },
    microsoft: {
      id: String,
      email: String,
      connected: { type: Boolean, default: false },
      accessToken: String,
      refreshToken: String,
      scope: [String]
    },
    slack: {
      id: String,
      teamId: String,
      connected: { type: Boolean, default: false },
      accessToken: String,
      scope: [String]
    },
    github: {
      id: String,
      username: String,
      connected: { type: Boolean, default: false },
      accessToken: String,
      scope: [String]
    }
  },
  
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended', 'deleted'],
    default: 'active',
    index: true
  },
  
  flags: {
    isEmailVerified: { type: Boolean, default: false },
    isPhoneVerified: { type: Boolean, default: false },
    isTwoFactorEnabled: { type: Boolean, default: false },
    isOnboardingCompleted: { type: Boolean, default: false },
    isProfileComplete: { type: Boolean, default: false },
    hasAcceptedTerms: { type: Boolean, default: false },
    hasAcceptedPrivacy: { type: Boolean, default: false }
  },
  
  metadata: {
    source: {
      type: String,
      enum: ['web', 'mobile', 'api', 'import', 'invitation'],
      default: 'web'
    },
    referrer: String,
    utmSource: String,
    utmMedium: String,
    utmCampaign: String,
    tags: [String],
    notes: String
  }
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.security.twoFactorAuth.secret;
      delete ret.security.passwordHistory;
      delete ret.verification;
      delete ret.__v;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

userSchema.virtual('fullName').get(function() {
  return `${this.profile.firstName} ${this.profile.lastName}`;
});

userSchema.virtual('initials').get(function() {
  return `${this.profile.firstName.charAt(0)}${this.profile.lastName.charAt(0)}`.toUpperCase();
});

userSchema.virtual('isLocked').get(function() {
  return !!(this.security.loginAttempts.lockedUntil && this.security.loginAttempts.lockedUntil > Date.now());
});

userSchema.virtual('profileCompleteness').get(function() {
  let completeness = 0;
  const fields = [
    'profile.firstName',
    'profile.lastName',
    'profile.bio',
    'profile.phone',
    'profile.avatar.url',
    'jobTitle',
    'department'
  ];
  
  fields.forEach(field => {
    const value = field.split('.').reduce((obj, key) => obj?.[key], this);
    if (value) completeness += 1;
  });
  
  return Math.round((completeness / fields.length) * 100);
});

userSchema.index({ email: 1, status: 1 });
userSchema.index({ username: 1, status: 1 });
userSchema.index({ organization: 1, role: 1 });
userSchema.index({ 'activity.lastActivity': -1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ 'profile.firstName': 'text', 'profile.lastName': 'text', email: 'text' });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    
    if (this.security.passwordHistory.length >= 5) {
      this.security.passwordHistory.shift();
    }
    this.security.passwordHistory.push({
      hash: this.password,
      createdAt: new Date()
    });
    
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.pre('save', function(next) {
  if (this.isNew) {
    this.activity.loginCount = 0;
    this.flags.isOnboardingCompleted = false;
  }
  
  const requiredFields = [
    this.profile.firstName,
    this.profile.lastName,
    this.profile.bio,
    this.jobTitle,
    this.department
  ];
  
  this.flags.isProfileComplete = requiredFields.every(field => field && field.trim().length > 0);
  
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.generateAuthToken = function() {
  const payload = {
    id: this._id,
    email: this.email,
    role: this.role,
    organization: this.organization
  };
  
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    issuer: 'enterprise-platform',
    audience: 'enterprise-platform-users'
  });
};

userSchema.methods.generateRefreshToken = function() {
  const payload = {
    id: this._id,
    type: 'refresh'
  };
  
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d'
  });
};

userSchema.methods.generatePasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.verification.email.token = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  
  this.verification.email.tokenExpires = Date.now() + 10 * 60 * 1000;
  
  return resetToken;
};

userSchema.methods.generateEmailVerificationToken = function() {
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  this.verification.email.token = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
  
  this.verification.email.tokenExpires = Date.now() + 24 * 60 * 60 * 1000;
  
  return verificationToken;
};

userSchema.methods.incrementLoginAttempts = function() {
  if (this.security.loginAttempts.lockedUntil && this.security.loginAttempts.lockedUntil < Date.now()) {
    return this.updateOne({
      $unset: { 'security.loginAttempts.lockedUntil': 1 },
      $set: { 'security.loginAttempts.count': 1, 'security.loginAttempts.lastAttempt': Date.now() }
    });
  }
  
  const updates = {
    $inc: { 'security.loginAttempts.count': 1 },
    $set: { 'security.loginAttempts.lastAttempt': Date.now() }
  };
  
  if (this.security.loginAttempts.count + 1 >= 5 && !this.isLocked) {
    updates.$set['security.loginAttempts.lockedUntil'] = Date.now() + 2 * 60 * 60 * 1000;
  }
  
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: {
      'security.loginAttempts.count': 1,
      'security.loginAttempts.lastAttempt': 1,
      'security.loginAttempts.lockedUntil': 1
    }
  });
};

userSchema.methods.updateLastActivity = function(ip, device, browser) {
  const updates = {
    'activity.lastActivity': new Date(),
    'activity.lastLogin': new Date(),
    $inc: { 'activity.loginCount': 1 }
  };
  
  if (ip && !this.activity.ipAddresses.includes(ip)) {
    updates.$addToSet = { 'activity.ipAddresses': ip };
  }
  
  if (device) {
    const existingDevice = this.activity.devices.find(d => d.name === device);
    if (existingDevice) {
      existingDevice.lastUsed = new Date();
    } else {
      this.activity.devices.push({
        name: device,
        type: this.getDeviceType(device),
        lastUsed: new Date()
      });
    }
  }
  
  return this.updateOne(updates);
};

userSchema.methods.getDeviceType = function(userAgent) {
  if (/mobile/i.test(userAgent)) return 'mobile';
  if (/tablet/i.test(userAgent)) return 'tablet';
  return 'desktop';
};

userSchema.methods.hasPermission = function(resource, action) {
  if (this.role === 'admin') return true;
  
  const permission = this.permissions.find(p => p.resource === resource);
  return permission && permission.actions.includes(action);
};

userSchema.methods.addAchievement = function(type, metadata = {}) {
  const existingAchievement = this.analytics.achievements.find(a => a.type === type);
  if (!existingAchievement) {
    this.analytics.achievements.push({
      type,
      metadata,
      earnedAt: new Date()
    });
    return this.save();
  }
  return Promise.resolve(this);
};

userSchema.methods.toPublicProfile = function() {
  const publicProfile = {
    id: this._id,
    username: this.username,
    fullName: this.fullName,
    initials: this.initials,
    avatar: this.profile.avatar,
    jobTitle: this.jobTitle,
    department: this.department,
    organization: this.organization,
    bio: this.profile.bio,
    skills: this.skills,
    profileCompleteness: this.profileCompleteness,
    joinedAt: this.createdAt
  };
  
  if (this.preferences.privacy.profileVisibility === 'private') {
    return {
      id: this._id,
      username: this.username,
      fullName: this.fullName,
      avatar: this.profile.avatar
    };
  }
  
  if (this.preferences.privacy.showEmail) {
    publicProfile.email = this.email;
  }
  
  if (this.preferences.privacy.showPhone) {
    publicProfile.phone = this.profile.phone;
  }
  
  return publicProfile;
};

userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase(), status: 'active' });
};

userSchema.statics.findByUsername = function(username) {
  return this.findOne({ username: username.toLowerCase(), status: 'active' });
};

userSchema.statics.findByResetToken = function(token) {
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  
  return this.findOne({
    'verification.email.token': hashedToken,
    'verification.email.tokenExpires': { $gt: Date.now() },
    status: 'active'
  });
};

userSchema.statics.searchUsers = function(query, options = {}) {
  const {
    page = 1,
    limit = 20,
    sortBy = 'createdAt',
    sortOrder = 'desc',
    role,
    organization,
    status = 'active'
  } = options;
  
  const searchQuery = {
    status,
    $or: [
      { 'profile.firstName': { $regex: query, $options: 'i' } },
      { 'profile.lastName': { $regex: query, $options: 'i' } },
      { email: { $regex: query, $options: 'i' } },
      { username: { $regex: query, $options: 'i' } }
    ]
  };
  
  if (role) searchQuery.role = role;
  if (organization) searchQuery.organization = organization;
  
  const skip = (page - 1) * limit;
  const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };
  
  return this.find(searchQuery)
    .populate('organization', 'name logo')
    .populate('manager', 'profile.firstName profile.lastName email')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .select('-password -security -verification');
};

userSchema.statics.getActiveUsersCount = function() {
  return this.countDocuments({ status: 'active' });
};

userSchema.statics.getUsersRegisteredToday = function() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  return this.countDocuments({
    createdAt: { $gte: today },
    status: 'active'
  });
};

userSchema.statics.getTopPerformers = function(limit = 10) {
  return this.find({ status: 'active' })
    .sort({ 'analytics.tasksCompleted': -1, 'analytics.hoursLogged': -1 })
    .limit(limit)
    .populate('organization', 'name')
    .select('profile email analytics organization');
};

module.exports = mongoose.model('User', userSchema);