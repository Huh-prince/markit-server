const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8001;

// Middleware - Manual CORS for better serverless compatibility
// Middleware - Allow all origins for testing
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  console.log('[CORS]', req.method, req.url, 'Origin:', origin);
  
  // Allow all origins for testing
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
  
  // Handle preflight
  if (req.method === 'OPTIONS') {
    console.log('[CORS] Handling OPTIONS preflight');
    return res.status(204).end();
  }
  
  next();
});

app.use(express.json({ limit: '50mb' }));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL, {
  dbName: process.env.DB_NAME
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// ==================== SCHEMAS ====================

// School Schema
const schoolSchema = new mongoose.Schema({
  schoolId: { type: String, default: () => uuidv4(), unique: true },
  name: { type: String, required: true },
  address: String,
  phone: String,
  email: String,
  logo: String,
  academicYear: String,
  settings: {
    scanTimeWindow: { type: Number, default: 30 },
    lateMarkingPolicy: { type: String, default: 'manual' },
    attendanceThreshold: { type: Number, default: 75 }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// User Schema (Admin/Teacher)
const userSchema = new mongoose.Schema({
  userId: { type: String, default: () => uuidv4(), unique: true },
  schoolId: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['admin', 'teacher'], required: true },
  phone: String,
  avatar: String,
  assignedClasses: [String],
  assignedSubjects: [String],
  isActive: { type: Boolean, default: true },
  refreshToken: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Class Schema
const classSchema = new mongoose.Schema({
  classId: { type: String, default: () => uuidv4(), unique: true },
  schoolId: { type: String, required: true },
  name: { type: String, required: true },
  section: String,
  academicYear: String,
  teacherId: String,
  totalStudents: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

// Subject Schema
const subjectSchema = new mongoose.Schema({
  subjectId: { type: String, default: () => uuidv4(), unique: true },
  schoolId: { type: String, required: true },
  name: { type: String, required: true },
  code: String,
  classIds: [String],
  teacherIds: [String],
  createdAt: { type: Date, default: Date.now }
});

// Student Schema
const studentSchema = new mongoose.Schema({
  studentId: { type: String, default: () => uuidv4(), unique: true },
  schoolId: { type: String, required: true },
  uid: { type: String, unique: true },
  name: { type: String, required: true },
  rollNumber: String,
  classId: { type: String, required: true },
  section: String,
  email: String,
  phone: String,
  parentPhone: String,
  address: String,
  avatar: String,
  qrCode: String,
  qrData: String,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Attendance Session Schema
const attendanceSessionSchema = new mongoose.Schema({
  sessionId: { type: String, default: () => uuidv4(), unique: true },
  schoolId: { type: String, required: true },
  classId: { type: String, required: true },
  teacherId: { type: String, required: true },
  sessionType: { type: String, enum: ['morning', 'afternoon'], required: true },
  date: { type: Date, required: true },
  startTime: { type: Date, default: Date.now },
  endTime: Date,
  status: { type: String, enum: ['active', 'ended'], default: 'active' },
  totalPresent: { type: Number, default: 0 },
  totalAbsent: { type: Number, default: 0 },
  syncStatus: { type: String, enum: ['synced', 'pending'], default: 'synced' },
  createdAt: { type: Date, default: Date.now }
});

// Attendance Record Schema
const attendanceRecordSchema = new mongoose.Schema({
  recordId: { type: String, default: () => uuidv4(), unique: true },
  sessionId: { type: String, required: true },
  schoolId: { type: String, required: true },
  studentId: { type: String, required: true },
  classId: { type: String, required: true },
  teacherId: { type: String, required: true },
  date: { type: Date, required: true },
  sessionType: { type: String, enum: ['morning', 'afternoon'], required: true },
  status: { type: String, enum: ['present', 'absent'], required: true },
  markedAt: { type: Date, default: Date.now },
  markedBy: String,
  method: { type: String, enum: ['qr', 'manual'], default: 'manual' },
  syncStatus: { type: String, enum: ['synced', 'pending'], default: 'synced' },
  editHistory: [{
    editedBy: String,
    editedAt: Date,
    previousStatus: String,
    newStatus: String,
    reason: String,
    approvalStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    approvedBy: String,
    approvedAt: Date
  }]
});

// Approval Request Schema
const approvalRequestSchema = new mongoose.Schema({
  requestId: { type: String, default: () => uuidv4(), unique: true },
  schoolId: { type: String, required: true },
  type: { type: String, enum: ['attendance_edit'], required: true },
  recordId: { type: String, required: true },
  requestedBy: { type: String, required: true },
  requestedByName: String,
  studentId: String,
  studentName: String,
  classId: String,
  previousStatus: String,
  newStatus: String,
  reason: String,
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: String,
  reviewedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

// Notification Schema
const notificationSchema = new mongoose.Schema({
  notificationId: { type: String, default: () => uuidv4(), unique: true },
  schoolId: { type: String, required: true },
  userId: String,
  type: { type: String, required: true },
  title: { type: String, required: true },
  message: String,
  data: Object,
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Announcement Schema
const announcementSchema = new mongoose.Schema({
  announcementId: { type: String, default: () => uuidv4(), unique: true },
  schoolId: { type: String, required: true },
  title: { type: String, required: true },
  content: String,
  targetAudience: { type: String, enum: ['all', 'teachers', 'specific_class'], default: 'all' },
  targetClasses: [String],
  createdBy: String,
  createdAt: { type: Date, default: Date.now }
});

// Audit Log Schema
const auditLogSchema = new mongoose.Schema({
  logId: { type: String, default: () => uuidv4(), unique: true },
  schoolId: { type: String, required: true },
  userId: String,
  userName: String,
  action: { type: String, required: true },
  entityType: String,
  entityId: String,
  details: Object,
  ipAddress: String,
  createdAt: { type: Date, default: Date.now }
});

// Models
const School = mongoose.model('School', schoolSchema);
const User = mongoose.model('User', userSchema);
const Class = mongoose.model('Class', classSchema);
const Subject = mongoose.model('Subject', subjectSchema);
const Student = mongoose.model('Student', studentSchema);
const AttendanceSession = mongoose.model('AttendanceSession', attendanceSessionSchema);
const AttendanceRecord = mongoose.model('AttendanceRecord', attendanceRecordSchema);
const ApprovalRequest = mongoose.model('ApprovalRequest', approvalRequestSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Announcement = mongoose.model('Announcement', announcementSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// ==================== MIDDLEWARE ====================

const JWT_SECRET = process.env.JWT_SECRET || 'markit-secret-key-2024';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'markit-refresh-secret-2024';

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access token required' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ userId: decoded.userId }).select('-password');
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ==================== AUTH ROUTES ====================

// Register New School
app.post('/api/auth/register', async (req, res) => {
  try {
    const { 
      schoolName, 
      schoolAddress, 
      schoolPhone, 
      schoolEmail,
      adminName, 
      adminEmail, 
      adminPassword 
    } = req.body;

    // Validate required fields
    if (!schoolName || !adminName || !adminEmail || !adminPassword) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if admin email already exists
    const existingUser = await User.findOne({ email: adminEmail.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Generate unique school ID
    const schoolId = `school-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;

    // Create school
    const school = new School({
      schoolId,
      name: schoolName,
      address: schoolAddress || '',
      phone: schoolPhone || '',
      email: schoolEmail || adminEmail,
      academicYear: `${new Date().getFullYear()}-${new Date().getFullYear() + 1}`,
      settings: {
        attendanceThreshold: 75,
        scanTimeWindow: 30,
        lateMarkingPolicy: 'manual'
      }
    });
    await school.save();

    // Hash password
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    // Create admin user
    const admin = new User({
      schoolId,
      email: adminEmail.toLowerCase(),
      password: hashedPassword,
      name: adminName,
      role: 'admin',
      phone: schoolPhone || '',
      isActive: true
    });
    await admin.save();

    // Generate tokens
    const accessToken = jwt.sign(
      { userId: admin.userId, email: admin.email, role: admin.role, schoolId: admin.schoolId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: admin.userId },
      JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    admin.refreshToken = refreshToken;
    await admin.save();

    // Create audit log
    await new AuditLog({
      schoolId,
      userId: admin.userId,
      userName: admin.name,
      action: 'SCHOOL_REGISTERED',
      entityType: 'school',
      entityId: schoolId,
      details: { schoolName, adminEmail }
    }).save();

    // Create welcome announcement
    await new Announcement({
      schoolId,
      title: 'Welcome to MARKIT!',
      content: `Congratulations on setting up ${schoolName}! Start by adding teachers, students, and classes to begin tracking attendance.`,
      targetAudience: 'all',
      createdBy: admin.userId
    }).save();

    res.status(201).json({
      message: 'School registered successfully',
      accessToken,
      refreshToken,
      user: {
        userId: admin.userId,
        email: admin.email,
        name: admin.name,
        role: admin.role,
        schoolId: admin.schoolId
      },
      school: {
        schoolId: school.schoolId,
        name: school.name,
        academicYear: school.academicYear
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const accessToken = jwt.sign(
      { userId: user.userId, email: user.email, role: user.role, schoolId: user.schoolId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    const refreshToken = jwt.sign(
      { userId: user.userId },
      JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );
    
    user.refreshToken = refreshToken;
    await user.save();
    
    const school = await School.findOne({ schoolId: user.schoolId });
    
    res.json({
      accessToken,
      refreshToken,
      user: {
        userId: user.userId,
        email: user.email,
        name: user.name,
        role: user.role,
        schoolId: user.schoolId,
        avatar: user.avatar,
        assignedClasses: user.assignedClasses,
        assignedSubjects: user.assignedSubjects
      },
      school: school ? {
        schoolId: school.schoolId,
        name: school.name,
        logo: school.logo,
        academicYear: school.academicYear
      } : null
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Refresh Token
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ error: 'Refresh token required' });
    
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const user = await User.findOne({ userId: decoded.userId, refreshToken });
    
    if (!user) return res.status(403).json({ error: 'Invalid refresh token' });
    
    const accessToken = jwt.sign(
      { userId: user.userId, email: user.email, role: user.role, schoolId: user.schoolId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    res.json({ accessToken });
  } catch (err) {
    res.status(403).json({ error: 'Invalid refresh token' });
  }
});

// Logout
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    req.user.refreshToken = null;
    await req.user.save();
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Current User
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const school = await School.findOne({ schoolId: req.user.schoolId });
    res.json({
      user: {
        userId: req.user.userId,
        email: req.user.email,
        name: req.user.name,
        role: req.user.role,
        schoolId: req.user.schoolId,
        avatar: req.user.avatar,
        phone: req.user.phone,
        assignedClasses: req.user.assignedClasses,
        assignedSubjects: req.user.assignedSubjects
      },
      school: school ? {
        schoolId: school.schoolId,
        name: school.name,
        logo: school.logo,
        academicYear: school.academicYear,
        settings: school.settings
      } : null
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== SCHOOL ROUTES ====================

app.get('/api/schools', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const schools = await School.find({}).select('-__v');
    res.json(schools);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/schools/:schoolId', authenticateToken, async (req, res) => {
  try {
    const school = await School.findOne({ schoolId: req.params.schoolId }).select('-__v');
    if (!school) return res.status(404).json({ error: 'School not found' });
    res.json(school);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/schools/:schoolId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const school = await School.findOneAndUpdate(
      { schoolId: req.params.schoolId },
      { ...req.body, updatedAt: new Date() },
      { new: true }
    ).select('-__v');
    if (!school) return res.status(404).json({ error: 'School not found' });
    res.json(school);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== DASHBOARD STATS ====================

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const { schoolId } = req.user;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const [
      totalStudents,
      totalTeachers,
      totalClasses,
      todayAttendance,
      weekAttendance,
      monthAttendance,
      pendingApprovals,
      recentAnnouncements,
      activeSessions
    ] = await Promise.all([
      Student.countDocuments({ schoolId, isActive: true }),
      User.countDocuments({ schoolId, role: 'teacher', isActive: true }),
      Class.countDocuments({ schoolId }),
      AttendanceRecord.find({ schoolId, date: { $gte: today } }),
      AttendanceRecord.find({ 
        schoolId, 
        date: { $gte: new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000) } 
      }),
      AttendanceRecord.find({ 
        schoolId, 
        date: { $gte: new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000) } 
      }),
      ApprovalRequest.countDocuments({ schoolId, status: 'pending' }),
      Announcement.find({ schoolId }).sort({ createdAt: -1 }).limit(5),
      AttendanceSession.find({ schoolId, status: 'active' })
    ]);
    
    const todayPresent = todayAttendance.filter(r => r.status === 'present').length;
    const weekPresent = weekAttendance.filter(r => r.status === 'present').length;
    const monthPresent = monthAttendance.filter(r => r.status === 'present').length;
    
    // Students below threshold
    const attendanceThreshold = 75;
    const studentAttendance = await AttendanceRecord.aggregate([
      { $match: { schoolId, date: { $gte: new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000) } } },
      { $group: { 
        _id: '$studentId', 
        total: { $sum: 1 },
        present: { $sum: { $cond: [{ $eq: ['$status', 'present'] }, 1, 0] } }
      }},
      { $project: { 
        studentId: '$_id', 
        percentage: { $multiply: [{ $divide: ['$present', '$total'] }, 100] }
      }},
      { $match: { percentage: { $lt: attendanceThreshold } } }
    ]);
    
    // Class-wise attendance
    const classWiseAttendance = await AttendanceRecord.aggregate([
      { $match: { schoolId, date: { $gte: new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000) } } },
      { $group: { 
        _id: '$classId', 
        total: { $sum: 1 },
        present: { $sum: { $cond: [{ $eq: ['$status', 'present'] }, 1, 0] } }
      }},
      { $project: { 
        classId: '$_id', 
        percentage: { $multiply: [{ $divide: ['$present', '$total'] }, 100] }
      }}
    ]);
    
    // Get class names
    const classIds = classWiseAttendance.map(c => c.classId);
    const classes = await Class.find({ classId: { $in: classIds } });
    const classMap = {};
    classes.forEach(c => { classMap[c.classId] = c.name + (c.section ? ` - ${c.section}` : ''); });
    
    // Weekly trend
    const weeklyTrend = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date(today.getTime() - i * 24 * 60 * 60 * 1000);
      const nextDate = new Date(date.getTime() + 24 * 60 * 60 * 1000);
      const dayRecords = weekAttendance.filter(r => r.date >= date && r.date < nextDate);
      const present = dayRecords.filter(r => r.status === 'present').length;
      const total = dayRecords.length;
      weeklyTrend.push({
        date: date.toISOString().split('T')[0],
        day: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][date.getDay()],
        percentage: total > 0 ? Math.round((present / total) * 100) : 0,
        present,
        total
      });
    }
    
    res.json({
      totalStudents,
      totalTeachers,
      totalClasses,
      todayAttendance: {
        percentage: todayAttendance.length > 0 ? Math.round((todayPresent / todayAttendance.length) * 100) : 0,
        present: todayPresent,
        total: todayAttendance.length
      },
      weekAttendance: {
        percentage: weekAttendance.length > 0 ? Math.round((weekPresent / weekAttendance.length) * 100) : 0,
        present: weekPresent,
        total: weekAttendance.length
      },
      monthAttendance: {
        percentage: monthAttendance.length > 0 ? Math.round((monthPresent / monthAttendance.length) * 100) : 0,
        present: monthPresent,
        total: monthAttendance.length
      },
      pendingApprovals,
      studentsBelow75: studentAttendance.length,
      studentsBelowThreshold: studentAttendance,
      recentAnnouncements,
      activeSessions: activeSessions.length,
      classWiseAttendance: classWiseAttendance.map(c => ({
        ...c,
        className: classMap[c.classId] || 'Unknown'
      })),
      weeklyTrend
    });
  } catch (err) {
    console.error('Dashboard stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Teacher Dashboard Stats
app.get('/api/dashboard/teacher-stats', authenticateToken, async (req, res) => {
  try {
    const { schoolId, userId, assignedClasses } = req.user;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const classFilter = assignedClasses?.length > 0 
      ? { classId: { $in: assignedClasses } }
      : {};
    
    const [
      totalStudents,
      todayAttendance,
      weekAttendance,
      recentSessions,
      announcements
    ] = await Promise.all([
      Student.countDocuments({ schoolId, ...classFilter, isActive: true }),
      AttendanceRecord.find({ schoolId, teacherId: userId, date: { $gte: today } }),
      AttendanceRecord.find({ 
        schoolId, 
        teacherId: userId,
        date: { $gte: new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000) } 
      }),
      AttendanceSession.find({ schoolId, teacherId: userId })
        .sort({ createdAt: -1 }).limit(10),
      Announcement.find({ 
        schoolId,
        $or: [
          { targetAudience: 'all' },
          { targetAudience: 'teachers' }
        ]
      }).sort({ createdAt: -1 }).limit(5)
    ]);
    
    const todayPresent = todayAttendance.filter(r => r.status === 'present').length;
    const weekPresent = weekAttendance.filter(r => r.status === 'present').length;
    
    // Weekly trend for teacher
    const weeklyTrend = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date(today.getTime() - i * 24 * 60 * 60 * 1000);
      const nextDate = new Date(date.getTime() + 24 * 60 * 60 * 1000);
      const dayRecords = weekAttendance.filter(r => r.date >= date && r.date < nextDate);
      const present = dayRecords.filter(r => r.status === 'present').length;
      const total = dayRecords.length;
      weeklyTrend.push({
        date: date.toISOString().split('T')[0],
        day: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][date.getDay()],
        percentage: total > 0 ? Math.round((present / total) * 100) : 0,
        present,
        total
      });
    }
    
    // Get assigned classes info
    const classes = await Class.find({ classId: { $in: assignedClasses || [] } });
    
    res.json({
      totalStudents,
      assignedClasses: classes.map(c => ({
        classId: c.classId,
        name: c.name,
        section: c.section,
        totalStudents: c.totalStudents
      })),
      todayAttendance: {
        percentage: todayAttendance.length > 0 ? Math.round((todayPresent / todayAttendance.length) * 100) : 0,
        present: todayPresent,
        total: todayAttendance.length
      },
      weekAttendance: {
        percentage: weekAttendance.length > 0 ? Math.round((weekPresent / weekAttendance.length) * 100) : 0,
        present: weekPresent,
        total: weekAttendance.length
      },
      recentSessions,
      announcements,
      weeklyTrend
    });
  } catch (err) {
    console.error('Teacher stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== USER/TEACHER ROUTES ====================

app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { role } = req.query;
    const filter = { schoolId: req.user.schoolId };
    if (role) filter.role = role;
    
    const users = await User.find(filter).select('-password -refreshToken -__v');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ 
      userId: req.params.userId,
      schoolId: req.user.schoolId 
    }).select('-password -refreshToken -__v');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { email, password, name, role, phone, assignedClasses, assignedSubjects } = req.body;
    
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(400).json({ error: 'Email already exists' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      schoolId: req.user.schoolId,
      email: email.toLowerCase(),
      password: hashedPassword,
      name,
      role,
      phone,
      assignedClasses: assignedClasses || [],
      assignedSubjects: assignedSubjects || []
    });
    
    await user.save();
    
    // Log action
    await new AuditLog({
      schoolId: req.user.schoolId,
      userId: req.user.userId,
      userName: req.user.name,
      action: 'CREATE_USER',
      entityType: 'user',
      entityId: user.userId,
      details: { name, role, email }
    }).save();
    
    res.status(201).json({
      userId: user.userId,
      email: user.email,
      name: user.name,
      role: user.role,
      schoolId: user.schoolId
    });
  } catch (err) {
    console.error('Create user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Only admin can update other users, users can only update themselves
    if (req.user.role !== 'admin' && req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const updates = { ...req.body, updatedAt: new Date() };
    delete updates.password;
    delete updates.email;
    delete updates.schoolId;
    delete updates.role;
    
    if (req.user.role === 'admin') {
      // Admin can update more fields
      if (req.body.assignedClasses) updates.assignedClasses = req.body.assignedClasses;
      if (req.body.assignedSubjects) updates.assignedSubjects = req.body.assignedSubjects;
      if (req.body.isActive !== undefined) updates.isActive = req.body.isActive;
    }
    
    const user = await User.findOneAndUpdate(
      { userId, schoolId: req.user.schoolId },
      updates,
      { new: true }
    ).select('-password -refreshToken -__v');
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findOneAndUpdate(
      { userId: req.params.userId, schoolId: req.user.schoolId },
      { isActive: false },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deactivated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== CLASS ROUTES ====================

app.get('/api/classes', authenticateToken, async (req, res) => {
  try {
    const classes = await Class.find({ schoolId: req.user.schoolId }).select('-__v');
    res.json(classes);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/classes/:classId', authenticateToken, async (req, res) => {
  try {
    const classDoc = await Class.findOne({ 
      classId: req.params.classId,
      schoolId: req.user.schoolId 
    }).select('-__v');
    if (!classDoc) return res.status(404).json({ error: 'Class not found' });
    res.json(classDoc);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/classes', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, section, academicYear, teacherId } = req.body;
    
    const classDoc = new Class({
      schoolId: req.user.schoolId,
      name,
      section,
      academicYear,
      teacherId
    });
    
    await classDoc.save();
    res.status(201).json(classDoc);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/classes/:classId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const classDoc = await Class.findOneAndUpdate(
      { classId: req.params.classId, schoolId: req.user.schoolId },
      req.body,
      { new: true }
    ).select('-__v');
    if (!classDoc) return res.status(404).json({ error: 'Class not found' });
    res.json(classDoc);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/classes/:classId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Class.findOneAndDelete({ classId: req.params.classId, schoolId: req.user.schoolId });
    res.json({ message: 'Class deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== SUBJECT ROUTES ====================

app.get('/api/subjects', authenticateToken, async (req, res) => {
  try {
    const subjects = await Subject.find({ schoolId: req.user.schoolId }).select('-__v');
    res.json(subjects);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/subjects', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const subject = new Subject({
      schoolId: req.user.schoolId,
      ...req.body
    });
    await subject.save();
    res.status(201).json(subject);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/subjects/:subjectId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const subject = await Subject.findOneAndUpdate(
      { subjectId: req.params.subjectId, schoolId: req.user.schoolId },
      req.body,
      { new: true }
    ).select('-__v');
    if (!subject) return res.status(404).json({ error: 'Subject not found' });
    res.json(subject);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/subjects/:subjectId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Subject.findOneAndDelete({ subjectId: req.params.subjectId, schoolId: req.user.schoolId });
    res.json({ message: 'Subject deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== STUDENT ROUTES ====================

app.get('/api/students', authenticateToken, async (req, res) => {
  try {
    const { classId, search, limit, skip } = req.query;
    const filter = { schoolId: req.user.schoolId, isActive: true };
    
    if (classId) filter.classId = classId;
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { rollNumber: { $regex: search, $options: 'i' } },
        { uid: { $regex: search, $options: 'i' } }
      ];
    }
    
    let query = Student.find(filter).select('-__v');
    if (limit) query = query.limit(parseInt(limit));
    if (skip) query = query.skip(parseInt(skip));
    
    const students = await query;
    const total = await Student.countDocuments(filter);
    
    res.json({ students, total });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/students/:studentId', authenticateToken, async (req, res) => {
  try {
    const student = await Student.findOne({ 
      studentId: req.params.studentId,
      schoolId: req.user.schoolId 
    }).select('-__v');
    if (!student) return res.status(404).json({ error: 'Student not found' });
    
    // Get attendance stats
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const attendance = await AttendanceRecord.find({
      studentId: student.studentId,
      date: { $gte: thirtyDaysAgo }
    });
    
    const present = attendance.filter(a => a.status === 'present').length;
    const total = attendance.length;
    
    res.json({
      ...student.toObject(),
      attendanceStats: {
        present,
        absent: total - present,
        total,
        percentage: total > 0 ? Math.round((present / total) * 100) : 0
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/students', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, rollNumber, classId, section, email, phone, parentPhone, address } = req.body;
    
    // Generate unique UID
    const uid = `STU-${Date.now()}-${Math.random().toString(36).substr(2, 5).toUpperCase()}`;
    
    // Generate QR data (encrypted/hashed)
    const qrData = Buffer.from(JSON.stringify({
      uid,
      schoolId: req.user.schoolId,
      timestamp: Date.now()
    })).toString('base64');
    
    // Generate QR code
    const qrCode = await QRCode.toDataURL(qrData);
    
    const student = new Student({
      schoolId: req.user.schoolId,
      uid,
      name,
      rollNumber,
      classId,
      section,
      email,
      phone,
      parentPhone,
      address,
      qrCode,
      qrData
    });
    
    await student.save();
    
    // Update class student count
    await Class.findOneAndUpdate(
      { classId },
      { $inc: { totalStudents: 1 } }
    );
    
    res.status(201).json(student);
  } catch (err) {
    console.error('Create student error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/students/bulk', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { students } = req.body;
    const results = [];
    
    for (const s of students) {
      const uid = `STU-${Date.now()}-${Math.random().toString(36).substr(2, 5).toUpperCase()}`;
      const qrData = Buffer.from(JSON.stringify({
        uid,
        schoolId: req.user.schoolId,
        timestamp: Date.now()
      })).toString('base64');
      const qrCode = await QRCode.toDataURL(qrData);
      
      const student = new Student({
        schoolId: req.user.schoolId,
        uid,
        qrCode,
        qrData,
        ...s
      });
      
      await student.save();
      results.push(student);
      
      // Update class count
      await Class.findOneAndUpdate(
        { classId: s.classId },
        { $inc: { totalStudents: 1 } }
      );
    }
    
    res.status(201).json({ created: results.length, students: results });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/students/:studentId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const updates = { ...req.body, updatedAt: new Date() };
    delete updates.uid;
    delete updates.qrCode;
    delete updates.qrData;
    delete updates.schoolId;
    
    const student = await Student.findOneAndUpdate(
      { studentId: req.params.studentId, schoolId: req.user.schoolId },
      updates,
      { new: true }
    ).select('-__v');
    
    if (!student) return res.status(404).json({ error: 'Student not found' });
    res.json(student);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/students/:studentId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const student = await Student.findOneAndUpdate(
      { studentId: req.params.studentId, schoolId: req.user.schoolId },
      { isActive: false },
      { new: true }
    );
    
    if (!student) return res.status(404).json({ error: 'Student not found' });
    
    // Update class count
    await Class.findOneAndUpdate(
      { classId: student.classId },
      { $inc: { totalStudents: -1 } }
    );
    
    res.json({ message: 'Student deactivated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Regenerate QR Code
app.post('/api/students/:studentId/regenerate-qr', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const student = await Student.findOne({ 
      studentId: req.params.studentId,
      schoolId: req.user.schoolId 
    });
    
    if (!student) return res.status(404).json({ error: 'Student not found' });
    
    const qrData = Buffer.from(JSON.stringify({
      uid: student.uid,
      schoolId: req.user.schoolId,
      timestamp: Date.now()
    })).toString('base64');
    
    const qrCode = await QRCode.toDataURL(qrData);
    
    student.qrData = qrData;
    student.qrCode = qrCode;
    student.updatedAt = new Date();
    await student.save();
    
    res.json({ qrCode, qrData });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Bulk generate QR codes
app.post('/api/students/bulk-qr', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { classId } = req.body;
    const filter = { schoolId: req.user.schoolId, isActive: true };
    if (classId) filter.classId = classId;
    
    const students = await Student.find(filter);
    const results = [];
    
    for (const student of students) {
      const qrData = Buffer.from(JSON.stringify({
        uid: student.uid,
        schoolId: req.user.schoolId,
        timestamp: Date.now()
      })).toString('base64');
      
      const qrCode = await QRCode.toDataURL(qrData);
      
      student.qrData = qrData;
      student.qrCode = qrCode;
      student.updatedAt = new Date();
      await student.save();
      
      results.push({
        studentId: student.studentId,
        name: student.name,
        uid: student.uid,
        qrCode
      });
    }
    
    res.json({ generated: results.length, students: results });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== ATTENDANCE SESSION ROUTES ====================

app.get('/api/attendance/sessions', authenticateToken, async (req, res) => {
  try {
    const { classId, status, date, limit } = req.query;
    const filter = { schoolId: req.user.schoolId };
    
    if (req.user.role === 'teacher') {
      filter.teacherId = req.user.userId;
    }
    if (classId) filter.classId = classId;
    if (status) filter.status = status;
    if (date) {
      const d = new Date(date);
      d.setHours(0, 0, 0, 0);
      const nextDay = new Date(d.getTime() + 24 * 60 * 60 * 1000);
      filter.date = { $gte: d, $lt: nextDay };
    }
    
    let query = AttendanceSession.find(filter).sort({ createdAt: -1 });
    if (limit) query = query.limit(parseInt(limit));
    
    const sessions = await query.select('-__v');
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/attendance/sessions', authenticateToken, async (req, res) => {
  try {
    const { classId, sessionType } = req.body;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    // Check if session already exists for today
    const existing = await AttendanceSession.findOne({
      schoolId: req.user.schoolId,
      classId,
      sessionType,
      date: { $gte: today }
    });
    
    if (existing && existing.status === 'active') {
      return res.status(400).json({ error: 'Active session already exists for this class and session type' });
    }
    
    const session = new AttendanceSession({
      schoolId: req.user.schoolId,
      classId,
      teacherId: req.user.userId,
      sessionType,
      date: today
    });
    
    await session.save();
    
    // Get class students count
    const classDoc = await Class.findOne({ classId });
    
    res.status(201).json({
      ...session.toObject(),
      className: classDoc?.name,
      classSection: classDoc?.section
    });
  } catch (err) {
    console.error('Create session error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/attendance/sessions/:sessionId/end', authenticateToken, async (req, res) => {
  try {
    const session = await AttendanceSession.findOne({
      sessionId: req.params.sessionId,
      schoolId: req.user.schoolId
    });
    
    if (!session) return res.status(404).json({ error: 'Session not found' });
    if (session.teacherId !== req.user.userId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Count attendance
    const records = await AttendanceRecord.find({ sessionId: session.sessionId });
    const present = records.filter(r => r.status === 'present').length;
    
    session.status = 'ended';
    session.endTime = new Date();
    session.totalPresent = present;
    session.totalAbsent = records.length - present;
    await session.save();
    
    res.json(session);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== ATTENDANCE RECORD ROUTES ====================

app.get('/api/attendance/records', authenticateToken, async (req, res) => {
  try {
    const { sessionId, classId, studentId, startDate, endDate, limit, skip } = req.query;
    const filter = { schoolId: req.user.schoolId };
    
    if (sessionId) filter.sessionId = sessionId;
    if (classId) filter.classId = classId;
    if (studentId) filter.studentId = studentId;
    if (startDate || endDate) {
      filter.date = {};
      if (startDate) filter.date.$gte = new Date(startDate);
      if (endDate) filter.date.$lte = new Date(endDate);
    }
    
    let query = AttendanceRecord.find(filter).sort({ date: -1, markedAt: -1 });
    if (limit) query = query.limit(parseInt(limit));
    if (skip) query = query.skip(parseInt(skip));
    
    const records = await query.select('-__v');
    const total = await AttendanceRecord.countDocuments(filter);
    
    res.json({ records, total });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark attendance via QR scan
app.post('/api/attendance/mark-qr', authenticateToken, async (req, res) => {
  try {
    const { sessionId, qrData } = req.body;
    
    const session = await AttendanceSession.findOne({ sessionId, status: 'active' });
    if (!session) return res.status(400).json({ error: 'Invalid or ended session' });
    
    // Decode QR data
    let decoded;
    try {
      decoded = JSON.parse(Buffer.from(qrData, 'base64').toString());
    } catch {
      return res.status(400).json({ error: 'Invalid QR code' });
    }
    
    const student = await Student.findOne({ uid: decoded.uid, schoolId: req.user.schoolId });
    if (!student) return res.status(404).json({ error: 'Student not found' });
    
    // Check if already marked
    const existing = await AttendanceRecord.findOne({
      sessionId,
      studentId: student.studentId
    });
    
    if (existing) {
      return res.status(400).json({ error: 'Attendance already marked for this student' });
    }
    
    const record = new AttendanceRecord({
      sessionId,
      schoolId: req.user.schoolId,
      studentId: student.studentId,
      classId: session.classId,
      teacherId: req.user.userId,
      date: session.date,
      sessionType: session.sessionType,
      status: 'present',
      markedBy: req.user.name,
      method: 'qr'
    });
    
    await record.save();
    
    // Update session count
    await AttendanceSession.findOneAndUpdate(
      { sessionId },
      { $inc: { totalPresent: 1 } }
    );
    
    res.status(201).json({
      ...record.toObject(),
      studentName: student.name,
      rollNumber: student.rollNumber
    });
  } catch (err) {
    console.error('Mark QR error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark attendance manually
app.post('/api/attendance/mark-manual', authenticateToken, async (req, res) => {
  try {
    const { sessionId, studentId, status } = req.body;
    
    const session = await AttendanceSession.findOne({ sessionId });
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    const student = await Student.findOne({ studentId, schoolId: req.user.schoolId });
    if (!student) return res.status(404).json({ error: 'Student not found' });
    
    // Check if already marked
    let record = await AttendanceRecord.findOne({ sessionId, studentId });
    
    if (record) {
      // Update existing record
      record.status = status;
      record.markedAt = new Date();
      record.markedBy = req.user.name;
      await record.save();
    } else {
      // Create new record
      record = new AttendanceRecord({
        sessionId,
        schoolId: req.user.schoolId,
        studentId,
        classId: session.classId,
        teacherId: req.user.userId,
        date: session.date,
        sessionType: session.sessionType,
        status,
        markedBy: req.user.name,
        method: 'manual'
      });
      await record.save();
    }
    
    // Update session counts
    const records = await AttendanceRecord.find({ sessionId });
    const present = records.filter(r => r.status === 'present').length;
    await AttendanceSession.findOneAndUpdate(
      { sessionId },
      { totalPresent: present, totalAbsent: records.length - present }
    );
    
    res.json({
      ...record.toObject(),
      studentName: student.name,
      rollNumber: student.rollNumber
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Bulk mark attendance
app.post('/api/attendance/mark-bulk', authenticateToken, async (req, res) => {
  try {
    const { sessionId, records: attendanceData } = req.body;
    
    const session = await AttendanceSession.findOne({ sessionId });
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    const results = [];
    
    for (const item of attendanceData) {
      let record = await AttendanceRecord.findOne({ 
        sessionId, 
        studentId: item.studentId 
      });
      
      if (record) {
        record.status = item.status;
        record.markedAt = new Date();
        record.markedBy = req.user.name;
        await record.save();
      } else {
        record = new AttendanceRecord({
          sessionId,
          schoolId: req.user.schoolId,
          studentId: item.studentId,
          classId: session.classId,
          teacherId: req.user.userId,
          date: session.date,
          sessionType: session.sessionType,
          status: item.status,
          markedBy: req.user.name,
          method: 'manual'
        });
        await record.save();
      }
      results.push(record);
    }
    
    // Update session counts
    const allRecords = await AttendanceRecord.find({ sessionId });
    const present = allRecords.filter(r => r.status === 'present').length;
    await AttendanceSession.findOneAndUpdate(
      { sessionId },
      { totalPresent: present, totalAbsent: allRecords.length - present }
    );
    
    res.json({ updated: results.length });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Edit attendance (creates approval request)
app.post('/api/attendance/edit-request', authenticateToken, async (req, res) => {
  try {
    const { recordId, newStatus, reason } = req.body;
    
    const record = await AttendanceRecord.findOne({ 
      recordId,
      schoolId: req.user.schoolId 
    });
    
    if (!record) return res.status(404).json({ error: 'Record not found' });
    
    const student = await Student.findOne({ studentId: record.studentId });
    const classDoc = await Class.findOne({ classId: record.classId });
    
    // Create approval request
    const request = new ApprovalRequest({
      schoolId: req.user.schoolId,
      type: 'attendance_edit',
      recordId,
      requestedBy: req.user.userId,
      requestedByName: req.user.name,
      studentId: record.studentId,
      studentName: student?.name,
      classId: record.classId,
      previousStatus: record.status,
      newStatus,
      reason
    });
    
    await request.save();
    
    // Create notification for admin
    const admins = await User.find({ schoolId: req.user.schoolId, role: 'admin' });
    for (const admin of admins) {
      await new Notification({
        schoolId: req.user.schoolId,
        userId: admin.userId,
        type: 'approval_request',
        title: 'Attendance Edit Request',
        message: `${req.user.name} requested to change ${student?.name}'s attendance from ${record.status} to ${newStatus}`,
        data: { requestId: request.requestId }
      }).save();
    }
    
    // Add to edit history
    record.editHistory.push({
      editedBy: req.user.userId,
      editedAt: new Date(),
      previousStatus: record.status,
      newStatus,
      reason,
      approvalStatus: 'pending'
    });
    await record.save();
    
    res.status(201).json(request);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== APPROVAL ROUTES ====================

app.get('/api/approvals', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status } = req.query;
    const filter = { schoolId: req.user.schoolId };
    if (status) filter.status = status;
    
    const requests = await ApprovalRequest.find(filter)
      .sort({ createdAt: -1 })
      .select('-__v');
    
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/approvals/:requestId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status } = req.body; // 'approved' or 'rejected'
    
    const request = await ApprovalRequest.findOne({
      requestId: req.params.requestId,
      schoolId: req.user.schoolId
    });
    
    if (!request) return res.status(404).json({ error: 'Request not found' });
    
    request.status = status;
    request.reviewedBy = req.user.userId;
    request.reviewedAt = new Date();
    await request.save();
    
    if (status === 'approved') {
      // Update the attendance record
      await AttendanceRecord.findOneAndUpdate(
        { recordId: request.recordId },
        { 
          status: request.newStatus,
          $push: {
            editHistory: {
              editedBy: request.requestedBy,
              editedAt: request.createdAt,
              previousStatus: request.previousStatus,
              newStatus: request.newStatus,
              reason: request.reason,
              approvalStatus: 'approved',
              approvedBy: req.user.userId,
              approvedAt: new Date()
            }
          }
        }
      );
    }
    
    // Notify requester
    await new Notification({
      schoolId: req.user.schoolId,
      userId: request.requestedBy,
      type: 'approval_response',
      title: `Attendance Edit ${status === 'approved' ? 'Approved' : 'Rejected'}`,
      message: `Your request to edit ${request.studentName}'s attendance has been ${status}`,
      data: { requestId: request.requestId }
    }).save();
    
    res.json(request);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== NOTIFICATION ROUTES ====================

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { unreadOnly, limit } = req.query;
    const filter = { 
      schoolId: req.user.schoolId,
      $or: [
        { userId: req.user.userId },
        { userId: null }
      ]
    };
    if (unreadOnly === 'true') filter.isRead = false;
    
    let query = Notification.find(filter).sort({ createdAt: -1 });
    if (limit) query = query.limit(parseInt(limit));
    
    const notifications = await query.select('-__v');
    const unreadCount = await Notification.countDocuments({ 
      ...filter, 
      isRead: false 
    });
    
    res.json({ notifications, unreadCount });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/notifications/:notificationId/read', authenticateToken, async (req, res) => {
  try {
    await Notification.findOneAndUpdate(
      { notificationId: req.params.notificationId },
      { isRead: true }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    await Notification.updateMany(
      { schoolId: req.user.schoolId, userId: req.user.userId },
      { isRead: true }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== ANNOUNCEMENT ROUTES ====================

app.get('/api/announcements', authenticateToken, async (req, res) => {
  try {
    const filter = { schoolId: req.user.schoolId };
    if (req.user.role === 'teacher') {
      // Teachers see: all announcements, teacher-only announcements, 
      // and specific class announcements if they teach that class
      const teacherClasses = req.user.assignedClasses || [];
      filter.$or = [
        { targetAudience: 'all' },
        { targetAudience: 'teachers' },
        { 
          targetAudience: 'specific_class',
          targetClasses: { $in: teacherClasses }
        }
      ];
    }
    
    const announcements = await Announcement.find(filter)
      .sort({ createdAt: -1 })
      .select('-__v');
    
    res.json(announcements);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/announcements', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const announcement = new Announcement({
      schoolId: req.user.schoolId,
      createdBy: req.user.userId,
      ...req.body
    });
    
    await announcement.save();
    res.status(201).json(announcement);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/announcements/:announcementId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Announcement.findOneAndDelete({
      announcementId: req.params.announcementId,
      schoolId: req.user.schoolId
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== AUDIT LOG ROUTES ====================

app.get('/api/audit-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { limit, skip } = req.query;
    
    let query = AuditLog.find({ schoolId: req.user.schoolId })
      .sort({ createdAt: -1 });
    
    if (limit) query = query.limit(parseInt(limit));
    if (skip) query = query.skip(parseInt(skip));
    
    const logs = await query.select('-__v');
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== SYNC ROUTES (For Offline) ====================

app.post('/api/sync/attendance', authenticateToken, async (req, res) => {
  try {
    const { sessions, records } = req.body;
    const results = { sessions: [], records: [] };
    
    // Sync sessions
    for (const s of sessions || []) {
      let session = await AttendanceSession.findOne({ sessionId: s.sessionId });
      if (!session) {
        session = new AttendanceSession({
          ...s,
          schoolId: req.user.schoolId,
          syncStatus: 'synced'
        });
        await session.save();
      }
      results.sessions.push(session.sessionId);
    }
    
    // Sync records
    for (const r of records || []) {
      let record = await AttendanceRecord.findOne({ recordId: r.recordId });
      if (!record) {
        record = new AttendanceRecord({
          ...r,
          schoolId: req.user.schoolId,
          syncStatus: 'synced'
        });
        await record.save();
      } else if (new Date(r.markedAt) > new Date(record.markedAt)) {
        // Update if incoming is newer
        record.status = r.status;
        record.markedAt = r.markedAt;
        record.syncStatus = 'synced';
        await record.save();
      }
      results.records.push(record.recordId);
    }
    
    res.json({ 
      synced: true, 
      timestamp: new Date().toISOString(),
      results 
    });
  } catch (err) {
    console.error('Sync error:', err);
    res.status(500).json({ error: 'Sync failed' });
  }
});

// Get data for offline cache
app.get('/api/sync/offline-data', authenticateToken, async (req, res) => {
  try {
    const { schoolId } = req.user;
    
    const [students, classes] = await Promise.all([
      Student.find({ schoolId, isActive: true })
        .select('studentId uid name rollNumber classId section qrData'),
      Class.find({ schoolId }).select('classId name section')
    ]);
    
    res.json({
      students,
      classes,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== REPORTS/ANALYTICS ROUTES ====================

app.get('/api/reports/attendance-summary', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate, classId } = req.query;
    const filter = { schoolId: req.user.schoolId };
    
    if (startDate || endDate) {
      filter.date = {};
      if (startDate) filter.date.$gte = new Date(startDate);
      if (endDate) filter.date.$lte = new Date(endDate);
    }
    if (classId) filter.classId = classId;
    
    const records = await AttendanceRecord.find(filter);
    
    // Group by date
    const byDate = {};
    records.forEach(r => {
      const dateStr = r.date.toISOString().split('T')[0];
      if (!byDate[dateStr]) {
        byDate[dateStr] = { present: 0, absent: 0, total: 0 };
      }
      byDate[dateStr].total++;
      if (r.status === 'present') byDate[dateStr].present++;
      else byDate[dateStr].absent++;
    });
    
    // Convert to array
    const dailyData = Object.entries(byDate).map(([date, data]) => ({
      date,
      ...data,
      percentage: Math.round((data.present / data.total) * 100)
    })).sort((a, b) => new Date(a.date) - new Date(b.date));
    
    // Overall stats
    const totalPresent = records.filter(r => r.status === 'present').length;
    const overallPercentage = records.length > 0 
      ? Math.round((totalPresent / records.length) * 100) 
      : 0;
    
    res.json({
      dailyData,
      overall: {
        total: records.length,
        present: totalPresent,
        absent: records.length - totalPresent,
        percentage: overallPercentage
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/reports/class-wise', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const filter = { schoolId: req.user.schoolId };
    
    if (startDate || endDate) {
      filter.date = {};
      if (startDate) filter.date.$gte = new Date(startDate);
      if (endDate) filter.date.$lte = new Date(endDate);
    }
    
    const data = await AttendanceRecord.aggregate([
      { $match: filter },
      { $group: {
        _id: '$classId',
        total: { $sum: 1 },
        present: { $sum: { $cond: [{ $eq: ['$status', 'present'] }, 1, 0] } }
      }},
      { $project: {
        classId: '$_id',
        total: 1,
        present: 1,
        absent: { $subtract: ['$total', '$present'] },
        percentage: { $round: [{ $multiply: [{ $divide: ['$present', '$total'] }, 100] }, 0] }
      }}
    ]);
    
    // Get class names
    const classIds = data.map(d => d.classId);
    const classes = await Class.find({ classId: { $in: classIds } });
    const classMap = {};
    classes.forEach(c => { classMap[c.classId] = { name: c.name, section: c.section }; });
    
    res.json(data.map(d => ({
      ...d,
      className: classMap[d.classId]?.name || 'Unknown',
      section: classMap[d.classId]?.section
    })));
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/reports/student-wise', authenticateToken, async (req, res) => {
  try {
    const { classId, belowThreshold } = req.query;
    const filter = { schoolId: req.user.schoolId };
    if (classId) filter.classId = classId;
    
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    filter.date = { $gte: thirtyDaysAgo };
    
    const data = await AttendanceRecord.aggregate([
      { $match: filter },
      { $group: {
        _id: '$studentId',
        total: { $sum: 1 },
        present: { $sum: { $cond: [{ $eq: ['$status', 'present'] }, 1, 0] } }
      }},
      { $project: {
        studentId: '$_id',
        total: 1,
        present: 1,
        absent: { $subtract: ['$total', '$present'] },
        percentage: { $round: [{ $multiply: [{ $divide: ['$present', '$total'] }, 100] }, 0] }
      }},
      { $sort: { percentage: 1 } }
    ]);
    
    // Filter below threshold if requested
    let filteredData = data;
    if (belowThreshold) {
      filteredData = data.filter(d => d.percentage < parseInt(belowThreshold));
    }
    
    // Get student details
    const studentIds = filteredData.map(d => d.studentId);
    const students = await Student.find({ studentId: { $in: studentIds } });
    const studentMap = {};
    students.forEach(s => { 
      studentMap[s.studentId] = { 
        name: s.name, 
        rollNumber: s.rollNumber,
        classId: s.classId 
      }; 
    });
    
    res.json(filteredData.map(d => ({
      ...d,
      name: studentMap[d.studentId]?.name || 'Unknown',
      rollNumber: studentMap[d.studentId]?.rollNumber,
      classId: studentMap[d.studentId]?.classId
    })));
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Teacher performance report
app.get('/api/reports/teacher-performance', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const filter = { schoolId: req.user.schoolId };
    
    const data = await AttendanceSession.aggregate([
      { $match: filter },
      { $group: {
        _id: '$teacherId',
        totalSessions: { $sum: 1 },
        totalPresent: { $sum: '$totalPresent' },
        totalAbsent: { $sum: '$totalAbsent' }
      }},
      { $project: {
        teacherId: '$_id',
        totalSessions: 1,
        totalPresent: 1,
        totalAbsent: 1,
        avgAttendance: {
          $round: [{
            $multiply: [{
              $divide: ['$totalPresent', { $add: ['$totalPresent', '$totalAbsent'] }]
            }, 100]
          }, 0]
        }
      }}
    ]);
    
    // Get teacher names
    const teacherIds = data.map(d => d.teacherId);
    const teachers = await User.find({ userId: { $in: teacherIds } });
    const teacherMap = {};
    teachers.forEach(t => { teacherMap[t.userId] = t.name; });
    
    res.json(data.map(d => ({
      ...d,
      teacherName: teacherMap[d.teacherId] || 'Unknown'
    })));
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== SEED DATA ====================

app.post('/api/seed', async (req, res) => {
  try {
    // Clear existing data
    await Promise.all([
      School.deleteMany({}),
      User.deleteMany({}),
      Class.deleteMany({}),
      Subject.deleteMany({}),
      Student.deleteMany({}),
      AttendanceSession.deleteMany({}),
      AttendanceRecord.deleteMany({}),
      ApprovalRequest.deleteMany({}),
      Notification.deleteMany({}),
      Announcement.deleteMany({}),
      AuditLog.deleteMany({})
    ]);
    
    // Create schools
    const schools = await School.insertMany([
      {
        schoolId: 'school-001',
        name: 'Greenfield Public School',
        address: '123 Education Lane, Rural District',
        phone: '+91 9876543210',
        email: 'admin@greenfield.edu',
        academicYear: '2024-2025',
        settings: { attendanceThreshold: 75, scanTimeWindow: 30 }
      },
      {
        schoolId: 'school-002',
        name: 'Sunrise Academy',
        address: '456 Knowledge Road, Valley Town',
        phone: '+91 9876543211',
        email: 'admin@sunrise.edu',
        academicYear: '2024-2025',
        settings: { attendanceThreshold: 75, scanTimeWindow: 30 }
      },
      {
        schoolId: 'school-003',
        name: 'Mountain View School',
        address: '789 Highland Avenue, Hill Station',
        phone: '+91 9876543212',
        email: 'admin@mountainview.edu',
        academicYear: '2024-2025',
        settings: { attendanceThreshold: 75, scanTimeWindow: 30 }
      }
    ]);
    
    // Create users for each school
    const hashedPassword = await bcrypt.hash('password123', 10);
    
    const users = [];
    for (const school of schools) {
      // Admin
      users.push({
        userId: `admin-${school.schoolId}`,
        schoolId: school.schoolId,
        email: `admin@${school.schoolId}.edu`,
        password: hashedPassword,
        name: `Principal ${school.name.split(' ')[0]}`,
        role: 'admin',
        phone: '+91 9800000001'
      });
      
      // Teachers
      for (let i = 1; i <= 5; i++) {
        users.push({
          userId: `teacher-${school.schoolId}-${i}`,
          schoolId: school.schoolId,
          email: `teacher${i}@${school.schoolId}.edu`,
          password: hashedPassword,
          name: `Teacher ${['Sharma', 'Patel', 'Kumar', 'Singh', 'Verma'][i-1]}`,
          role: 'teacher',
          phone: `+91 980000000${i}`,
          assignedClasses: [`class-${school.schoolId}-${i}-A`, `class-${school.schoolId}-${i}-B`],
          assignedSubjects: [`subject-${school.schoolId}-${i}`]
        });
      }
    }
    
    await User.insertMany(users);
    
    // Create classes for each school
    const classes = [];
    const classNames = ['Class 6', 'Class 7', 'Class 8', 'Class 9', 'Class 10'];
    const sections = ['A', 'B'];
    
    for (const school of schools) {
      for (let i = 0; i < classNames.length; i++) {
        for (const section of sections) {
          classes.push({
            classId: `class-${school.schoolId}-${i+1}-${section}`,
            schoolId: school.schoolId,
            name: classNames[i],
            section,
            academicYear: '2024-2025',
            teacherId: `teacher-${school.schoolId}-${(i % 5) + 1}`,
            totalStudents: 30
          });
        }
      }
    }
    
    await Class.insertMany(classes);
    
    // Create subjects
    const subjectNames = ['Mathematics', 'Science', 'English', 'Social Studies', 'Hindi'];
    const subjects = [];
    
    for (const school of schools) {
      for (let i = 0; i < subjectNames.length; i++) {
        subjects.push({
          subjectId: `subject-${school.schoolId}-${i+1}`,
          schoolId: school.schoolId,
          name: subjectNames[i],
          code: subjectNames[i].substring(0, 3).toUpperCase(),
          teacherIds: [`teacher-${school.schoolId}-${(i % 5) + 1}`]
        });
      }
    }
    
    await Subject.insertMany(subjects);
    
    // Create students
    const firstNames = ['Aarav', 'Vivaan', 'Aditya', 'Vihaan', 'Arjun', 'Sai', 'Reyansh', 'Ayaan', 'Krishna', 'Ishaan',
                        'Ananya', 'Aadhya', 'Myra', 'Pari', 'Anika', 'Saanvi', 'Diya', 'Pihu', 'Kiara', 'Navya'];
    const lastNames = ['Sharma', 'Patel', 'Kumar', 'Singh', 'Verma', 'Gupta', 'Mehta', 'Joshi', 'Rao', 'Reddy'];
    
    const students = [];
    
    for (const school of schools) {
      let rollNum = 1;
      for (const cls of classes.filter(c => c.schoolId === school.schoolId)) {
        for (let i = 0; i < 30; i++) {
          const firstName = firstNames[Math.floor(Math.random() * firstNames.length)];
          const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];
          const uid = `STU-${school.schoolId}-${rollNum}`;
          
          const qrData = Buffer.from(JSON.stringify({
            uid,
            schoolId: school.schoolId,
            timestamp: Date.now()
          })).toString('base64');
          
          const qrCode = await QRCode.toDataURL(qrData, { width: 200, margin: 1 });
          
          students.push({
            studentId: `student-${school.schoolId}-${rollNum}`,
            schoolId: school.schoolId,
            uid,
            name: `${firstName} ${lastName}`,
            rollNumber: rollNum.toString().padStart(3, '0'),
            classId: cls.classId,
            section: cls.section,
            email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}${rollNum}@student.edu`,
            phone: `+91 98${Math.floor(10000000 + Math.random() * 90000000)}`,
            parentPhone: `+91 97${Math.floor(10000000 + Math.random() * 90000000)}`,
            qrData,
            qrCode
          });
          rollNum++;
        }
      }
    }
    
    await Student.insertMany(students);
    
    // Create attendance sessions and records for past 30 days
    const sessions = [];
    const records = [];
    
    for (const school of schools) {
      const schoolStudents = students.filter(s => s.schoolId === school.schoolId);
      const schoolClasses = classes.filter(c => c.schoolId === school.schoolId);
      
      for (let dayOffset = 30; dayOffset >= 0; dayOffset--) {
        const date = new Date();
        date.setDate(date.getDate() - dayOffset);
        date.setHours(0, 0, 0, 0);
        
        // Skip weekends
        if (date.getDay() === 0 || date.getDay() === 6) continue;
        
        for (const cls of schoolClasses) {
          for (const sessionType of ['morning', 'afternoon']) {
            const sessionId = `session-${cls.classId}-${date.toISOString().split('T')[0]}-${sessionType}`;
            const teacherId = cls.teacherId;
            
            const classStudents = schoolStudents.filter(s => s.classId === cls.classId);
            let present = 0;
            let absent = 0;
            
            for (const student of classStudents) {
              // Random attendance (85% present rate)
              const isPresent = Math.random() > 0.15;
              const status = isPresent ? 'present' : 'absent';
              if (isPresent) present++;
              else absent++;
              
              records.push({
                recordId: `record-${student.studentId}-${date.toISOString().split('T')[0]}-${sessionType}`,
                sessionId,
                schoolId: school.schoolId,
                studentId: student.studentId,
                classId: cls.classId,
                teacherId,
                date,
                sessionType,
                status,
                markedAt: new Date(date.getTime() + (sessionType === 'morning' ? 9 : 14) * 60 * 60 * 1000),
                markedBy: 'System',
                method: Math.random() > 0.3 ? 'qr' : 'manual'
              });
            }
            
            sessions.push({
              sessionId,
              schoolId: school.schoolId,
              classId: cls.classId,
              teacherId,
              sessionType,
              date,
              startTime: new Date(date.getTime() + (sessionType === 'morning' ? 9 : 14) * 60 * 60 * 1000),
              endTime: new Date(date.getTime() + (sessionType === 'morning' ? 12 : 17) * 60 * 60 * 1000),
              status: 'ended',
              totalPresent: present,
              totalAbsent: absent
            });
          }
        }
      }
    }
    
    // Insert in batches
    const batchSize = 1000;
    for (let i = 0; i < sessions.length; i += batchSize) {
      await AttendanceSession.insertMany(sessions.slice(i, i + batchSize));
    }
    for (let i = 0; i < records.length; i += batchSize) {
      await AttendanceRecord.insertMany(records.slice(i, i + batchSize));
    }
    
    // Create sample announcements
    const announcements = [];
    for (const school of schools) {
      announcements.push({
        schoolId: school.schoolId,
        title: 'Welcome to New Academic Year',
        content: 'We are excited to begin the new academic year 2024-2025. Let\'s make it a great year!',
        targetAudience: 'all',
        createdBy: `admin-${school.schoolId}`
      });
      announcements.push({
        schoolId: school.schoolId,
        title: 'Parent-Teacher Meeting',
        content: 'PTM scheduled for next Saturday. All teachers please prepare student progress reports.',
        targetAudience: 'teachers',
        createdBy: `admin-${school.schoolId}`
      });
    }
    
    await Announcement.insertMany(announcements);
    
    res.json({ 
      success: true,
      seeded: {
        schools: schools.length,
        users: users.length,
        classes: classes.length,
        subjects: subjects.length,
        students: students.length,
        sessions: sessions.length,
        records: records.length,
        announcements: announcements.length
      },
      credentials: {
        school1: { email: 'admin@school-001.edu', password: 'password123' },
        school2: { email: 'admin@school-002.edu', password: 'password123' },
        school3: { email: 'admin@school-003.edu', password: 'password123' },
        teacher: { email: 'teacher1@school-001.edu', password: 'password123' }
      }
    });
  } catch (err) {
    console.error('Seed error:', err);
    res.status(500).json({ error: 'Seed failed', details: err.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Root
app.get('/api', (req, res) => {
  res.json({ message: 'MARKIT API Server' });
});

app.get('/', (req, res) => {
  res.send("Server running on test api")
  res.json({ message: 'MARKIT API Server' });
});

// Start server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running... on port ${PORT}`);
  });
}

app.models = {
  School,
  User,
  Class,
  Subject,
  Student,
  AttendanceSession,
  AttendanceRecord,
  ApprovalRequest,
  Notification,
  Announcement,
  AuditLog
};

module.exports = app;




