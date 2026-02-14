const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
require('dotenv').config();





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




module.exports = {
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
