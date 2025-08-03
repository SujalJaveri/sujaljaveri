const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
        },
    },
}));

app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});

const contactLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // limit each IP to 5 contact form submissions per hour
    message: 'Too many contact form submissions, please try again later.'
});

app.use(limiter);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/sujal_portfolio', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
    console.log('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});

// MongoDB Schemas
const ContactSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    subject: { type: String, required: true, trim: true },
    message: { type: String, required: true, trim: true },
    ipAddress: { type: String },
    userAgent: { type: String },
    status: { 
        type: String, 
        enum: ['new', 'read', 'replied', 'archived'], 
        default: 'new' 
    },
    createdAt: { type: Date, default: Date.now },
    readAt: { type: Date },
    repliedAt: { type: Date }
});

const VisitorSchema = new mongoose.Schema({
    ipAddress: { type: String, required: true },
    userAgent: { type: String },
    referrer: { type: String },
    country: { type: String },
    city: { type: String },
    device: { type: String },
    browser: { type: String },
    visitedPages: [{ 
        page: String, 
        timestamp: { type: Date, default: Date.now } 
    }],
    sessionDuration: { type: Number }, // in seconds
    isReturningVisitor: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    lastVisit: { type: Date, default: Date.now }
});

const ProjectSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    image: { type: String },
    technologies: [{ type: String }],
    githubUrl: { type: String },
    liveUrl: { type: String },
    featured: { type: Boolean, default: false },
    status: { 
        type: String, 
        enum: ['planning', 'in-progress', 'completed', 'on-hold'], 
        default: 'planning' 
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const BlogSchema = new mongoose.Schema({
    title: { type: String, required: true },
    slug: { type: String, required: true, unique: true },
    content: { type: String, required: true },
    excerpt: { type: String },
    featuredImage: { type: String },
    tags: [{ type: String }],
    published: { type: Boolean, default: false },
    views: { type: Number, default: 0 },
    likes: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    publishedAt: { type: Date }
});

const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'moderator'], default: 'admin' },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Models
const Contact = mongoose.model('Contact', ContactSchema);
const Visitor = mongoose.model('Visitor', VisitorSchema);
const Project = mongoose.model('Project', ProjectSchema);
const Blog = mongoose.model('Blog', BlogSchema);
const Admin = mongoose.model('Admin', AdminSchema);

// Email Configuration
const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'));
        }
    }
});

// Middleware Functions
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

const trackVisitor = async (req, res, next) => {
    try {
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.get('User-Agent');
        const referrer = req.get('Referrer');
        
        let visitor = await Visitor.findOne({ ipAddress });
        
        if (visitor) {
            visitor.isReturningVisitor = true;
            visitor.lastVisit = new Date();
            visitor.visitedPages.push({
                page: req.originalUrl,
                timestamp: new Date()
            });
        } else {
            visitor = new Visitor({
                ipAddress,
                userAgent,
                referrer,
                visitedPages: [{
                    page: req.originalUrl,
                    timestamp: new Date()
                }]
            });
        }
        
        await visitor.save();
        next();
    } catch (error) {
        console.error('Visitor tracking error:', error);
        next();
    }
};

// Routes

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Contact Form
app.post('/api/contact', contactLimiter, trackVisitor, async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;
        
        // Validation
        if (!name || !email || !subject || !message) {
            return res.status(400).json({ 
                message: 'All fields are required' 
            });
        }
        
        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                message: 'Invalid email format' 
            });
        }
        
        // Save to database
        const contact = new Contact({
            name: name.trim(),
            email: email.trim().toLowerCase(),
            subject: subject.trim(),
            message: message.trim(),
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });
        
        await contact.save();
        
        // Send email notification
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: 'sujal309206@gmail.com',
            subject: `Portfolio Contact: ${subject}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #667eea;">New Contact Form Submission</h2>
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
                        <h3 style="color: #333; margin-bottom: 15px;">Contact Details:</h3>
                        <p><strong>Name:</strong> ${name}</p>
                        <p><strong>Email:</strong> ${email}</p>
                        <p><strong>Subject:</strong> ${subject}</p>
                    </div>
                    <div style="background: #fff; padding: 20px; border: 1px solid #e9ecef; border-radius: 10px;">
                        <h3 style="color: #333; margin-bottom: 15px;">Message:</h3>
                        <p style="line-height: 1.6;">${message}</p>
                    </div>
                    <div style="margin-top: 20px; padding: 15px; background: #e7f3ff; border-radius: 5px;">
                        <small style="color: #666;">
                            <strong>IP Address:</strong> ${req.ip}<br>
                            <strong>User Agent:</strong> ${req.get('User-Agent')}<br>
                            <strong>Timestamp:</strong> ${new Date().toLocaleString()}
                        </small>
                    </div>
                </div>
            `
        };
        
        // Send auto-reply to sender
        const autoReplyOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Thank you for contacting Sujal Javeri',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #667eea;">Thank you for reaching out!</h2>
                    <p>Hi ${name},</p>
                    <p>Thank you for your message. I've received your inquiry about "${subject}" and will get back to you as soon as possible.</p>
                    <p>In the meantime, feel free to connect with me on:</p>
                    <ul>
                        <li><a href="https://www.linkedin.com/in/sujal-javeri-b50638282" style="color: #667eea;">LinkedIn</a></li>
                        <li><a href="https://instagram.com/sujal_javeri" style="color: #667eea;">Instagram</a></li>
                    </ul>
                    <p>Best regards,<br>Sujal Javeri</p>
                    <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 10px;">
                        <h3 style="color: #333;">Your Message:</h3>
                        <p style="font-style: italic;">"${message}"</p>
                    </div>
                </div>
            `
        };
        
        await transporter.sendMail(mailOptions);
        await transporter.sendMail(autoReplyOptions);
        
        res.status(200).json({ 
            message: 'Message sent successfully! You will receive a confirmation email shortly.' 
        });
        
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ 
            message: 'Failed to send message. Please try again later.' 
        });
    }
});

// Analytics
app.get('/api/analytics', authenticateToken, async (req, res) => {
    try {
        const totalVisitors = await Visitor.countDocuments();
        const totalContacts = await Contact.countDocuments();
        const recentContacts = await Contact.find()
            .sort({ createdAt: -1 })
            .limit(10)
            .select('name email subject status createdAt');
        
        const visitorStats = await Visitor.aggregate([
            {
                $group: {
                    _id: {
                        year: { $year: '$createdAt' },
                        month: { $month: '$createdAt' },
                        day: { $dayOfMonth: '$createdAt' }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { '_id.year': -1, '_id.month': -1, '_id.day': -1 } },
            { $limit: 30 }
        ]);
        
        const contactStats = await Contact.aggregate([
            {
                $group: {
                    _id: '$status',
                    count: { $sum: 1 }
                }
            }
        ]);
        
        res.json({
            totalVisitors,
            totalContacts,
            recentContacts,
            visitorStats,
            contactStats
        });
        
    } catch (error) {
        console.error('Analytics error:', error);
        res.status(500).json({ message: 'Failed to fetch analytics' });
    }
});

// Projects CRUD
app.get('/api/projects', trackVisitor, async (req, res) => {
    try {
        const { featured, status, limit } = req.query;
        let query = {};
        
        if (featured === 'true') query.featured = true;
        if (status) query.status = status;
        
        const projects = await Project.find(query)
            .sort({ createdAt: -1 })
            .limit(limit ? parseInt(limit) : 0);
            
        res.json(projects);
    } catch (error) {
        console.error('Projects fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch projects' });
    }
});

app.post('/api/projects', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { title, description, technologies, githubUrl, liveUrl, featured, status } = req.body;
        
        const project = new Project({
            title,
            description,
            technologies: Array.isArray(technologies) ? technologies : technologies.split(','),
            githubUrl,
            liveUrl,
            featured: featured === 'true',
            status,
            image: req.file ? `/uploads/${req.file.filename}` : null
        });
        
        await project.save();
        res.status(201).json({ message: 'Project created successfully', project });
    } catch (error) {
        console.error('Project creation error:', error);
        res.status(500).json({ message: 'Failed to create project' });
    }
});

// Blog CRUD
app.get('/api/blog', trackVisitor, async (req, res) => {
    try {
        const { published, limit } = req.query;
        let query = {};
        
        if (published === 'true') query.published = true;
        
        const blogs = await Blog.find(query)
            .sort({ createdAt: -1 })
            .limit(limit ? parseInt(limit) : 0)
            .select('title slug excerpt featuredImage tags published views likes createdAt');
            
        res.json(blogs);
    } catch (error) {
        console.error('Blog fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch blog posts' });
    }
});

app.get('/api/blog/:slug', trackVisitor, async (req, res) => {
    try {
        const blog = await Blog.findOne({ slug: req.params.slug });
        
        if (!blog) {
            return res.status(404).json({ message: 'Blog post not found' });
        }
        
        // Increment view count
        blog.views += 1;
        await blog.save();
        
        res.json(blog);
    } catch (error) {
        console.error('Blog fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch blog post' });
    }
});

// Admin Authentication
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        const isValidPassword = await bcrypt.compare(password, admin.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        admin.lastLogin = new Date();
        await admin.save();
        
        const token = jwt.sign(
            { userId: admin._id, username: admin.username, role: admin.role },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Login successful',
            token,
            user: {
                id: admin._id,
                username: admin.username,
                email: admin.email,
                role: admin.role
            }
        });
        
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ message: 'Login failed' });
    }
});

// Contact Management
app.get('/api/admin/contacts', authenticateToken, async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.query;
        let query = {};
        
        if (status) query.status = status;
        
        const contacts = await Contact.find(query)
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
            
        const total = await Contact.countDocuments(query);
        
        res.json({
            contacts,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            totalContacts: total
        });
    } catch (error) {
        console.error('Contacts fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch contacts' });
    }
});

app.patch('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            { 
                status,
                readAt: status === 'read' ? new Date() : undefined,
                repliedAt: status === 'replied' ? new Date() : undefined
            },
            { new: true }
        );
        
        if (!contact) {
            return res.status(404).json({ message: 'Contact not found' });
        }
        
        res.json({ message: 'Contact updated successfully', contact });
    } catch (error) {
        console.error('Contact update error:', error);
        res.status(500).json({ message: 'Failed to update contact' });
    }
});

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Error:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ message: 'File too large. Maximum size is 5MB.' });
        }
    }
    
    res.status(500).json({ message: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
