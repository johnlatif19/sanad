require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

// ===================================================
// 1. التهيئة الأساسية والإعدادات الأمنية
// ===================================================
const app = express();
const PORT = process.env.PORT || 3000;

// Supabase Client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ===================================================
// 2. إعدادات الأمان المتقدمة
// ===================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://i.postimg.cc"],
    }
  }
}));

// CORS - السماح فقط لـ Vercel والـ localhost
app.use(cors({
  origin: ['https://sanad.vercel.app', 'http://localhost:3000'],
  credentials: true
}));

// Rate Limiting - 100 طلب لكل IP كل 15 دقيقة
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { ar: 'عدد الطلبات كبير جدًا، يرجى المحاولة لاحقًا.', en: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// ===================================================
// 3. إعدادات الجلسة (Session)
// ===================================================
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 // 24 ساعة
  }
}));

// ===================================================
// 4. Middleware أساسية
// ===================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// CSRF Protection (لحماية النماذج)
const csrfProtection = csrf({ cookie: false });
app.use('/api/', csrfProtection);

// ===================================================
// 5. إعداد البريد الإلكتروني (Nodemailer)
// ===================================================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ===================================================
// 6. دوال مساعدة (Helpers)
// ===================================================
// توليد كود متابعة آمن
function generateFollowCode() {
  return 'SANAD-' + uuidv4().split('-')[0].toUpperCase();
}

// الحصول على رسائل الخطأ باللغة المطلوبة
function getMessage(key, lang, params = {}) {
  const messages = {
    ar: {
      'invalid_input': 'بيانات غير صالحة.',
      'unauthorized': 'غير مصرح بالوصول.',
      'not_found': 'غير موجود.',
      'email_sent': 'تم إرسال تنبيه الطوارئ بنجاح!',
      'invalid_credentials': 'اسم المستخدم أو كلمة المرور غير صحيحة.',
      'code_invalid': 'كود المتابعة غير صحيح أو منتهي الصلاحية.',
      'linked_success': 'تم الربط بنجاح!',
      'alert_saved': 'تم حفظ التنبيه وإرسال البريد الإلكتروني.'
    },
    en: {
      'invalid_input': 'Invalid input.',
      'unauthorized': 'Unauthorized.',
      'not_found': 'Not found.',
      'email_sent': 'Emergency alert sent successfully!',
      'invalid_credentials': 'Invalid username or password.',
      'code_invalid': 'Invalid or expired follow code.',
      'linked_success': 'Linked successfully!',
      'alert_saved': 'Alert saved and email sent.'
    }
  };
  let msg = messages[lang]?.[key] || messages['ar'][key] || 'حدث خطأ.';
  // استبدال المتغيرات
  Object.keys(params).forEach(k => msg = msg.replace(`{{${k}}}`, params[k]));
  return msg;
}

// ===================================================
// 7. واجهات API - المصادقة (Authentication)
// ===================================================
// تسجيل مريض جديد
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, age, gender, medication, phone, bloodType, address, email, password, lang = 'ar' } = req.body;
    // التحقق من صحة الإدخال
    if (!name || !email || !password) {
      return res.status(400).json({ error: getMessage('invalid_input', lang) });
    }

    // التحقق من وجود البريد الإلكتروني
    const { data: existing } = await supabase
      .from('patients')
      .select('id')
      .eq('emergency_email', email)
      .maybeSingle();

    if (existing) {
      return res.status(400).json({ error: lang === 'ar' ? 'البريد الإلكتروني مسجل بالفعل.' : 'Email already registered.' });
    }

    // تشفير كلمة المرور
    const hashedPassword = await bcrypt.hash(password, 10);

    // إنشاء المتابع الأولي (لمنع الحذف)
    const { data: newPatient, error: insertError } = await supabase
      .from('patients')
      .insert([
        {
          name,
          age: parseInt(age),
          gender,
          medication,
          phone,
          blood_type: bloodType,
          address,
          emergency_email: email,
          password_hash: hashedPassword,
          follow_code: generateFollowCode(),
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (insertError) throw insertError;

    res.status(201).json({ message: lang === 'ar' ? 'تم التسجيل بنجاح!' : 'Registered successfully!', patient: { id: newPatient.id, name: newPatient.name } });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// تسجيل دخول المريض
app.post('/api/auth/patient-login', async (req, res) => {
  try {
    const { email, password, lang = 'ar' } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: getMessage('invalid_input', lang) });
    }

    const { data: patient, error } = await supabase
      .from('patients')
      .select('*')
      .eq('emergency_email', email)
      .maybeSingle();

    if (!patient || !(await bcrypt.compare(password, patient.password_hash))) {
      return res.status(401).json({ error: getMessage('invalid_credentials', lang) });
    }

    // تخزين الجلسة
    req.session.user = { id: patient.id, type: 'patient', name: patient.name };
    req.session.save();

    res.json({ message: 'Login successful', patient: { id: patient.id, name: patient.name } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// تسجيل دخول الأدمن
app.post('/api/auth/admin-login', async (req, res) => {
  try {
    const { username, password, lang = 'ar' } = req.body;
    if (username !== process.env.ADMIN_USERNAME) {
      return res.status(401).json({ error: getMessage('invalid_credentials', lang) });
    }

    const isValid = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    if (!isValid) {
      return res.status(401).json({ error: getMessage('invalid_credentials', lang) });
    }

    req.session.user = { type: 'admin' };
    req.session.save();
    res.json({ message: 'Admin login successful' });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// التحقق من حالة الجلسة
app.get('/api/auth/status', (req, res) => {
  if (req.session.user) {
    res.json({ authenticated: true, user: req.session.user });
  } else {
    res.json({ authenticated: false });
  }
});

// تسجيل الخروج
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.json({ message: 'Logged out' });
  });
});

// ===================================================
// 8. واجهات API - نظام الطوارئ (Emergency System)
// ===================================================
// إنشاء تنبيه طوارئ جديد
app.post('/api/emergency/create', async (req, res) => {
  try {
    // تحقق من المصادقة
    if (!req.session.user || req.session.user.type !== 'patient') {
      return res.status(401).json({ error: getMessage('unauthorized', req.body.lang || 'ar') });
    }

    const patientId = req.session.user.id;
    const { latitude, longitude, lang = 'ar' } = req.body;

    if (!latitude || !longitude) {
      return res.status(400).json({ error: getMessage('invalid_input', lang) });
    }

    // جلب بيانات المريض
    const { data: patient, error: patientError } = await supabase
      .from('patients')
      .select('*')
      .eq('id', patientId)
      .single();

    if (patientError || !patient) {
      return res.status(404).json({ error: getMessage('not_found', lang) });
    }

    // جلب المتابعين المرتبطين
    const { data: followers } = await supabase
      .from('followers')
      .select('*')
      .eq('patient_id', patientId);

    // إنشاء التنبيه
    const alertData = {
      patient_id: patientId,
      patient_name: patient.name,
      phone: patient.phone,
      age: patient.age,
      gender: patient.gender,
      blood_type: patient.blood_type,
      medication: patient.medication,
      address: patient.address,
      latitude: latitude,
      longitude: longitude,
      emergency_time: new Date().toISOString(),
      status: 'New'
    };

    const { data: alert, error: alertError } = await supabase
      .from('emergency_alerts')
      .insert([alertData])
      .select()
      .single();

    if (alertError) throw alertError;

    // إرسال البريد الإلكتروني لكل المتابعين
    const emailPromises = followers.map(async (follower) => {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: follower.contact_email || patient.emergency_email,
        subject: lang === 'ar' ? '🚨 تنبيه طوارئ من سَنَد' : '🚨 SANAD EMERGENCY ALERT',
        html: generateEmailHTML(patient, alert, lang)
      };
      return transporter.sendMail(mailOptions);
    });

    await Promise.allSettled(emailPromises);

    res.status(201).json({
      message: getMessage('alert_saved', lang),
      alert: alert
    });

  } catch (error) {
    console.error('Emergency error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// دالة لإنشاء HTML البريد الإلكتروني
function generateEmailHTML(patient, alert, lang) {
  const mapLink = `https://www.google.com/maps?q=${alert.latitude},${alert.longitude}`;
  if (lang === 'ar') {
    return `
      <div dir="rtl" style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd;">
        <h1 style="color: #d32f2f;">🚨 تنبيه طوارئ من سَنَد</h1>
        <p><strong>المريض:</strong> ${patient.name}</p>
        <p><strong>رقم الهاتف:</strong> ${patient.phone}</p>
        <p><strong>العمر:</strong> ${patient.age}</p>
        <p><strong>الجنس:</strong> ${patient.gender}</p>
        <p><strong>فصيلة الدم:</strong> ${patient.blood_type || 'غير محدد'}</p>
        <p><strong>العلاج:</strong> ${patient.medication || 'غير محدد'}</p>
        <p><strong>العنوان:</strong> ${patient.address || 'غير محدد'}</p>
        <hr>
        <p><strong>الموقع الحالي:</strong> ${alert.latitude}, ${alert.longitude}</p>
        <p><a href="${mapLink}" target="_blank">📍 فتح الموقع على الخريطة</a></p>
        <p><strong>وقت الطوارئ:</strong> ${new Date(alert.emergency_time).toLocaleString('ar-EG')}</p>
        <hr>
        <p style="color: #d32f2f;"><strong>يرجى التواصل مع المريض أو خدمات الطوارئ فورًا.</strong></p>
      </div>
    `;
  } else {
    return `
      <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd;">
        <h1 style="color: #d32f2f;">🚨 SANAD EMERGENCY ALERT</h1>
        <p><strong>Patient:</strong> ${patient.name}</p>
        <p><strong>Phone:</strong> ${patient.phone}</p>
        <p><strong>Age:</strong> ${patient.age}</p>
        <p><strong>Gender:</strong> ${patient.gender}</p>
        <p><strong>Blood Type:</strong> ${patient.blood_type || 'Not specified'}</p>
        <p><strong>Medication:</strong> ${patient.medication || 'Not specified'}</p>
        <p><strong>Address:</strong> ${patient.address || 'Not specified'}</p>
        <hr>
        <p><strong>Current Location:</strong> ${alert.latitude}, ${alert.longitude}</p>
        <p><a href="${mapLink}" target="_blank">📍 Open Location on Map</a></p>
        <p><strong>Emergency Time:</strong> ${new Date(alert.emergency_time).toLocaleString('en-US')}</p>
        <hr>
        <p style="color: #d32f2f;"><strong>Please contact the patient or emergency services immediately.</strong></p>
      </div>
    `;
  }
}

// ===================================================
// 9. واجهات API - نظام المتابعة (Follow System)
// ===================================================
// ربط متابع بمريض عبر كود المتابعة
app.post('/api/follow/link', async (req, res) => {
  try {
    const { name, phone, followCode, lang = 'ar' } = req.body;
    if (!name || !phone || !followCode) {
      return res.status(400).json({ error: getMessage('invalid_input', lang) });
    }

    // التحقق من الكود وجلب المريض
    const { data: patient, error: patientError } = await supabase
      .from('patients')
      .select('id, name')
      .eq('follow_code', followCode.toUpperCase())
      .maybeSingle();

    if (!patient) {
      return res.status(404).json({ error: getMessage('code_invalid', lang) });
    }

    // التحقق من عدم وجود المتابع مسبقًا
    const { data: existing } = await supabase
      .from('followers')
      .select('id')
      .eq('phone', phone)
      .eq('patient_id', patient.id)
      .maybeSingle();

    if (existing) {
      return res.status(400).json({ error: lang === 'ar' ? 'أنت متابع بالفعل لهذا المريض.' : 'You are already following this patient.' });
    }

    // إنشاء المتابع
    const { data: follower, error: insertError } = await supabase
      .from('followers')
      .insert([
        {
          name,
          phone,
          patient_id: patient.id,
          contact_email: null, // يمكن إضافة بريد إلكتروني للتواصل
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (insertError) throw insertError;

    res.status(201).json({
      message: getMessage('linked_success', lang),
      follower: follower,
      patientName: patient.name
    });

  } catch (error) {
    console.error('Follow link error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===================================================
// 10. واجهات API - لوحة التحكم (Admin Dashboard)
// ===================================================
// Middleware للتحقق من صلاحيات الأدمن
const isAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.type === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
};

// جلب جميع المرضى
app.get('/api/admin/patients', isAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('patients')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Admin patients error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// جلب جميع المتابعين
app.get('/api/admin/followers', isAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('followers')
      .select('*, patients(name)')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Admin followers error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// جلب جميع تنبيهات الطوارئ
app.get('/api/admin/alerts', isAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('emergency_alerts')
      .select('*')
      .order('emergency_time', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Admin alerts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// تحديث حالة التنبيه
app.put('/api/admin/alerts/:id', isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const validStatuses = ['New', 'Contacted', 'Emergency Services Called', 'Resolved'];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const { data, error } = await supabase
      .from('emergency_alerts')
      .update({ status })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Update alert error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===================================================
// 11. تشغيل الخادم
// ===================================================
// نقطة النهاية لجلب CSRF Token
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// صفحة 404 (يتم التعامل معها بواسطة React Router في Frontend)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Sanad server running on port ${PORT}`);
});
