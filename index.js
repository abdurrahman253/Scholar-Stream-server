require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const admin = require('firebase-admin');
const port = process.env.PORT || 3000;

// ========================
// Firebase Admin Setup
// ========================
let serviceAccount;
try {
  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf8");
  serviceAccount = JSON.parse(decoded);
  
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log('✅ Firebase initialized');
  }
} catch (err) {
  console.error("❌ Firebase initialization error:", err.message);
  // Don't crash - continue without Firebase
}

const app = express();

// ========================
// CORS Configuration
// ========================
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "https://scholar-stream-client-side-six.vercel.app"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(null, false);
      }
    },
    credentials: true
  })
);

app.options("*", cors());

// ========================
// Middleware
// ========================
app.use((req, res, next) => {
  // Skip JSON parsing for webhook route
  if (req.path === '/stripe-webhook') {
    next();
  } else {
    express.json()(req, res, next);
  }
});

// ========================
// JWT Verification
// ========================
const verifyJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ success: false, message: 'Unauthorized Access!' });
  }
  
  const token = authHeader.split('Bearer ')[1]?.trim();
  
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decodedToken.email;
    req.userUid = decodedToken.uid;
    next();
  } catch (err) {
    if (err.code === 'auth/id-token-expired') {
      return res.status(401).send({ 
        success: false, 
        message: 'Token expired', 
        code: 'TOKEN_EXPIRED' 
      });
    }
    return res.status(401).send({ success: false, message: 'Invalid token' });
  }
};

// ========================
// MongoDB Connection
// ========================
let client;
let db;
let scholarshipCollection;
let reviewsCollection;
let applicationsCollection;
let usersCollection;

async function connectDB() {
  if (db) return db; // Return existing connection
  
  try {
    client = new MongoClient(process.env.MONGODB_URI, {
      serverApi: { 
        version: ServerApiVersion.v1, 
        strict: true, 
        deprecationErrors: true 
      },
    });
    
    await client.connect();
    console.log('✅ MongoDB Connected');
    
    db = client.db(process.env.DB_NAME);
    scholarshipCollection = db.collection('scholarships');
    reviewsCollection = db.collection('reviews');
    applicationsCollection = db.collection('applications');
    usersCollection = db.collection('users');
    
    return db;
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    throw error;
  }
}

// ========================
// Role Verification Middlewares
// ========================
const verifyModerator = async (req, res, next) => {
  try {
    const user = await usersCollection.findOne({ email: req.tokenEmail });
    if (!user || (user.role !== 'moderator' && user.role !== 'admin')) {
      return res.status(403).send({ message: 'Forbidden: Restricted Access' });
    }
    req.userRole = user.role;
    next();
  } catch (error) {
    res.status(500).send({ message: 'Error verifying role' });
  }
};

const verifyAdmin = async (req, res, next) => {
  try {
    const user = await usersCollection.findOne({ email: req.tokenEmail });
    if (!user || user.role !== 'admin') {
      return res.status(403).send({ message: 'Forbidden: Admin Only' });
    }
    next();
  } catch (error) {
    res.status(500).send({ message: 'Error verifying admin' });
  }
};

// ========================
// Health Check Route
// ========================
app.get('/', async (req, res) => {
  try {
    await connectDB();
    res.send({ 
      status: 'OK', 
      message: 'Scholarship Server Running...', 
      timestamp: new Date().toISOString() 
    });
  } catch (error) {
    res.status(500).send({ 
      status: 'ERROR', 
      message: error.message 
    });
  }
});

// ========================
// USER ROUTES
// ========================
app.post('/users', async (req, res) => {
  try {
    await connectDB();
    const { email, name, photoURL } = req.body;
    
    if (!email) {
      return res.status(400).send({ message: 'Email is required' });
    }
    
    const existingUser = await usersCollection.findOne({ email });
    
    if (existingUser) {
      await usersCollection.updateOne(
        { email }, 
        { $set: { name, photoURL, lastLogin: new Date() } }
      );
      return res.send({ message: 'User updated' });
    }
    
    const result = await usersCollection.insertOne({
      email,
      name: name || 'Anonymous',
      photoURL: photoURL || '',
      role: 'student',
      createdAt: new Date(),
      lastLogin: new Date()
    });
    
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectDB();
    const users = await usersCollection.find().toArray();
    res.send(users);
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.get('/user/role', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const user = await usersCollection.findOne({ email: req.tokenEmail });
    res.send({ role: user?.role || 'student' });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.patch('/users/:id/role', verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectDB();
    await usersCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role: req.body.role } }
    );
    res.send({ success: true });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.delete('/users/:id', verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectDB();
    await usersCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.send({ success: true });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

// ========================
// SCHOLARSHIP ROUTES
// ========================
app.post('/scholarships', verifyJWT, verifyModerator, async (req, res) => {
  try {
    await connectDB();
    const data = req.body;
    
    const scholarshipData = {
      scholarshipName: data.scholarshipName,
      universityName: data.universityName,
      universityCountry: data.universityCountry,
      universityCity: data.universityCity,
      universityWorldRank: parseInt(data.universityWorldRank),
      subjectCategory: data.subjectCategory,
      scholarshipCategory: data.scholarshipCategory,
      degree: data.degree,
      tuitionFees: parseFloat(data.tuitionFees || 0),
      applicationFees: parseFloat(data.applicationFees),
      serviceCharge: parseFloat(data.serviceCharge),
      applicationDeadline: new Date(data.applicationDeadline),
      totalAmount: parseFloat(data.totalAmount),
      universityImage: data.universityImage,
      postedUserEmail: data.postedUserEmail,
      postDate: new Date()
    };

    const result = await scholarshipCollection.insertOne(scholarshipData);
    res.status(201).send({ success: true, scholarshipId: result.insertedId });
  } catch (error) {
    res.status(500).send({ success: false, message: error.message });
  }
});

app.get('/scholarships', async (req, res) => {
  try {
    await connectDB();
    const { 
      page = 1, 
      limit = 10, 
      search = '', 
      country = '', 
      category = '', 
      sortBy = 'postDate', 
      sortOrder = 'desc' 
    } = req.query;

    const query = {};
    
    if (search) {
      query.$or = [
        { scholarshipName: { $regex: search, $options: 'i' } },
        { universityName: { $regex: search, $options: 'i' } },
        { degree: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (country) {
      query.universityCountry = { $regex: country, $options: 'i' };
    }
    
    if (category) {
      query.scholarshipCategory = { $regex: category, $options: 'i' };
    }

    const sort = {};
    sort[sortBy] = sortOrder === 'asc' ? 1 : -1;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [scholarships, total] = await Promise.all([
      scholarshipCollection
        .find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      scholarshipCollection.countDocuments(query)
    ]);

    res.send({
      success: true,
      scholarships,
      total,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    res.status(500).send({ success: false, message: error.message });
  }
});

app.get('/scholarships-top', async (req, res) => {
  try {
    await connectDB();
    const top = await scholarshipCollection
      .find()
      .sort({ applicationFees: 1 })
      .limit(6)
      .toArray();
    res.send(top);
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.get('/scholarships/:id', async (req, res) => {
  try {
    await connectDB();
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: 'Invalid ID' });
    }
    
    const result = await scholarshipCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.patch('/scholarships/:id', verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectDB();
    const { id } = req.params;
    
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ 
        success: false, 
        message: 'Invalid scholarship ID' 
      });
    }

    const updateData = {};

    const fieldMap = {
      name: 'scholarshipName',
      university: 'universityName',
      country: 'universityCountry',
      city: 'universityCity',
      worldRank: 'universityWorldRank',
      subjectCategory: 'subjectCategory',
      scholarshipCategory: 'scholarshipCategory',
      degree: 'degree',
      tuitionFees: 'tuitionFees',
      applicationFees: 'applicationFees',
      serviceCharge: 'serviceCharge',
      deadline: 'applicationDeadline',
      postDate: 'postDate',
      stipend: 'stipend',
      scholarshipDescription: 'scholarshipDescription',
      universityImage: 'universityImage'
    };

    Object.keys(fieldMap).forEach(formKey => {
      if (req.body[formKey] !== undefined && req.body[formKey] !== '') {
        const dbKey = fieldMap[formKey];

        if (dbKey === 'universityWorldRank') {
          updateData[dbKey] = parseInt(req.body[formKey]);
        } else if (['applicationFees', 'serviceCharge', 'tuitionFees', 'stipend'].includes(dbKey)) {
          updateData[dbKey] = parseFloat(req.body[formKey]) || 0;
        } else if (['applicationDeadline', 'postDate'].includes(dbKey)) {
          updateData[dbKey] = new Date(req.body[formKey]);
        } else {
          updateData[dbKey] = req.body[formKey].trim();
        }
      }
    });

    updateData.postedUserEmail = req.tokenEmail;

    const appFee = parseFloat(req.body.applicationFees) || 0;
    const servFee = parseFloat(req.body.serviceCharge) || 0;
    if (req.body.applicationFees || req.body.serviceCharge) {
      updateData.totalAmount = appFee + servFee;
    }

    if (Object.keys(updateData).length === 0) {
      return res.status(400).send({ 
        success: false, 
        message: 'No data provided to update' 
      });
    }

    const result = await scholarshipCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ 
        success: false, 
        message: 'Scholarship not found' 
      });
    }

    res.send({ success: true, message: 'Scholarship updated successfully!' });
  } catch (error) {
    console.error('Update scholarship error:', error);
    res.status(500).send({ 
      success: false, 
      message: 'Failed to update scholarship' 
    });
  }
});

app.delete('/scholarships/:id', verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectDB();
    const { id } = req.params;
    
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ 
        success: false, 
        message: 'Invalid scholarship ID' 
      });
    }

    const result = await scholarshipCollection.deleteOne({ 
      _id: new ObjectId(id) 
    });

    if (result.deletedCount === 0) {
      return res.status(404).send({ 
        success: false, 
        message: 'Scholarship not found' 
      });
    }

    res.send({ success: true, message: 'Scholarship deleted successfully!' });
  } catch (error) {
    console.error('Delete scholarship error:', error);
    res.status(500).send({ 
      success: false, 
      message: 'Failed to delete scholarship' 
    });
  }
});

// ========================
// PAYMENT & APPLICATION ROUTES
// ========================
app.post('/create-checkout-session', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const {
      scholarshipId,
      scholarshipName,
      universityName,
      universityImage,
      universityCountry,
      universityCity,
      degree,
      subjectCategory,
      scholarshipCategory,
      applicationFees,
      serviceCharge,
      totalAmount,
      applicant,
      applicationDeadline,
      applicationDate,
      status
    } = req.body;

    if (!scholarshipId || !totalAmount || !applicant?.email) {
      return res.status(400).send({
        success: false,
        message: 'Missing required fields'
      });
    }

    if (applicant.email !== req.tokenEmail) {
      return res.status(403).send({
        success: false,
        message: 'Email mismatch. Unauthorized application.'
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      success_url: `${process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/payment-cancel`,
      customer_email: req.tokenEmail,
      client_reference_id: scholarshipId,
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: scholarshipName,
              description: `Application for ${universityName} - ${degree} in ${subjectCategory}`,
              images: [universityImage],
              metadata: {
                universityName,
                degree,
                scholarshipCategory
              }
            },
            unit_amount: Math.round(totalAmount * 100),
          },
          quantity: 1,
        },
      ],
      metadata: {
        scholarshipId,
        scholarshipName,
        universityName,
        applicantName: applicant.name,
        applicantEmail: req.tokenEmail,
        applicationFees: applicationFees.toString(),
        serviceCharge: serviceCharge.toString(),
        totalAmount: totalAmount.toString(),
        applicationDate,
        status
      },
    });

    const applicationData = {
      scholarshipId: new ObjectId(scholarshipId),
      scholarshipName,
      universityName,
      universityImage,
      universityCountry,
      universityCity,
      degree,
      subjectCategory,
      scholarshipCategory,
      applicationFees,
      serviceCharge,
      totalAmount,
      applicant: {
        name: applicant.name,
        email: req.tokenEmail,
        image: applicant.image
      },
      applicationDeadline,
      applicationDate: new Date(applicationDate || Date.now()),
      paymentStatus: 'pending',
      stripeSessionId: session.id,
      status: 'pending',
      createdAt: new Date()
    };

    await applicationsCollection.insertOne(applicationData);

    res.send({
      success: true,
      url: session.url,
      sessionId: session.id
    });
  } catch (error) {
    console.error('❌ Stripe checkout error:', error);
    res.status(500).send({
      success: false,
      message: 'Failed to create checkout session',
      error: error.message
    });
  }
});

app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    await connectDB();
    event = stripe.webhooks.constructEvent(
      req.body, 
      sig, 
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.log(`⚠️ Webhook Error: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;

    await applicationsCollection.updateOne(
      { stripeSessionId: session.id },
      {
        $set: {
          paymentStatus: 'paid',
          status: 'pending',
          paidAt: new Date()
        }
      }
    );

    console.log(`✅ Payment completed for session: ${session.id}`);
  }

  res.json({ received: true });
});

app.get('/verify-payment/:sessionId', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const { sessionId } = req.params;

    const session = await stripe.checkout.sessions.retrieve(sessionId);

    const application = await applicationsCollection.findOne({
      stripeSessionId: sessionId
    });

    if (!application) {
      return res.status(404).send({
        success: false,
        message: 'Application not found'
      });
    }

    if (application.applicant.email !== req.tokenEmail) {
      return res.status(403).send({
        success: false,
        message: 'Unauthorized access to this application'
      });
    }

    if (session.payment_status === 'paid') {
      await applicationsCollection.updateOne(
        { stripeSessionId: sessionId },
        {
          $set: {
            paymentStatus: 'paid',
            status: 'pending',
            paidAt: new Date()
          }
        }
      );

      return res.send({
        success: true,
        paymentStatus: 'paid',
        application: {
          ...application,
          paymentStatus: 'paid'
        },
        amountPaid: session.amount_total / 100
      });
    } else {
      return res.send({
        success: false,
        paymentStatus: 'unpaid',
        application
      });
    }
  } catch (error) {
    console.error('❌ Payment verification error:', error);
    res.status(500).send({
      success: false,
      message: 'Failed to verify payment',
      error: error.message
    });
  }
});

app.get('/my-applications', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const applications = await applicationsCollection
      .find({ 'applicant.email': req.tokenEmail })
      .sort({ applicationDate: -1 })
      .toArray();

    res.send({
      success: true,
      applications
    });
  } catch (error) {
    console.error('❌ Error fetching applications:', error);
    res.status(500).send({
      success: false,
      message: 'Failed to fetch applications'
    });
  }
});

app.post('/retry-payment/:applicationId', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const { applicationId } = req.params;

    const application = await applicationsCollection.findOne({
      _id: new ObjectId(applicationId),
      'applicant.email': req.tokenEmail,
      paymentStatus: 'pending'
    });

    if (!application) {
      return res.status(404).send({
        success: false,
        message: 'Application not found or already paid'
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      success_url: `${process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/payment-cancel`,
      customer_email: req.tokenEmail,
      client_reference_id: application.scholarshipId.toString(),
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: application.scholarshipName,
              description: `Retry: Application for ${application.universityName}`,
              images: [application.universityImage],
            },
            unit_amount: Math.round(application.totalAmount * 100),
          },
          quantity: 1,
        },
      ],
      metadata: {
        applicationId: applicationId,
        scholarshipId: application.scholarshipId.toString(),
        retryAttempt: 'true'
      },
    });

    await applicationsCollection.updateOne(
      { _id: new ObjectId(applicationId) },
      { $set: { stripeSessionId: session.id } }
    );

    res.send({
      success: true,
      url: session.url,
      sessionId: session.id
    });
  } catch (error) {
    console.error('❌ Retry payment error:', error);
    res.status(500).send({
      success: false,
      message: 'Failed to retry payment'
    });
  }
});

app.get('/applications/all', verifyJWT, verifyModerator, async (req, res) => {
  try {
    await connectDB();
    const apps = await applicationsCollection
      .find({})
      .sort({ applicationDate: -1 })
      .toArray();
    res.send(apps);
  } catch (error) {
    res.status(500).send({ message: 'Failed to fetch applications' });
  }
});

app.patch('/applications/:id/status', verifyJWT, verifyModerator, async (req, res) => {
  try {
    await connectDB();
    const { status } = req.body;
    const { id } = req.params;

    await applicationsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status, updatedAt: new Date() } }
    );

    res.send({ success: true });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.patch('/applications/:id/feedback', verifyJWT, verifyModerator, async (req, res) => {
  try {
    await connectDB();
    const { feedback } = req.body;
    const { id } = req.params;

    await applicationsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { feedback, feedbackDate: new Date() } }
    );

    res.send({ success: true });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.delete('/applications/:id', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: 'Invalid application ID' });
    }

    const app = await applicationsCollection.findOne({ 
      _id: new ObjectId(id) 
    });

    if (!app) {
      return res.status(404).send({ message: 'Application not found' });
    }

    if (app.applicant.email !== req.tokenEmail) {
      return res.status(403).send({ message: 'Unauthorized' });
    }

    if (app.status !== 'pending') {
      return res.status(403).send({ 
        message: 'Cannot delete non-pending applications' 
      });
    }

    const result = await applicationsCollection.deleteOne({
      _id: new ObjectId(id)
    });

    if (result.deletedCount === 0) {
      return res.status(500).send({ message: 'Delete failed' });
    }

    res.send({ success: true });
  } catch (error) {
    console.error('Delete application error:', error);
    res.status(500).send({ message: 'Server error' });
  }
});

// ========================
// REVIEWS ROUTES
// ========================
app.post('/reviews', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const reviewData = {
      ...req.body,
      scholarshipId: new ObjectId(req.body.scholarshipId),
      ratingPoint: parseInt(req.body.ratingPoint),
      reviewDate: new Date(),
      userEmail: req.tokenEmail
    };
    
    const result = await reviewsCollection.insertOne(reviewData);
    res.status(201).send({ success: true, reviewId: result.insertedId });
  } catch (error) {
    res.status(500).send({ success: false, message: error.message });
  }
});

app.get('/reviews/all', verifyJWT, verifyModerator, async (req, res) => {
  try {
    await connectDB();
    const reviews = await reviewsCollection
      .find({})
      .sort({ reviewDate: -1 })
      .toArray();
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch reviews' });
  }
});

app.get('/reviews/my', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const reviews = await reviewsCollection
      .find({ userEmail: req.tokenEmail })
      .sort({ reviewDate: -1 })
      .toArray();
    res.send(reviews);
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.patch('/reviews/:id', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const { id } = req.params;
    const filter = { _id: new ObjectId(id), userEmail: req.tokenEmail };
    const updateDoc = {
      $set: {
        ratingPoint: req.body.ratingPoint,
        reviewComment: req.body.reviewComment
      }
    };
    
    const result = await reviewsCollection.updateOne(filter, updateDoc);
    
    if (result.matchedCount === 0) {
      return res.status(403).send({ message: 'Unauthorized' });
    }
    
    res.send({ success: true });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.delete('/reviews/:id', verifyJWT, async (req, res) => {
  try {
    await connectDB();
    const { id } = req.params;
    const review = await reviewsCollection.findOne({ 
      _id: new ObjectId(id) 
    });
    
    if (!review) {
      return res.status(404).send({ message: 'Review not found' });
    }

    const user = await usersCollection.findOne({ email: req.tokenEmail });
    const isAdminMod = user.role === 'admin' || user.role === 'moderator';

    if (isAdminMod || review.userEmail === req.tokenEmail) {
      await reviewsCollection.deleteOne({ _id: new ObjectId(id) });
      return res.send({ success: true });
    }
    
    res.status(403).send({ message: 'Forbidden' });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

// ========================
// ADMIN STATISTICS
// ========================
app.get('/admin/statistics', verifyJWT, verifyAdmin, async (req, res) => {
  try {
    await connectDB();
    
    const [totalUsers, totalScholarships, totalApplications] = await Promise.all([
      usersCollection.countDocuments(),
      scholarshipCollection.countDocuments(),
      applicationsCollection.countDocuments()
    ]);

    const revenueStats = await applicationsCollection.aggregate([
      { $match: { paymentStatus: 'paid' } },
      { $group: { _id: null, total: { $sum: "$totalAmount" } } }
    ]).toArray();
    
    const totalFeesCollected = revenueStats[0]?.total || 0;

    const appsByUni = await applicationsCollection.aggregate([
      { $group: { _id: '$universityName', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]).toArray();

    const appsByCat = await applicationsCollection.aggregate([
      { $group: { _id: '$scholarshipCategory', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]).toArray();

    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const monthlyRev = await applicationsCollection.aggregate([
      {
        $match: {
          paymentStatus: 'paid',
          paidAt: { $gte: sixMonthsAgo }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: "$paidAt" },
            month: { $month: "$paidAt" }
          },
          revenue: { $sum: "$totalAmount" }
        }
      },
      { $sort: { "_id.year": 1, "_id.month": 1 } }
    ]).toArray();

    res.send({
      success: true,
      statistics: {
        totalUsers,
        totalScholarships,
        totalApplications,
        totalFeesCollected: totalFeesCollected.toFixed(2),
        applicationsByUniversity: appsByUni.map(i => ({
          name: i._id || 'Unknown',
          count: i.count
        })),
        applicationsByCategory: appsByCat.map(i => ({
          name: i._id || 'Unknown',
          count: i.count
        })),
        monthlyRevenue: monthlyRev.map(i => ({
          month: `${i._id.year}-${String(i._id.month).padStart(2, '0')}`,
          revenue: i.revenue
        }))
      }
    });
  } catch (error) {
    res.status(500).send({ success: false, message: error.message });
  }
});

// ========================
// Error Handling Middleware
// ========================
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).send({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ========================
// Initialize and Start Server
// ========================
const startServer = async () => {
  try {
    await connectDB();
    console.log('✅ Database connection established');
    
    app.listen(port, () => {
      console.log(`✅ Server running on port ${port}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// For Vercel serverless functions
if (process.env.VERCEL) {
  module.exports = app;
} else {
  startServer();
}