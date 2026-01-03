require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const multer = require('multer');
const path = require('path');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)
const admin = require('firebase-admin');
const port = process.env.PORT || 3000;

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf-8');
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

app.use(
  cors({
    origin: [
      'http://localhost:5173',
      'http://localhost:5174',
      process.env.CLIENT_URL
    ].filter(Boolean),
    credentials: true,
    optionsSuccessStatus: 200,
  })
)
app.use(express.json());
app.use('/uploads', express.static('uploads'));


// Multer config - local storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });


// JWT Middleware
const verifyJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ message: 'Unauthorized Access! No token provided' });
  }

  const token = authHeader.split('Bearer ')[1]?.trim(); // <-- Critical: split on 'Bearer ' (with space)

  if (!token) {
    return res.status(401).send({ message: 'Unauthorized Access! Empty token' });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    req.userUid = decoded.uid; // Optional: useful later
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    return res.status(401).send({ message: 'Unauthorized Access! Invalid or expired token' });
  }
};




// MongoDB Client
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const db = client.db(process.env.DB_NAME);
    const scholarshipCollection = db.collection('scholarships');
    const reviewsCollection = db.collection('reviews');
    const applicationsCollection = db.collection('applications');
    const usersCollection = db.collection('users');




    
    const verifyModeratorOrAdmin = async (req, res, next) => {
      try {
        const user = await usersCollection.findOne({ email: req.tokenEmail });
        if (!user || (user.role !== 'moderator' && user.role !== 'admin')) {
          return res.status(403).send({ message: 'Forbidden: Moderator or Admin access required' });
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
          return res.status(403).send({ message: 'Forbidden: Admin access required' });
        }
        next();
      } catch (error) {
        res.status(500).send({ message: 'Error verifying admin role' });
      }
    };



  // POST: Add new scholarship (Admin only + image upload)
app.post('/scholarships', verifyJWT, verifyAdmin, upload.single('image'), async (req, res) => {
  try {
    const {
      name,
      university,
      country,
      city,
      worldRank,
      subjectCategory,
      scholarshipCategory,
      degree,
      tuitionFees,
      applicationFees,
      serviceCharge,
      deadline,
      postDate,
      userEmail
    } = req.body;

    // Validation
    if (!name || !university || !country || !city || !worldRank || 
        !subjectCategory || !scholarshipCategory || !degree || 
        !applicationFees || !serviceCharge || !deadline || !postDate || !userEmail) {
      return res.status(400).send({ 
        success: false, 
        message: 'All required fields must be provided' 
      });
    }

    const totalAmount = parseFloat(applicationFees) + parseFloat(serviceCharge);

    const scholarshipData = {
      name: name.trim(),
      university: university.trim(),
      country: country.trim(),
      city: city.trim(),
      worldRank: parseInt(worldRank),
      subjectCategory: subjectCategory.trim(),
      scholarshipCategory: scholarshipCategory.trim(),
      degree: degree.trim(),
      tuitionFees: tuitionFees ? parseFloat(tuitionFees) : null,
      applicationFees: parseFloat(applicationFees),
      serviceCharge: parseFloat(serviceCharge),
      totalAmount,
      deadline: new Date(deadline),
      postDate: new Date(postDate),
      userEmail: userEmail.trim(),
      createdAt: new Date(),
      createdBy: req.tokenEmail, 
      status: 'active'
    };

    // Image handling
    if (req.file) {
      scholarshipData.image = `/uploads/${req.file.filename}`;
    }

    const result = await scholarshipCollection.insertOne(scholarshipData);

    res.send({
      success: true,
      message: 'Scholarship added successfully!',
      scholarshipId: result.insertedId
    });

  } catch (error) {
    console.error('Add scholarship error:', error);
    res.status(500).send({ 
      success: false, 
      message: 'Failed to add scholarship',
      error: error.message 
    });
  }
});



    // GET: Top 6 scholarships
    app.get('/scholarships-top', async (req, res) => {
      try {
        const topScholarships = await scholarshipCollection
          .find()
          .sort({ applicationFees: 1 })
          .limit(6)
          .toArray();
        res.send(topScholarships);
      } catch (error) {
        console.error('Error fetching top scholarships:', error);
        res.status(500).send({ message: 'Failed to fetch top scholarships' });
      }
    });

    // GET: All scholarships
    app.get('/scholarships', async (req, res) => {
      const result = await scholarshipCollection.find().toArray();
      res.send(result);
    });

    // GET: Single scholarship
    app.get('/scholarships/:id', async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: 'Invalid scholarship ID' });
        }
        const result = await scholarshipCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!result) {
          return res.status(404).send({ message: 'Scholarship not found' });
        }
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Internal Server Error' });
      }
    });


    // reviews routes from here

    // GET: Reviews for scholarship
    app.get('/reviews/:scholarshipId', async (req, res) => {
      try {
        const { scholarshipId } = req.params;
        if (!ObjectId.isValid(scholarshipId)) {
          return res.status(400).send({ message: 'Invalid scholarship ID' });
        }
        const reviews = await reviewsCollection
          .find({ scholarshipId: new ObjectId(scholarshipId) })
          .sort({ reviewDate: -1 })
          .toArray();

        const averageRating = reviews.length > 0
          ? reviews.reduce((sum, review) => sum + review.ratingPoint, 0) / reviews.length
          : 0;

        res.send({
          success: true,
          reviews,
          averageRating: parseFloat(averageRating.toFixed(1)),
          totalReviews: reviews.length
        });
      } catch (error) {
        console.error('Error fetching reviews:', error);
        res.status(500).send({
          success: false,
          message: 'Failed to fetch reviews',
          error: error.message
        });
      }
    });

    // POST: Add review (with JWT)
    app.post('/reviews', verifyJWT, async (req, res) => {
      try {
        const reviewData = req.body;
        if (!reviewData.scholarshipId || !reviewData.ratingPoint || !reviewData.reviewComment) {
          return res.status(400).send({
            success: false,
            message: 'Required fields missing'
          });
        }
        if (!ObjectId.isValid(reviewData.scholarshipId)) {
          return res.status(400).send({ message: 'Invalid scholarship ID' });
        }

        reviewData.scholarshipId = new ObjectId(reviewData.scholarshipId);
        reviewData.reviewDate = new Date();
        reviewData.userEmail = req.tokenEmail; // Add email for moderation

        const result = await reviewsCollection.insertOne(reviewData);
        res.status(201).send({
          success: true,
          message: 'Review added successfully',
          reviewId: result.insertedId
        });
      } catch (error) {
        console.error('Error adding review:', error);
        res.status(500).send({
          success: false,
          message: 'Failed to add review',
          error: error.message
        });
      }
    });






    // POST: Create Stripe Checkout Session
app.post('/create-checkout-session', verifyJWT, async (req, res) => {
  try {
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
    } = req.body

    // Validate required fields
    if (!scholarshipId || !totalAmount || !applicant?.email) {
      return res.status(400).send({ 
        success: false, 
        message: 'Missing required fields' 
      })
    }

    // Create Stripe checkout session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      success_url: `${process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/payment-cancel`,
      customer_email: applicant.email,
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
            unit_amount: Math.round(totalAmount * 100), // Convert to cents
          },
          quantity: 1,
        },
      ],
      metadata: {
        scholarshipId,
        scholarshipName,
        universityName,
        applicantName: applicant.name,
        applicantEmail: applicant.email,
        applicationFees: applicationFees.toString(),
        serviceCharge: serviceCharge.toString(),
        totalAmount: totalAmount.toString(),
        applicationDate,
        status
      },
    })

    // Optional: Save application to database immediately
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
        email: applicant.email,
        image: applicant.image
      },
      applicationDeadline,
      applicationDate,
      paymentStatus: 'pending',
      stripeSessionId: session.id,
      status: 'pending'
    }

  
    await applicationsCollection.insertOne(applicationData)
    res.send({ 
      success: true, 
      url: session.url,
      sessionId: session.id
    })
  } catch (error) {
    console.error('Stripe checkout error:', error)
    res.status(500).send({ 
      success: false, 
      message: 'Failed to create checkout session',
      error: error.message 
    })
  }
})


  // Webhook থেকে আসা event handle করার জন্য
app.post('/stripe-webhook', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.log(`Webhook Error: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Payment success handle করুন
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
  }

  res.json({received: true});
});

// Payment verification route - Success page এর জন্য
app.get('/verify-payment/:sessionId', verifyJWT, async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    // Stripe session retrieve করুন
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    
    // Database থেকে application data নিন
    const application = await applicationsCollection.findOne({ 
      stripeSessionId: sessionId 
    });

    if (!application) {
      return res.status(404).send({ 
        success: false, 
        message: 'Application not found' 
      });
    }

    // Payment status update করুন
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

      res.send({
        success: true,
        paymentStatus: 'paid',
        application: {
          ...application,
          paymentStatus: 'paid'
        },
        amountPaid: session.amount_total / 100 // Convert from cents
      });
    } else {
      res.send({
        success: false,
        paymentStatus: 'unpaid',
        application
      });
    }
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).send({ 
      success: false, 
      message: 'Failed to verify payment',
      error: error.message 
    });
  }
});

// GET: User এর applications (Dashboard এর জন্য)
app.get('/my-applications', verifyJWT, async (req, res) => {
  try {
    const applications = await applicationsCollection
      .find({ 'applicant.email': req.tokenEmail })
      .sort({ applicationDate: -1 })
      .toArray();
    
    res.send({ 
      success: true, 
      applications 
    });
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).send({ 
      success: false, 
      message: 'Failed to fetch applications' 
    });
  }
});

// POST: Retry payment for failed applications
app.post('/retry-payment/:applicationId', verifyJWT, async (req, res) => {
  try {
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

    // নতুন Stripe session তৈরি করুন
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      success_url: `${process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/payment-cancel`,
      customer_email: application.applicant.email,
      client_reference_id: application.scholarshipId.toString(),
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: application.scholarshipName,
              description: `Application for ${application.universityName}`,
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
      },
    });

    // Session ID update করুন
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
    console.error('Retry payment error:', error);
    res.status(500).send({ 
      success: false, 
      message: 'Failed to retry payment' 
    });
  }
});












// GET: Admin Statistics
app.get('/admin/statistics', verifyJWT, async (req, res) => {
  try {
    // Verify admin role (আপনার auth system অনুযায়ী adjust করুন)
    // const user = await usersCollection.findOne({ email: req.tokenEmail });
    // if (user?.role !== 'admin') {
    //   return res.status(403).send({ message: 'Forbidden Access' });
    // }

    // Total Users Count
    const totalUsers = await db.collection('users').countDocuments();

    // Total Scholarships Count
    const totalScholarships = await scholarshipCollection.countDocuments();

    // Total Fees Collected (শুধুমাত্র paid applications)
    const paidApplications = await applicationsCollection
      .find({ paymentStatus: 'paid' })
      .toArray();
    
    const totalFeesCollected = paidApplications.reduce(
      (sum, app) => sum + (app.totalAmount || 0),
      0
    );

    // Total Applications
    const totalApplications = await applicationsCollection.countDocuments();

    // Applications by University
    const applicationsByUniversity = await applicationsCollection.aggregate([
      {
        $group: {
          _id: '$universityName',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]).toArray();

    // Applications by Scholarship Category
    const applicationsByCategory = await applicationsCollection.aggregate([
      {
        $group: {
          _id: '$scholarshipCategory',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]).toArray();

    // Applications by Subject Category
    const applicationsBySubject = await applicationsCollection.aggregate([
      {
        $group: {
          _id: '$subjectCategory',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 8 }
    ]).toArray();

    // Monthly Revenue (last 6 months)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const monthlyRevenue = await applicationsCollection.aggregate([
      {
        $match: {
          paymentStatus: 'paid',
          paidAt: { $gte: sixMonthsAgo }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$paidAt' },
            month: { $month: '$paidAt' }
          },
          revenue: { $sum: '$totalAmount' },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } }
    ]).toArray();

    res.send({
      success: true,
      statistics: {
        totalUsers,
        totalScholarships,
        totalFeesCollected: parseFloat(totalFeesCollected.toFixed(2)),
        totalApplications,
        applicationsByUniversity: applicationsByUniversity.map(item => ({
          name: item._id || 'Unknown',
          count: item.count
        })),
        applicationsByCategory: applicationsByCategory.map(item => ({
          name: item._id || 'Unknown',
          count: item.count
        })),
        applicationsBySubject: applicationsBySubject.map(item => ({
          name: item._id || 'Unknown',
          count: item.count
        })),
        monthlyRevenue: monthlyRevenue.map(item => ({
          month: `${item._id.year}-${String(item._id.month).padStart(2, '0')}`,
          revenue: parseFloat(item.revenue.toFixed(2)),
          count: item.count
        }))
      }
    });
  } catch (error) {
    console.error('Error fetching admin statistics:', error);
    res.status(500).send({
      success: false,
      message: 'Failed to fetch statistics',
      error: error.message
    });
  }
});









 // POST: Save or update user in MongoDB after sign up/login
app.post('/users', async (req, res) => {
  try {
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
      return res.send({ message: 'User updated', upserted: false });
    }

    const newUser = {
      email,
      name: name || 'Anonymous',
      photoURL: photoURL || '',
      role: 'student',         
      createdAt: new Date(),
      lastLogin: new Date()
    };

    const result = await usersCollection.insertOne(newUser);
    res.send({ message: 'User created', insertedId: result.insertedId });

  } catch (error) {
    console.error('Error saving user:', error);
    res.status(500).send({ message: 'Failed to save user' });
  }
});








// GET: All users (Admin only)
app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
  // Optional: role check for admin
  try {
    const users = await usersCollection.find({}).toArray();
    res.send(users);
  } catch (error) {
    res.status(500).send({ message: 'Failed to fetch users' });
  }
});


// GET: Current user's role
app.get('/user/role', verifyJWT, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ email: req.tokenEmail });
    res.send({ role: user?.role || 'student' });
  } catch (error) {
    res.status(500).send({ role: 'student' });
  }
});

// PATCH: Change user role (Admin only)
app.patch('/users/:id/role', verifyJWT, verifyAdmin, async (req, res) => {
  const { role } = req.body;
  const { id } = req.params;
  try {
    await usersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { role } }
    );
    res.send({ success: true });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update role' });
  }
});

// DELETE: Delete user (Admin only)
app.delete('/users/:id', verifyJWT, async (req, res) => {
  const { id } = req.params;
  try {
    await usersCollection.deleteOne({ _id: new ObjectId(id) });
    res.send({ success: true });
  } catch (error) {
    res.status(500).send({ message: 'Failed to delete user' });
  }
});


// GET: All scholarships for admin
app.get('/scholarships/admin', verifyJWT, verifyAdmin, async (req, res) => {
  const scholarships = await scholarshipCollection.find({}).toArray();
  res.send(scholarships);
});

// PATCH: Update scholarship
app.patch('/scholarships/:id', verifyJWT, verifyAdmin, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const data = req.body;
  if (req.file) data.image = `/uploads/${req.file.filename}`;
  await scholarshipCollection.updateOne({ _id: new ObjectId(id) }, { $set: data });
  res.send({ success: true });
});

// DELETE: Delete scholarship
app.delete('/scholarships/:id', verifyJWT, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  await scholarshipCollection.deleteOne({ _id: new ObjectId(id) });
  res.send({ success: true });
});



// === Applications Routes ===
// GET: All applications (Moderator + Admin)
app.get('/applications/all', verifyJWT, verifyModeratorOrAdmin, async (req, res) => {
  try {
    const apps = await applicationsCollection.find({}).toArray();
    res.send(apps);
  } catch (error) {
    res.status(500).send({ message: 'Failed' });
  }
});

// PATCH: Update status
app.patch('/applications/:id/status', verifyJWT, verifyModeratorOrAdmin, async (req, res) => {
  const { status } = req.body;
  const { id } = req.params;
  await applicationsCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { status } }
  );
  res.send({ success: true });
});

// PATCH: Add feedback
app.patch('/applications/:id/feedback', verifyJWT, verifyModeratorOrAdmin, async (req, res) => {
  const { feedback } = req.body;
  const { id } = req.params;
  await applicationsCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { feedback } }
  );
  res.send({ success: true });
});

// DELETE: Student delete pending application
app.delete('/applications/:id', verifyJWT, async (req, res) => {
  const { id } = req.params;
  const app = await applicationsCollection.findOne({ _id: new ObjectId(id) });
  if (app.status === 'pending' && app.applicant.email === req.tokenEmail) {
    await applicationsCollection.deleteOne({ _id: new ObjectId(id) });
    res.send({ success: true });
  } else {
    res.status(403).send({ message: 'Forbidden' });
  }
});

// === Reviews Routes ===
// GET: All reviews (Moderator)
app.get('/reviews/all', verifyJWT, verifyModeratorOrAdmin, async (req, res) => {
  const reviews = await reviewsCollection.find({}).sort({ reviewDate: -1 }).toArray();
  res.send(reviews);
});

// GET: My reviews (Student)
app.get('/reviews/my', verifyJWT, async (req, res) => {
  const reviews = await reviewsCollection
    .find({ userEmail: req.tokenEmail })
    .sort({ reviewDate: -1 })
    .toArray();
  res.send(reviews);
});

// PATCH: Update review
app.patch('/reviews/:id', verifyJWT, async (req, res) => {
  const { ratingPoint, reviewComment } = req.body;
  const { id } = req.params;
  const review = await reviewsCollection.findOne({ _id: new ObjectId(id) });
  if (review.userEmail === req.tokenEmail) {
    await reviewsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { ratingPoint, reviewComment } }
    );
    res.send({ success: true });
  } else {
    res.status(403).send({ message: 'Forbidden' });
  }
});

// DELETE: Review (Moderator or Owner)
app.delete('/reviews/:id', verifyJWT, verifyModeratorOrAdmin, async (req, res) => {
  const { id } = req.params;
  const review = await reviewsCollection.findOne({ _id: new ObjectId(id) });
  // Moderator can delete any, student only own
  if (review.userEmail === req.tokenEmail || req.userRole === 'moderator') {
    await reviewsCollection.deleteOne({ _id: new ObjectId(id) });
    res.send({ success: true });
  } else {
    res.status(403).send({ message: 'Forbidden' });
  }
});



    await client.db('admin').command({ ping: 1 });
    console.log('Connected to MongoDB!');
  } finally {}
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Hello from Server..');
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});