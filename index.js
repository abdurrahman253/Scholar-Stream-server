require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
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
      'https://b12-m11-session.web.app',
    ],
    credentials: true,
    optionSuccessStatus: 200,
  })
);
app.use(express.json());

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