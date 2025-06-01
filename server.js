const express = require('express');
const admin = require('firebase-admin');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Firebase Admin
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.FIREBASE_CLIENT_EMAIL)}`,
  universe_domain: "googleapis.com"
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: process.env.FIREBASE_PROJECT_ID
});

const db = admin.firestore();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Firebase Config for client (without sensitive keys)
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  measurementId: process.env.FIREBASE_MEASUREMENT_ID
};

// Faculty emails list
const facultyEmails = process.env.FACULTY_EMAILS.split(',').map(email => email.trim());

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/signin', (req, res) => {
  // If user is already signed in, redirect based on profile completion
  if (req.session.uid) {
    return res.redirect('/check-redirect');
  }
  res.sendFile(path.join(__dirname, 'public', 'signin.html'));
});

// Route to check and redirect user based on their profile status
app.get('/check-redirect', requireAuth, async (req, res) => {
  try {
    const userRef = db.collection('users').doc(req.session.uid);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.redirect('/signin');
    }
    
    const userData = userDoc.data();
    
    // If profile is not complete, redirect to profile
    if (!userData.profileComplete) {
      return res.redirect('/profile');
    }
    
    // If profile is complete, redirect to dashboard
    return res.redirect('/dashboard');
  } catch (error) {
    console.error('Error checking user status:', error);
    res.redirect('/signin');
  }
});

app.get('/profile', requireAuth, async (req, res) => {
  try {
    const userRef = db.collection('users').doc(req.session.uid);
    const userDoc = await userRef.get();
    
    // If profile is already complete, redirect to dashboard
    if (userDoc.exists && userDoc.data().profileComplete) {
      return res.redirect('/dashboard');
    }
    
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
  } catch (error) {
    console.error('Error checking profile status:', error);
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
  }
});

app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const userRef = db.collection('users').doc(req.session.uid);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || !userDoc.data().profileComplete) {
      return res.redirect('/profile');
    }
    
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  } catch (error) {
    console.error('Error checking user profile:', error);
    res.redirect('/signin');
  }
});

app.get('/faculty', requireAuth, async (req, res) => {
  try {
    const userRef = db.collection('users').doc(req.session.uid);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || !facultyEmails.includes(userDoc.data().email)) {
      return res.status(403).send('Access denied. Faculty only.');
    }
    
    res.sendFile(path.join(__dirname, 'public', 'faculty.html'));
  } catch (error) {
    console.error('Error checking faculty access:', error);
    res.status(500).send('Server error');
  }
});

// API Routes
app.get('/api/config', (req, res) => {
  res.json(firebaseConfig);
});

// Enhanced session status check
app.get('/api/auth/status', async (req, res) => {
  if (!req.session.uid) {
    return res.json({ authenticated: false });
  }
  
  try {
    const userRef = db.collection('users').doc(req.session.uid);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      req.session.destroy();
      return res.json({ authenticated: false });
    }
    
    const userData = userDoc.data();
    res.json({
      authenticated: true,
      profileComplete: userData.profileComplete || false,
      user: {
        uid: req.session.uid,
        email: userData.email,
        name: userData.name,
        profilePicture: userData.profilePicture
      }
    });
  } catch (error) {
    console.error('Error checking auth status:', error);
    res.json({ authenticated: false });
  }
});

app.post('/api/auth/signin', async (req, res) => {
  try {
    const { idToken, userData } = req.body;
    
    // Verify the ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const uid = decodedToken.uid;
    
    // Check if user already exists
    const userRef = db.collection('users').doc(uid);
    const existingUser = await userRef.get();
    
    let profileComplete = false;
    let redirectUrl = '/profile';
    
    if (existingUser.exists) {
      // User exists, check if profile is complete
      const existingData = existingUser.data();
      profileComplete = existingData.profileComplete || false;
      
      // Update last login time
      await userRef.update({
        lastLoginAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // If profile is complete, redirect to dashboard
      if (profileComplete) {
        redirectUrl = '/dashboard';
      }
    } else {
      // New user, create profile
      await userRef.set({
        email: userData.email,
        name: userData.displayName,
        profilePicture: userData.photoURL,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
        profileComplete: false
      });
    }
    
    // Set session
    req.session.uid = uid;
    req.session.email = userData.email;
    
    res.json({ 
      success: true, 
      redirect: redirectUrl,
      profileComplete: profileComplete
    });
  } catch (error) {
    console.error('Error signing in:', error);
    res.status(400).json({ error: 'Invalid token' });
  }
});

app.post('/api/profile/update', requireAuth, async (req, res) => {
  try {
    const { hostelBlock, mobileNumber, regNumber } = req.body;
    
    // Validate registration number format (uppercase)
    if (!/^[A-Z0-9]+$/.test(regNumber)) {
      return res.status(400).json({ error: 'Registration number must contain only uppercase letters and numbers' });
    }
    
    // Check if registration number already exists
    const existingUser = await db.collection('users').where('regNumber', '==', regNumber).get();
    if (!existingUser.empty && existingUser.docs[0].id !== req.session.uid) {
      return res.status(400).json({ error: 'Registration number already exists' });
    }
    
    const userRef = db.collection('users').doc(req.session.uid);
    await userRef.update({
      hostelBlock,
      mobileNumber,
      regNumber,
      profileComplete: true,
      profileCompletedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    res.json({ success: true, redirect: '/dashboard' });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Enhanced user profile API with live data
app.get('/api/user/profile', requireAuth, async (req, res) => {
  try {
    const userRef = db.collection('users').doc(req.session.uid);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userData = userDoc.data();
    
    // Also fetch user's team information
    let teamInfo = null;
    if (userData.regNumber) {
      const teamQuery = await db.collection('teams').where('members', 'array-contains', userData.regNumber).get();
      if (!teamQuery.empty) {
        const teamDoc = teamQuery.docs[0];
        teamInfo = { id: teamDoc.id, ...teamDoc.data() };
      }
    }
    
    res.json({
      ...userData,
      team: teamInfo
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/team/create', requireAuth, async (req, res) => {
  try {
    const { teamName, memberRegNumbers, track, topic, pptLink, description } = req.body;
    
    // Validate team size (3-4 members including leader)
    if (memberRegNumbers.length < 2 || memberRegNumbers.length > 3) {
      return res.status(400).json({ error: 'Team must have 3-4 members (including you)' });
    }
    
    // Get current user with live data
    const currentUserRef = db.collection('users').doc(req.session.uid);
    const currentUserDoc = await currentUserRef.get();
    
    if (!currentUserDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const currentUser = currentUserDoc.data();
    
    // Check if current user is already in a team (live check)
    const existingTeam = await db.collection('teams').where('members', 'array-contains', currentUser.regNumber).get();
    if (!existingTeam.empty) {
      return res.status(400).json({ error: 'You are already part of a team' });
    }
    
    // Validate and get all team members with live data
    const allMembers = [currentUser.regNumber, ...memberRegNumbers];
    const memberDocs = [];
    
    for (const regNumber of memberRegNumbers) {
      const memberQuery = await db.collection('users').where('regNumber', '==', regNumber).get();
      if (memberQuery.empty) {
        return res.status(400).json({ error: `User with registration number ${regNumber} not found` });
      }
      
      const memberDoc = memberQuery.docs[0];
      const memberData = memberDoc.data();
      
      // Check if member is already in a team (live check)
      const memberTeam = await db.collection('teams').where('members', 'array-contains', regNumber).get();
      if (!memberTeam.empty) {
        return res.status(400).json({ error: `${memberData.name} is already part of a team` });
      }
      
      memberDocs.push({ id: memberDoc.id, ...memberData });
    }
    
    // Create team
    const teamRef = db.collection('teams').doc();
    await teamRef.set({
      teamName,
      leaderId: req.session.uid,
      leaderRegNumber: currentUser.regNumber,
      members: allMembers,
      memberDetails: [
        { id: req.session.uid, name: currentUser.name, regNumber: currentUser.regNumber, email: currentUser.email },
        ...memberDocs.map(member => ({ id: member.id, name: member.name, regNumber: member.regNumber, email: member.email }))
      ],
      track,
      topic,
      pptLink,
      description,
      status: 'pending',
      statusDescription: '',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      submissionVisible: false
    });
    
    res.json({ success: true, message: 'Team created successfully' });
  } catch (error) {
    console.error('Error creating team:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Enhanced team fetching with live data
app.get('/api/team/my-team', requireAuth, async (req, res) => {
  try {
    const currentUserRef = db.collection('users').doc(req.session.uid);
    const currentUserDoc = await currentUserRef.get();
    
    if (!currentUserDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const currentUser = currentUserDoc.data();
    
    if (!currentUser.regNumber) {
      return res.json({ hasTeam: false, message: 'Complete your profile first' });
    }
    
    const teamQuery = await db.collection('teams').where('members', 'array-contains', currentUser.regNumber).get();
    
    if (teamQuery.empty) {
      return res.json({ hasTeam: false });
    }
    
    const teamDoc = teamQuery.docs[0];
    const teamData = teamDoc.data();
    
    // Enrich team data with latest member information
    const enrichedMemberDetails = [];
    for (const member of teamData.memberDetails) {
      const memberRef = db.collection('users').doc(member.id);
      const memberDoc = await memberRef.get();
      if (memberDoc.exists) {
        const latestMemberData = memberDoc.data();
        enrichedMemberDetails.push({
          ...member,
          name: latestMemberData.name,
          email: latestMemberData.email,
          profilePicture: latestMemberData.profilePicture
        });
      } else {
        enrichedMemberDetails.push(member);
      }
    }
    
    res.json({ 
      hasTeam: true, 
      team: { 
        id: teamDoc.id, 
        ...teamData,
        memberDetails: enrichedMemberDetails
      } 
    });
  } catch (error) {
    console.error('Error fetching team:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/team/submit', requireAuth, async (req, res) => {
  try {
    const { githubLink, linkedinLink } = req.body;
    
    const currentUserRef = db.collection('users').doc(req.session.uid);
    const currentUserDoc = await currentUserRef.get();
    
    if (!currentUserDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const currentUser = currentUserDoc.data();
    const teamQuery = await db.collection('teams').where('members', 'array-contains', currentUser.regNumber).get();
    
    if (teamQuery.empty) {
      return res.status(400).json({ error: 'You are not part of any team' });
    }
    
    const teamDoc = teamQuery.docs[0];
    const teamData = teamDoc.data();
    
    if (teamData.status !== 'approved') {
      return res.status(400).json({ error: 'Team must be approved before submission' });
    }
    
    await teamDoc.ref.update({
      githubLink,
      linkedinLink,
      submittedAt: admin.firestore.FieldValue.serverTimestamp(),
      submittedBy: req.session.uid
    });
    
    res.json({ success: true, message: 'Submission completed successfully' });
  } catch (error) {
    console.error('Error submitting:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Faculty API Routes with live data
app.get('/api/faculty/users', requireAuth, requireFaculty, async (req, res) => {
  try {
    const usersSnapshot = await db.collection('users').orderBy('createdAt', 'desc').get();
    const users = usersSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/faculty/teams', requireAuth, requireFaculty, async (req, res) => {
  try {
    const teamsSnapshot = await db.collection('teams').orderBy('createdAt', 'desc').get();
    const teams = teamsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(teams);
  } catch (error) {
    console.error('Error fetching teams:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/faculty/team/approve', requireAuth, requireFaculty, async (req, res) => {
  try {
    const { teamId, status, statusDescription } = req.body;
    
    const teamRef = db.collection('teams').doc(teamId);
    const teamDoc = await teamRef.get();
    
    if (!teamDoc.exists) {
      return res.status(404).json({ error: 'Team not found' });
    }
    
    await teamRef.update({
      status,
      statusDescription,
      submissionVisible: status === 'approved',
      reviewedAt: admin.firestore.FieldValue.serverTimestamp(),
      reviewedBy: req.session.uid
    });
    
    res.json({ success: true, message: `Team ${status} successfully` });
  } catch (error) {
    console.error('Error updating team status:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// FIXED: Removed the problematic query that required composite index
app.get('/api/faculty/submissions', requireAuth, requireFaculty, async (req, res) => {
  try {
    // Get all teams first, then filter client-side
    const teamsSnapshot = await db.collection('teams').get();
    const submissions = teamsSnapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() }))
      .filter(team => team.githubLink && team.submittedAt) // Filter teams with submissions
      .sort((a, b) => {
        // Sort by submittedAt descending
        if (a.submittedAt && b.submittedAt) {
          return b.submittedAt._seconds - a.submittedAt._seconds;
        }
        return 0;
      });
    
    res.json(submissions);
  } catch (error) {
    console.error('Error fetching submissions:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Enhanced statistics API for live dashboard updates
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const [usersSnapshot, teamsSnapshot] = await Promise.all([
      db.collection('users').get(),
      db.collection('teams').get()
    ]);
    
    const totalUsers = usersSnapshot.size;
    const completedProfiles = usersSnapshot.docs.filter(doc => doc.data().profileComplete).length;
    const totalTeams = teamsSnapshot.size;
    const approvedTeams = teamsSnapshot.docs.filter(doc => doc.data().status === 'approved').length;
    const submissions = teamsSnapshot.docs.filter(doc => doc.data().githubLink).length;
    
    res.json({
      totalUsers,
      completedProfiles,
      totalTeams,
      approvedTeams,
      submissions,
      pendingApprovals: totalTeams - approvedTeams
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/signout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// Middleware functions
function requireAuth(req, res, next) {
  if (!req.session.uid) {
    return res.redirect('/signin');
  }
  next();
}

async function requireFaculty(req, res, next) {
  try {
    const userRef = db.collection('users').doc(req.session.uid);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || !facultyEmails.includes(userDoc.data().email)) {
      return res.status(403).json({ error: 'Faculty access required' });
    }
    
    next();
  } catch (error) {
    console.error('Error checking faculty access:', error);
    res.status(500).json({ error: 'Server error' });
  }
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});