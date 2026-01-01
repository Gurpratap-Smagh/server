//  TODO: Can you create backend with standard folder structure like: week-4/hard ???
import express from 'express';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import { z } from 'zod';
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from 'helmet';
// Simple URL validation function
function isSafeUrl(url) {
  try {
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
}

import { LoginAttempt } from "./loginAttemptSchema.js";
import rateLimit from "express-rate-limit";


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 250, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: "Too many requests from this IP, please try again later.",
});



const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: '10kb' }));
app.use(limiter);
app.use(cookieParser());
app.use(helmet);
// Configure CORS with allowed origins from environment variable
const allowedOrigins = process.env.ALLOWED_ORIGINS ? 
  process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : [];

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    // Allow if the origin is in our list
    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

// Handle preflight requests
app.options('*', cors(corsOptions));

// Use CORS for all other requests
app.use(cors(corsOptions));


// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  console.error(`Missing required environment variables: ${missingVars.join(', ')}`);
  process.exit(1);
}

app.use(express.json());

// Configuration
const secret = process.env.JWT_SECRET;
const port = process.env.PORT || 8080;

// Define mongoose schemas
const userSchema = new mongoose.Schema({
    user: {type: String, unique: true},
    password: String,
    rank: String,
    my_courses: Array
});

const adminSchema = new mongoose.Schema({
// adminSchema here
    user: {type: String, unique: true},
    password: String,
    rank: String,
    my_courses: Array
});

const courseSchema = new mongoose.Schema({
// courseSchema here
    title: {type: String, unique: true},
    description: String,
    imagelink: String,
    published: Boolean,
    creatorId: String,
    link: String
});

// Define mongoose models
const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Course = mongoose.model('Course', courseSchema);

const authMiddleware = (req, res, next) => {
    try {
        // Try to get token from cookies first (for same-origin requests)
        let token = req.cookies.token;
        
        // If no cookie token, try Authorization header (for cross-origin requests)
        if (!token && req.headers.authorization) {
            const authHeader = req.headers.authorization;
            if (authHeader.startsWith('Bearer ')) {
                token = authHeader.split(' ')[1];
            }
        }

        if (!token) {
            return res.status(403).json({ message: "wtf no token" });
        }

        const decodeddata = jwt.verify(token, secret);
        req.userId = decodeddata.id;
        req.rank = decodeddata.rank;
        return next();
    } catch (error) {
        console.error(error);
        return res.status(403).json({ message: "invalid token" });
    }
};

const published = async (req, res, next) => {
    const title = req.params.title;
    try {
        const course = await Course.findOne({ title: title });
        if (course && course.published) {
            next();
        } else {
            res.status(404).json({ message: 'Course not found or not published' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});


// Admin routes
app.post('/admin/signup', async function(req, res) {
    // logic to sign up admin
        const bruh = z.object({
            admin_name: z.string().max(64),
            password: z.string().min(8)
        });

        const safeparse = bruh.safeParse(req.body);

        if (!safeparse.success)
        {
            return res.status(400).json({error: safeparse.error});
        }
        console.log("Safeparse result:", safeparse);

        const hashed = await bcrypt.hash(safeparse.data.password, 5);

        let err = false;
        try{
            console.log("doing");
            await Admin.create({
                
                user: safeparse.data.admin_name,
                password: hashed,
                rank: "admin",
                my_courses: []
            });
        }catch(e) {
            res.status(409).json({ message: "nah bruh, already exist, come later mate" });
            err=true;
            return;
        };
        if(!err){
            res.status(201).json({
            message: "User created"
            });
        }

    
})

app.post('/admin/login', async function(req, res) {
  const bruh = z.object({
    admin_name: z.string().max(64),
    password: z.string().min(8)
  });

  const safeparse = bruh.safeParse(req.body);

  if (!safeparse.success) {
    return res.status(400).json({ error: safeparse.error });
  }

  const username = safeparse.data.admin_name;

  // Check lock status
  let record = await LoginAttempt.findOne({ username });
  if (record && record.lockUntil && record.lockUntil > new Date()) {
    const secondsLeft = Math.ceil((record.lockUntil - new Date()) / 1000);
    return res.status(429).json({
      message: `Too many attempts. Try again in ${secondsLeft} seconds.`
    });
  }

  const u = await Admin.findOne({
    user: username
  });

  if (!u) {
    return res.status(403).json({ message: "user not found" });
  }

  try {
    const hashed = await bcrypt.compare(safeparse.data.password, u.password);
    if (hashed) {
      // Successful login → reset attempts
      await LoginAttempt.deleteOne({ username });

      const token = jwt.sign({
        id: u._id.toString(),
        rank: u.rank.toString()
      }, secret);
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24
      });

      res.json({
        token: token,
        rank: u.rank,
        message: "user found"
      });
      console.log(safeparse.data.admin_name);
    } else {
      // Password incorrect → handle cooldown
      if (!record) {
        record = new LoginAttempt({
          username: username,
          attemptsLeft: 4,
          lockUntil: null
        });
      } else {
        record.attemptsLeft -= 1;
      }

      if (record.attemptsLeft <= 0) {
        let lockTime;
        if (!record.lockUntil) {
          lockTime = 5 * 60 * 1000; // 5 min
          record.attemptsLeft = 3;
        } else if (record.lockUntil && record.attemptsLeft === 0) {
          if (record.lockUntil.getTime() - Date.now() === 5 * 60 * 1000) {
            lockTime = 15 * 60 * 1000; // 15 min
            record.attemptsLeft = 1;
          } else {
            lockTime = 60 * 60 * 1000; // 1 hour
            record.attemptsLeft = 0;
          }
        } else {
          lockTime = 60 * 60 * 1000;
        }

        record.lockUntil = new Date(Date.now() + lockTime);
        await record.save();

        return res.status(429).json({
          message: `Too many attempts. Account locked for ${lockTime / 60000} minutes.`
        });
      } else {
        await record.save();
        return res.status(403).json({
          message: `Invalid password. Attempts left: ${record.attemptsLeft}`
        });
      }
    }
  } catch (e) {
    res.json({ message: "wrong pass" });
    return;
  }
});

app.post('/admin/courses', authMiddleware, async function(req, res) {
    // logic to create a course
    try{
        const{title, description, img, published, link} = req.body;
        const userId = req.userId;
        const rank = req.rank;
        if (img && !isSafeUrl(img)) {
            return res.status(400).json({ error: "Invalid image URL" });
        }
        if (link && !isSafeUrl(link)) {
            return res.status(400).json({ error: "Invalid course link" });
        }
        const u = await Admin.findOne({_id: userId});
        if(u && rank=="admin")
        {
            const newcourse = await Course.create({
                title: title,
                description: description,
                imagelink: img,
                published: published,
                creatorId: userId,
                link: link
            })
            return res.status(201).json(newcourse);
        }else
        {
            return res.status(403).json({error: "u dont have access"});
        }
    }catch(err) {
        return res.status(500).json({error: "internal error"});
    }
});

app.put('/admin/courses/:title', authMiddleware, async function(req, res) {
    // logic to edit a course
    const title = req.params.title;
    const{new_title, new_d, new_img, new_published, new_link} = req.body;
    const userId = req.userId;
    const rank = req.rank;
    if (new_img && !isSafeUrl(new_img)) {
        return res.status(400).json({ error: "Invalid image URL" });
    }
    if (new_link && !isSafeUrl(new_link)) {
        return res.status(400).json({ error: "Invalid course link" });
    }
    const u = await Admin.findOne({_id: userId});
    try{
        if(u && rank=="admin")
        {
            const updatedCourse = await Course.findOneAndUpdate(
                { title: title },
                {
                    $set: {
                    title: new_title || title,
                    description: new_d,
                    imagelink: new_img,
                    published: new_published,
                    creatorId: userId,
                    link: new_link
                    }
                },
                { new: true }
            );

            return res.status(201).json(updatedCourse);
        }else
        {
            return res.status(403).json({error: "u dont have access"});
        } 
    } catch (error) {
        return res.status(500).json({ error: "An error occurred while finding the bookmark" });
    }
});

app.get('/admin/courses', authMiddleware, async function(req, res) {
    // logic to get all courses
    try {
        const userId = req.userId;
        const rank = req.rank;
        const u = await Admin.findOne({_id: userId});
        if(u && rank=="admin")
        {
            const all_courses = await Course.find({
                creatorId: userId
            })
            if (all_courses) {  
                return res.status(200).json(all_courses);
            }
            else
                return res.status(404).json({ error: "no courses made by admin" })
        }
        else
            return res.status(403).json({ error: "u don't have access" })
    } catch (error) {
        return res.status(500).json({ error: "An error occurred while adding the bookmark" });
    }
});

// User routes

app.post('/users/signup', async function(req, res) {
    // logic to sign up admin
        const bruh = z.object({
            user_name: z.string().max(64),
            password: z.string().min(8)
        });

        const safeparse = bruh.safeParse(req.body);

        if (!safeparse.success)
        {
            return res.status(400).json({error: safeparse.error});
        }
        console.log("Safeparse result:", safeparse);

        const hashed = await bcrypt.hash(safeparse.data.password, 5);

        let err = false;
        try{
            console.log("doing");
            await User.create({
                
                user: safeparse.data.user_name,
                password: hashed,
                rank: "user",
                my_courses: []
            });
        }catch(e) {
            res.status(409).json({ message: "nah bruh, already exist" });
            err=true;
            return;
        };
        if(!err){
            res.status(201).json({
            message: "User created"
            });
        }

    
})

app.get('/courses', async function(req, res) {
    try {
        const publishedCourses = await Course.find({
            published: true
        }); //
        
        if (publishedCourses.length > 0) {
            return res.status(200).json(publishedCourses);
        } else {
            return res.status(404).json({ message: "No published courses found" });
        }
    } catch (err) {
        return res.status(500).json({ error: "An internal error occurred" });
    }
});

app.post('/users/login', async function(req, res) {
  const bruh = z.object({
    user_name: z.string().max(64),
    password: z.string().min(8)
  });

  const safeparse = bruh.safeParse(req.body);

  if (!safeparse.success) {
    return res.status(400).json({ error: safeparse.error });
  }

  const username = safeparse.data.user_name;

  // Check lock status
  let record = await LoginAttempt.findOne({ username });
  if (record && record.lockUntil && record.lockUntil > new Date()) {
    const secondsLeft = Math.ceil((record.lockUntil - new Date()) / 1000);
    return res.status(429).json({
      message: `Too many attempts. Try again in ${secondsLeft} seconds.`
    });
  }

  const u = await User.findOne({
    user: username
  });

  if (!u) {
    return res.status(403).json({ message: "user not found" });
  }

  try {
    const hashed = await bcrypt.compare(safeparse.data.password, u.password);
    if (hashed) {
      // Successful login → reset attempts
      await LoginAttempt.deleteOne({ username });

      const token = jwt.sign({
        id: u._id.toString(),
        rank: u.rank.toString()
      }, secret);
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24
      });

      res.json({
        token: token,
        rank: u.rank,
        message: "user found"
      });
      console.log(safeparse.data.user_name);
    } else {
      if (!record) {
        record = new LoginAttempt({
          username: username,
          attemptsLeft: 4,
          lockUntil: null
        });
      } else {
        record.attemptsLeft -= 1;
      }

      if (record.attemptsLeft <= 0) {
        let lockTime;
        if (!record.lockUntil) {
          lockTime = 5 * 60 * 1000; // 5 min
          record.attemptsLeft = 3;
        } else if (record.lockUntil && record.attemptsLeft === 0) {
          if (record.lockUntil.getTime() - Date.now() === 5 * 60 * 1000) {
            lockTime = 15 * 60 * 1000; // 15 min
            record.attemptsLeft = 1;
          } else {
            lockTime = 60 * 60 * 1000; // 1 hour
            record.attemptsLeft = 0;
          }
        } else {
          lockTime = 60 * 60 * 1000;
        }

        record.lockUntil = new Date(Date.now() + lockTime);
        await record.save();

        return res.status(429).json({
          message: `Too many attempts. Account locked for ${lockTime / 60000} minutes.`
        });
      } else {
        await record.save();
        return res.status(403).json({
          message: `Invalid password. Attempts left: ${record.attemptsLeft}`
        });
      }
    }
  } catch (e) {
    res.json({ message: "wrong pass" });
    return;
  }
});


app.get('/users/courses',authMiddleware , async function(req, res) {
    // logic to list all courses
    const userId = req.userId;
    try{
        const user = await User.findOne({_id: userId})
        const admin = await Admin.findOne({_id: userId})
        
        if(user || admin)
        {
            try{
                
                const find_course = await Course.find({
                    published: true
                })
                if (find_course)
                {
                    return res.status(200).json(find_course)
                }
                else
                    return res.status(404).json({ error: "course not found" })

            }catch(err) {
                return res.status(500).json({ error: "error occured" })
            }
        }
        else
            return res.status(404).json({ error: "user not found" })
        }catch(err) {
            return res.status(500).json({ error: "user not found" })
        }
});

app.post('/users/courses/:title',authMiddleware, published, async function(req, res) {
    // logic to purchase a course
    const title = req.params.title;
    const userId = req.userId;
    try{
        const user = await User.findOne({_id: userId})
        const admin = await Admin.findOne({_id: userId})
        
        if(user)
        {
            try{
                const find_course = await Course.findOne({
                    title: title
                })
                if (find_course)
                {
                    const purchase = await User.updateOne({
                        _id: userId
                    },
                    {
                        $push: {my_courses: find_course._id}
                    })
                    return res.status(200).json({message: "course bought"})
                }
                else
                    return res.status(404).json({ error: "course not found" })

            }catch(err) {
                return res.status(500).json({ error: "error occured" })
            }
        }
        else if(admin)
        {
            try{
                const find_course = await Course.findOne({
                    title: title
                })
                if (find_course)
                {
                    const purchase = await Admin.updateOne({
                        _id: userId
                    },
                    {
                        $push: {my_courses: find_course._id}
                    })
                    return res.status(200).json({message: "course bought"})
                }
                else
                    return res.status(404).json({ error: "course not found" })

            }catch(err) {
                return res.status(500).json({ error: "error occured" })
            }
        }
        else
            return res.status(404).json({ error: "user not found" })
    }catch(err) {
        res.status(500).json({ error: "try later" })
    }

});

app.get('/users/purchasedCourses', authMiddleware, async function(req, res) {
    // logic to view purchased courses
    const user_id = req.userId;
    try{
        const user = await User.findOne({_id: user_id})
        const admin = await Admin.findOne({_id: user_id})
        if(user)
        {
            const mycourses = user.my_courses
            console.log(mycourses)
            const courses = await Course.find({
                _id: { $in: mycourses }
            })
            if(mycourses.length>0)
            {
                res.status(200).json(courses)
            }
            else
                return res.status(404).json({ error: "u dont own any courses" })
        }
        else if(admin)
        {
            const mycourses = admin.my_courses
            const courses = await Course.find({
                _id: { $in: mycourses }
            })
            if(mycourses.length>0)
            {
                res.status(200).json(courses)
            }
            else
                return res.status(404).json({ error: "u dont own any courses" })
        }
        else
            return res.status(404).json({ error: "user not found" })
    }catch(err) {
        res.status(500).json({ error: "try later" })
    }
});

app.get("/users/me", authMiddleware, (req, res) => {
  return res.json({
    token: req.cookies.token,
    rank: req.rank,
  });
});

app.get("/admin/me", authMiddleware, (req, res) => {
  return res.json({
    token: req.cookies.token,
    rank: req.rank,
  });
});


app.listen(port, () => {
    console.log('Server is listening on port 8080');
});

