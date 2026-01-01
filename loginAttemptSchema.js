// loginAttemptSchema.js
import mongoose from "mongoose";

const loginAttemptSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  attemptsLeft: Number,
  lockUntil: Date
});

export const LoginAttempt = mongoose.model("LoginAttempt", loginAttemptSchema);
