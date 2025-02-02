import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }, // Hashed password
    victronUsername: { type: String, required: true },
    victronPassword: { type: String, required: true },
    growattUsername: { type: String, required: true },
    growattPassword: { type: String, required: true },
    haLongTermKey: { type: String, required: true }
});

export default mongoose.model('User', userSchema);
