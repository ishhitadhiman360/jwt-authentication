const mongoose = require("mongoose");

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/database', { useNewUrlParser: true, useUnifiedTopology: true })
.then(() => console.log('Database connected'))
.catch(err => console.log(err));

// Create user schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    loginTime: {
        type: Date
    },
    logoutTime: {
        type: Date
    },
    loginCount: {
        type: Number,
        default: 0
    }
});

// Create user model
const User = mongoose.model('User', userSchema);

// Export the user model
module.exports = User;
