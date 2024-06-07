import mongoose from "mongoose"
const userSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    isadmin: {
        type: Boolean,
        required: true,
        default: false,

    }
},
    { timestamp: true }
);
const User = mongoose.model('User', userSchema);

export default User;