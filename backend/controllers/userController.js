import User from "../models/userModel.js";
import asyncHandler from "../middlewares/asyncHandler.js"
import bcrypt from "bcrypt";
import buildToken from "../utils/buildToken.js";

const createUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !password || !email) {
        throw new Error("please fill the info correctly")

    }
    const userExists = await User.findOne({ email });
    if (userExists) res.status(400).send("the user exists")

    const salt = await bcrypt.genSalt(10)
    const hashedPass = await bcrypt.hash(password, salt);

    const newUser = new User({ username, email, password: hashedPass });

    try {
        await newUser.save()
        buildToken(res, newUser._id);
        res.status(201).json({ _id: newUser._id, username: newUser.username, email: newUser.email, isAdmin: newUser.isAdmin })
    } catch (error) {
        res.status(400)
        throw new Error("invalid user data")
    }

});

export { createUser };
